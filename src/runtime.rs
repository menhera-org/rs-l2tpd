use async_trait::async_trait;
use iphost::{AutoIpHostResolver, IpHost, IpHostResolver};
use log::{debug, info, warn};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use std::time::Duration;

use crate::config::{Config, IpVersion};
use crate::error::{Error, Result};
use crate::state;

pub(crate) type TunnelId = u32;
pub(crate) type SessionId = u32;
pub(crate) type SessionKey = (TunnelId, SessionId);

type DesiredTunnelMap = BTreeMap<TunnelId, DesiredTunnel>;
type DesiredSessionMap = BTreeMap<SessionKey, DesiredSession>;

const DNS_REFRESH_INTERVAL_SECS: u64 = 30;
const DNS_WATCH_POLL_INTERVAL_SECS: u64 = 1;
const MAX_INTERFACE_NAME_LEN: usize = 15;

#[derive(Debug)]
pub(crate) enum ControlEvent {
    ReloadRequested,
    ShutdownRequested,
    DnsChanged { tunnel_id: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesiredTunnel {
    tunnel_id: u32,
    peer_tunnel_id: u32,
    ip_version: IpVersion,
    remote_addr: IpHost,
    bind_interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesiredSession {
    tunnel_id: u32,
    session_id: u32,
    peer_session_id: u32,
    interface_name: String,
}

#[derive(Debug, Default)]
struct TunnelPlan {
    to_delete: BTreeSet<TunnelId>,
    to_add: BTreeSet<TunnelId>,
    to_update: BTreeSet<TunnelId>,
}

#[derive(Debug, Default)]
struct SessionPlan {
    to_delete: BTreeSet<SessionKey>,
    to_add: BTreeSet<SessionKey>,
    to_modify: Vec<SessionKey>,
}

#[async_trait]
pub(crate) trait StateOps: Send + Sync {
    async fn has_tunnel(&self, tunnel_id: u32) -> bool;
    async fn add_tunnel(
        &self,
        tunnel_id: u32,
        peer_tunnel_id: u32,
        remote_addr: IpAddr,
        if_name: Option<&str>,
    ) -> Result<()>;
    async fn modify_tunnel(&self, tunnel_id: u32, remote_addr: IpAddr) -> Result<()>;
    async fn delete_tunnel(&self, tunnel_id: u32) -> Result<()>;
    async fn has_session(&self, tunnel_id: u32, session_id: u32) -> bool;
    async fn add_session(
        &self,
        tunnel_id: u32,
        session_id: u32,
        peer_session_id: u32,
        if_name: &str,
    ) -> Result<()>;
    async fn modify_session(&self, tunnel_id: u32, session_id: u32, ifname: &str) -> Result<()>;
    async fn delete_session(&self, tunnel_id: u32, session_id: u32) -> Result<()>;
}

#[async_trait]
impl StateOps for state::State {
    async fn has_tunnel(&self, tunnel_id: u32) -> bool {
        state::State::has_tunnel(self, tunnel_id).await
    }

    async fn add_tunnel(
        &self,
        tunnel_id: u32,
        peer_tunnel_id: u32,
        remote_addr: IpAddr,
        if_name: Option<&str>,
    ) -> Result<()> {
        state::State::add_tunnel(self, tunnel_id, peer_tunnel_id, remote_addr, if_name).await
    }

    async fn modify_tunnel(&self, tunnel_id: u32, remote_addr: IpAddr) -> Result<()> {
        state::State::modify_tunnel(self, tunnel_id, remote_addr).await
    }

    async fn delete_tunnel(&self, tunnel_id: u32) -> Result<()> {
        state::State::delete_tunnel(self, tunnel_id).await
    }

    async fn has_session(&self, tunnel_id: u32, session_id: u32) -> bool {
        state::State::has_session(self, tunnel_id, session_id).await
    }

    async fn add_session(
        &self,
        tunnel_id: u32,
        session_id: u32,
        peer_session_id: u32,
        if_name: &str,
    ) -> Result<()> {
        state::State::add_session(self, tunnel_id, session_id, peer_session_id, if_name).await
    }

    async fn modify_session(&self, tunnel_id: u32, session_id: u32, ifname: &str) -> Result<()> {
        state::State::modify_session(self, tunnel_id, session_id, ifname).await
    }

    async fn delete_session(&self, tunnel_id: u32, session_id: u32) -> Result<()> {
        state::State::delete_session(self, tunnel_id, session_id).await
    }
}

struct ResolverRuntime {
    resolver: AutoIpHostResolver,
    ip_version: Arc<StdRwLock<IpVersion>>,
    active: Arc<AtomicBool>,
    dns_event_pending: Arc<AtomicBool>,
    last_queued_addr: Arc<StdRwLock<Option<IpAddr>>>,
    worker: JoinHandle<()>,
}

impl ResolverRuntime {
    fn new(
        tunnel_id: u32,
        desired: &DesiredTunnel,
        control_tx: mpsc::Sender<ControlEvent>,
    ) -> Self {
        let resolver = AutoIpHostResolver::new(
            desired.remote_addr.clone(),
            Duration::from_secs(DNS_REFRESH_INTERVAL_SECS),
        );
        let ip_version = Arc::new(StdRwLock::new(desired.ip_version));
        let active = Arc::new(AtomicBool::new(true));
        let dns_event_pending = Arc::new(AtomicBool::new(false));
        let last_queued_addr = Arc::new(StdRwLock::new(Self::current_remote_addr_for(
            &resolver,
            desired.ip_version,
        )));

        let watcher_resolver = resolver.clone();
        let watcher_ip_version = Arc::clone(&ip_version);
        let watcher_active = Arc::clone(&active);
        let watcher_pending = Arc::clone(&dns_event_pending);
        let watcher_last_queued = Arc::clone(&last_queued_addr);
        let worker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(DNS_WATCH_POLL_INTERVAL_SECS)).await;
                if control_tx.is_closed() {
                    break;
                }
                if !watcher_active.load(Ordering::Relaxed) {
                    continue;
                }

                let current = if let Ok(version) = watcher_ip_version.read() {
                    Self::current_remote_addr_for(&watcher_resolver, *version)
                } else {
                    None
                };

                let mut old = None;
                let should_emit = {
                    let mut queued = watcher_last_queued
                        .write()
                        .expect("resolver watcher queue state poisoned");
                    if *queued == current {
                        false
                    } else if watcher_pending
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                    {
                        old = Some(*queued);
                        *queued = current;
                        true
                    } else {
                        false
                    }
                };

                if !should_emit {
                    continue;
                }

                if control_tx
                    .try_send(ControlEvent::DnsChanged { tunnel_id })
                    .is_err()
                {
                    watcher_pending.store(false, Ordering::Release);
                    if let Some(previous) = old {
                        if let Ok(mut queued) = watcher_last_queued.write() {
                            *queued = previous;
                        }
                    }
                }
            }
        });

        Self {
            resolver,
            ip_version,
            active,
            dns_event_pending,
            last_queued_addr,
            worker,
        }
    }

    fn apply_tunnel_config(&self, desired: &DesiredTunnel) {
        if let Ok(mut version) = self.ip_version.write() {
            *version = desired.ip_version;
        }
        self.active.store(true, Ordering::Relaxed);
        self.dns_event_pending.store(false, Ordering::Relaxed);

        if self
            .resolver
            .replace_ip_host(desired.remote_addr.clone())
            .is_err()
        {
            warn!(
                "failed to update resolver hostname immediately for tunnel_id={}",
                desired.tunnel_id
            );
        }

        if let Ok(mut queued) = self.last_queued_addr.write() {
            *queued = Self::current_remote_addr_for(&self.resolver, desired.ip_version);
        }
    }

    fn deactivate(&self) {
        self.active.store(false, Ordering::Relaxed);
        self.dns_event_pending.store(false, Ordering::Relaxed);
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    fn clear_dns_event_pending(&self) {
        self.dns_event_pending.store(false, Ordering::Relaxed);
    }

    fn current_remote_addr(&self) -> Option<IpAddr> {
        let ip_version = self.ip_version.read().ok().map(|v| *v)?;
        Self::current_remote_addr_for(&self.resolver, ip_version)
    }

    fn current_remote_addr_for(
        resolver: &AutoIpHostResolver,
        ip_version: IpVersion,
    ) -> Option<IpAddr> {
        match ip_version {
            IpVersion::V4 => resolver.ipv4_addr().map(IpAddr::V4),
            IpVersion::V6 => resolver.ipv6_addr().map(IpAddr::V6),
        }
    }
}

impl Drop for ResolverRuntime {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Relaxed);
        self.worker.abort();
    }
}

pub(crate) struct Runtime {
    state: Arc<dyn StateOps>,
    tunnel_specs: DesiredTunnelMap,
    session_specs: DesiredSessionMap,
    resolvers: BTreeMap<TunnelId, ResolverRuntime>,
    control_tx: mpsc::Sender<ControlEvent>,
}

impl Runtime {
    pub(crate) fn new(state: Arc<state::State>, control_tx: mpsc::Sender<ControlEvent>) -> Self {
        Self {
            state,
            tunnel_specs: BTreeMap::new(),
            session_specs: BTreeMap::new(),
            resolvers: BTreeMap::new(),
            control_tx,
        }
    }

    #[cfg(test)]
    fn new_with_state_ops(
        state: Arc<dyn StateOps>,
        control_tx: mpsc::Sender<ControlEvent>,
    ) -> Self {
        Self {
            state,
            tunnel_specs: BTreeMap::new(),
            session_specs: BTreeMap::new(),
            resolvers: BTreeMap::new(),
            control_tx,
        }
    }

    pub(crate) async fn reconcile(&mut self, config: &Config) -> Result<()> {
        let (desired_tunnels, desired_sessions) = build_desired_maps(config)?;
        let mut applied_tunnel_specs = self.tunnel_specs.clone();
        let mut applied_session_specs = self.session_specs.clone();

        macro_rules! try_apply {
            ($result:expr) => {
                if let Err(e) = $result {
                    self.tunnel_specs = applied_tunnel_specs;
                    self.session_specs = applied_session_specs;
                    return Err(e);
                }
            };
        }
        let tunnel_plan = plan_tunnel_changes(&self.tunnel_specs, &desired_tunnels);

        for tunnel_id in &tunnel_plan.to_delete {
            if let Some(resolver_runtime) = self.resolvers.get(tunnel_id) {
                resolver_runtime.deactivate();
            }
        }

        for tunnel_id in &tunnel_plan.to_delete {
            if self.state.has_tunnel(*tunnel_id).await {
                info!("deleting tunnel_id={}", tunnel_id);
                try_apply!(self.state.delete_tunnel(*tunnel_id).await);
            }
            self.resolvers.remove(tunnel_id);
            applied_tunnel_specs.remove(tunnel_id);
            applied_session_specs.retain(|(tid, _), _| tid != tunnel_id);
        }

        for tunnel_id in &tunnel_plan.to_add {
            let desired = desired_tunnels
                .get(tunnel_id)
                .expect("tunnel exists in desired map");

            let had_resolver = self.resolvers.contains_key(tunnel_id);
            if !had_resolver {
                let runtime = ResolverRuntime::new(*tunnel_id, desired, self.control_tx.clone());
                self.resolvers.insert(*tunnel_id, runtime);
            }

            let resolver_runtime = self
                .resolvers
                .get(tunnel_id)
                .expect("resolver exists for tunnel");
            resolver_runtime.apply_tunnel_config(desired);

            let remote_addr = if let Some(addr) = resolver_runtime.current_remote_addr() {
                addr
            } else {
                match resolve_ip_host_once(&desired.remote_addr, desired.ip_version) {
                    Ok(addr) => addr,
                    Err(e) => {
                        if !applied_tunnel_specs.contains_key(tunnel_id) {
                            self.resolvers.remove(tunnel_id);
                        }
                        self.tunnel_specs = applied_tunnel_specs;
                        self.session_specs = applied_session_specs;
                        return Err(e);
                    }
                }
            };

            info!(
                "adding tunnel_id={} peer_tunnel_id={} remote_addr={}",
                desired.tunnel_id, desired.peer_tunnel_id, remote_addr
            );
            if let Err(e) = self
                .state
                .add_tunnel(
                    desired.tunnel_id,
                    desired.peer_tunnel_id,
                    remote_addr,
                    desired.bind_interface.as_deref(),
                )
                .await
            {
                if !applied_tunnel_specs.contains_key(tunnel_id) {
                    self.resolvers.remove(tunnel_id);
                }
                self.tunnel_specs = applied_tunnel_specs;
                self.session_specs = applied_session_specs;
                return Err(e);
            }
            applied_tunnel_specs.insert(*tunnel_id, desired.clone());
        }

        for tunnel_id in &tunnel_plan.to_update {
            let current = self
                .tunnel_specs
                .get(tunnel_id)
                .expect("tunnel exists in current map");
            let desired = desired_tunnels
                .get(tunnel_id)
                .expect("tunnel exists in desired map");

            let had_resolver = self.resolvers.contains_key(tunnel_id);
            if !had_resolver {
                let runtime = ResolverRuntime::new(*tunnel_id, desired, self.control_tx.clone());
                self.resolvers.insert(*tunnel_id, runtime);
            }

            let resolver_runtime = self
                .resolvers
                .get(tunnel_id)
                .expect("resolver exists for tunnel");
            resolver_runtime.apply_tunnel_config(desired);

            let remote_addr = if let Some(addr) = resolver_runtime.current_remote_addr() {
                addr
            } else {
                match resolve_ip_host_once(&desired.remote_addr, desired.ip_version) {
                    Ok(addr) => addr,
                    Err(e) => {
                        if !had_resolver {
                            self.resolvers.remove(tunnel_id);
                        } else if let Some(resolver_runtime) = self.resolvers.get(tunnel_id) {
                            resolver_runtime.apply_tunnel_config(current);
                        }
                        self.tunnel_specs = applied_tunnel_specs;
                        self.session_specs = applied_session_specs;
                        return Err(e);
                    }
                }
            };

            info!(
                "updating tunnel_id={} remote_addr={}",
                desired.tunnel_id, remote_addr
            );
            if let Err(e) = self
                .state
                .modify_tunnel(desired.tunnel_id, remote_addr)
                .await
            {
                if !had_resolver {
                    self.resolvers.remove(tunnel_id);
                } else if let Some(resolver_runtime) = self.resolvers.get(tunnel_id) {
                    resolver_runtime.apply_tunnel_config(current);
                }
                self.tunnel_specs = applied_tunnel_specs;
                self.session_specs = applied_session_specs;
                return Err(e);
            }
            applied_tunnel_specs.insert(*tunnel_id, desired.clone());
        }

        for tunnel_id in self
            .tunnel_specs
            .keys()
            .filter(|id| !tunnel_plan.to_delete.contains(id) && !tunnel_plan.to_update.contains(id))
        {
            if let Some(desired) = desired_tunnels.get(tunnel_id) {
                if let Some(resolver_runtime) = self.resolvers.get(tunnel_id) {
                    resolver_runtime.apply_tunnel_config(desired);
                }
                applied_tunnel_specs.insert(*tunnel_id, desired.clone());
            }
        }

        let session_plan = plan_session_changes(&applied_session_specs, &desired_sessions);

        let mut reserved_interface_names: BTreeSet<String> = applied_session_specs
            .values()
            .map(|s| s.interface_name.clone())
            .collect();
        reserved_interface_names
            .extend(desired_sessions.values().map(|s| s.interface_name.clone()));
        let mut temp_interface_counter: u32 = 0;

        for (tunnel_id, session_id) in &session_plan.to_modify {
            let temp_ifname = allocate_temp_interface_name(
                &mut reserved_interface_names,
                &mut temp_interface_counter,
            );
            info!(
                "renaming session interface tunnel_id={} session_id={} to temporary {}",
                tunnel_id, session_id, temp_ifname
            );
            try_apply!(
                self.state
                    .modify_session(*tunnel_id, *session_id, &temp_ifname)
                    .await
            );
            if let Some(applied) = applied_session_specs.get_mut(&(*tunnel_id, *session_id)) {
                applied.interface_name = temp_ifname;
            }
        }

        for (tunnel_id, session_id) in &session_plan.to_modify {
            let desired = desired_sessions
                .get(&(*tunnel_id, *session_id))
                .expect("session exists in desired map");
            info!(
                "renaming session interface tunnel_id={} session_id={} to {}",
                tunnel_id, session_id, desired.interface_name
            );
            try_apply!(
                self.state
                    .modify_session(*tunnel_id, *session_id, &desired.interface_name)
                    .await
            );
            applied_session_specs.insert((*tunnel_id, *session_id), desired.clone());
        }

        for (tunnel_id, session_id) in &session_plan.to_delete {
            if self.state.has_session(*tunnel_id, *session_id).await {
                info!(
                    "deleting session tunnel_id={} session_id={}",
                    tunnel_id, session_id
                );
                try_apply!(self.state.delete_session(*tunnel_id, *session_id).await);
            }
            applied_session_specs.remove(&(*tunnel_id, *session_id));
        }

        for (tunnel_id, session_id) in &session_plan.to_add {
            let desired = desired_sessions
                .get(&(*tunnel_id, *session_id))
                .expect("session exists in desired map");
            info!(
                "adding session tunnel_id={} session_id={} interface_name={}",
                tunnel_id, session_id, desired.interface_name
            );
            try_apply!(
                self.state
                    .add_session(
                        *tunnel_id,
                        *session_id,
                        desired.peer_session_id,
                        &desired.interface_name,
                    )
                    .await
            );
            applied_session_specs.insert((*tunnel_id, *session_id), desired.clone());
        }

        self.tunnel_specs = desired_tunnels;
        self.session_specs = desired_sessions;
        Ok(())
    }

    pub(crate) async fn handle_dns_change(&self, tunnel_id: u32) {
        let Some(resolver_runtime) = self.resolvers.get(&tunnel_id) else {
            return;
        };
        resolver_runtime.clear_dns_event_pending();

        if !self.tunnel_specs.contains_key(&tunnel_id) {
            return;
        }

        if !resolver_runtime.is_active() {
            return;
        }

        let Some(remote_addr) = resolver_runtime.current_remote_addr() else {
            debug!(
                "resolver emitted change for tunnel_id={} but no address for the selected ip_version",
                tunnel_id
            );
            return;
        };

        match self.state.modify_tunnel(tunnel_id, remote_addr).await {
            Ok(()) => info!(
                "dns change applied tunnel_id={} remote_addr={}",
                tunnel_id, remote_addr
            ),
            Err(e) => warn!(
                "failed to apply dns change tunnel_id={} remote_addr={} error={}",
                tunnel_id, remote_addr, e
            ),
        }
    }

    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        self.reconcile(&Config::default()).await
    }
}

fn plan_tunnel_changes(current: &DesiredTunnelMap, desired: &DesiredTunnelMap) -> TunnelPlan {
    let current_ids: BTreeSet<u32> = current.keys().copied().collect();
    let desired_ids: BTreeSet<u32> = desired.keys().copied().collect();

    let mut plan = TunnelPlan {
        to_delete: current_ids.difference(&desired_ids).copied().collect(),
        to_add: desired_ids.difference(&current_ids).copied().collect(),
        to_update: BTreeSet::new(),
    };

    for tunnel_id in current_ids.intersection(&desired_ids) {
        let current_tunnel = current
            .get(tunnel_id)
            .expect("tunnel exists in current map");
        let desired_tunnel = desired
            .get(tunnel_id)
            .expect("tunnel exists in desired map");

        let requires_recreate = current_tunnel.peer_tunnel_id != desired_tunnel.peer_tunnel_id
            || current_tunnel.bind_interface != desired_tunnel.bind_interface;
        if requires_recreate {
            plan.to_delete.insert(*tunnel_id);
            plan.to_add.insert(*tunnel_id);
            continue;
        }

        let mutable_changed = current_tunnel.remote_addr != desired_tunnel.remote_addr
            || current_tunnel.ip_version != desired_tunnel.ip_version;
        if mutable_changed {
            plan.to_update.insert(*tunnel_id);
        }
    }

    plan
}

fn plan_session_changes(current: &DesiredSessionMap, desired: &DesiredSessionMap) -> SessionPlan {
    let mut plan = SessionPlan::default();

    for (key, current_session) in current {
        let Some(desired_session) = desired.get(key) else {
            plan.to_delete.insert(*key);
            continue;
        };

        if current_session.peer_session_id != desired_session.peer_session_id {
            plan.to_delete.insert(*key);
            plan.to_add.insert(*key);
            continue;
        }

        if current_session.interface_name != desired_session.interface_name {
            plan.to_modify.push(*key);
        }
    }

    for key in desired.keys() {
        if !current.contains_key(key) {
            plan.to_add.insert(*key);
        }
    }

    plan
}

fn allocate_temp_interface_name(used_names: &mut BTreeSet<String>, counter: &mut u32) -> String {
    loop {
        let candidate = format!("rsl2tp{:08x}", *counter);
        *counter = counter.wrapping_add(1);
        if candidate.len() > MAX_INTERFACE_NAME_LEN {
            continue;
        }
        if used_names.insert(candidate.clone()) {
            return candidate;
        }
    }
}

fn resolve_ip_host_once(ip_host: &IpHost, ip_version: IpVersion) -> Result<IpAddr> {
    match (ip_version, ip_host) {
        (IpVersion::V4, IpHost::V4Addr(addr)) => return Ok(IpAddr::V4(*addr)),
        (IpVersion::V6, IpHost::V6Addr(addr)) => return Ok(IpAddr::V6(*addr)),
        (IpVersion::V4, IpHost::V6Addr(_)) => {
            return Err(Error::InvalidConfig(format!(
                "remote_addr {} is IPv6 but ip_version is v4",
                ip_host
            )));
        }
        (IpVersion::V6, IpHost::V4Addr(_)) => {
            return Err(Error::InvalidConfig(format!(
                "remote_addr {} is IPv4 but ip_version is v6",
                ip_host
            )));
        }
        _ => {}
    }

    let resolver = IpHostResolver::new(ip_host.clone());
    let resolved = match ip_version {
        IpVersion::V4 => resolver.resolve_v4().into_iter().next().map(IpAddr::V4),
        IpVersion::V6 => resolver.resolve_v6().into_iter().next().map(IpAddr::V6),
    };

    resolved.ok_or_else(|| {
        Error::Other(format!(
            "failed to resolve remote_addr {} for ip_version {:?}",
            ip_host, ip_version
        ))
    })
}

fn build_desired_maps(config: &Config) -> Result<(DesiredTunnelMap, DesiredSessionMap)> {
    let mut tunnels: DesiredTunnelMap = BTreeMap::new();
    for tunnel in config.tunnels.values() {
        let desired = DesiredTunnel {
            tunnel_id: tunnel.tunnel_id,
            peer_tunnel_id: tunnel.peer_tunnel_id,
            ip_version: tunnel.ip_version,
            remote_addr: tunnel.remote_addr.clone(),
            bind_interface: tunnel.bind_interface.clone(),
        };

        if tunnels.insert(desired.tunnel_id, desired).is_some() {
            return Err(Error::InvalidConfig(format!(
                "duplicate tunnel_id in config: {}",
                tunnel.tunnel_id
            )));
        }
    }

    let mut sessions: DesiredSessionMap = BTreeMap::new();
    for session in config.sessions.values() {
        let tunnel = config.tunnels.get(&session.tunnel_name).ok_or_else(|| {
            Error::InvalidConfig(format!("tunnel not defined: {}", session.tunnel_name))
        })?;
        let tunnel_id = tunnel.tunnel_id;

        let desired = DesiredSession {
            tunnel_id,
            session_id: session.session_id,
            peer_session_id: session.peer_session_id,
            interface_name: session.interface_name.clone(),
        };
        let key = (desired.tunnel_id, desired.session_id);

        if sessions.insert(key, desired).is_some() {
            return Err(Error::InvalidConfig(format!(
                "duplicate session_id={} in tunnel_id={}",
                session.session_id, tunnel_id
            )));
        }
    }

    Ok((tunnels, sessions))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;

    #[derive(Debug, Clone)]
    struct MockTunnel {
        remote_addr: IpAddr,
    }

    #[derive(Debug, Clone)]
    struct MockSession {
        interface_name: String,
    }

    #[derive(Default)]
    struct MockStateInner {
        tunnels: BTreeMap<u32, MockTunnel>,
        sessions: BTreeMap<(u32, u32), MockSession>,
        fail_add_tunnel_for: Option<u32>,
        fail_modify_tunnel_for: Option<u32>,
        fail_add_session_for: Option<(u32, u32)>,
    }

    #[derive(Default)]
    struct MockState {
        inner: Mutex<MockStateInner>,
    }

    impl MockState {
        fn inject_add_tunnel_failure(&self, tunnel_id: u32) {
            self.inner
                .lock()
                .expect("lock poisoned")
                .fail_add_tunnel_for = Some(tunnel_id);
        }

        fn inject_modify_tunnel_failure(&self, tunnel_id: u32) {
            self.inner
                .lock()
                .expect("lock poisoned")
                .fail_modify_tunnel_for = Some(tunnel_id);
        }

        fn clear_modify_tunnel_failure(&self) {
            self.inner
                .lock()
                .expect("lock poisoned")
                .fail_modify_tunnel_for = None;
        }

        fn inject_add_session_failure(&self, key: (u32, u32)) {
            self.inner
                .lock()
                .expect("lock poisoned")
                .fail_add_session_for = Some(key);
        }

        fn session_name(&self, tunnel_id: u32, session_id: u32) -> Option<String> {
            self.inner
                .lock()
                .expect("lock poisoned")
                .sessions
                .get(&(tunnel_id, session_id))
                .map(|s| s.interface_name.clone())
        }

        fn tunnel_remote_addr(&self, tunnel_id: u32) -> Option<IpAddr> {
            self.inner
                .lock()
                .expect("lock poisoned")
                .tunnels
                .get(&tunnel_id)
                .map(|t| t.remote_addr)
        }
    }

    #[async_trait]
    impl StateOps for MockState {
        async fn has_tunnel(&self, tunnel_id: u32) -> bool {
            self.inner
                .lock()
                .expect("lock poisoned")
                .tunnels
                .contains_key(&tunnel_id)
        }

        async fn add_tunnel(
            &self,
            tunnel_id: u32,
            _peer_tunnel_id: u32,
            remote_addr: IpAddr,
            _if_name: Option<&str>,
        ) -> Result<()> {
            let mut inner = self.inner.lock().expect("lock poisoned");
            if inner.fail_add_tunnel_for == Some(tunnel_id) {
                return Err(Error::Other("injected add_tunnel failure".to_string()));
            }
            if inner.tunnels.contains_key(&tunnel_id) {
                return Err(Error::Other("Duplicate tunnel_id".to_string()));
            }
            inner.tunnels.insert(tunnel_id, MockTunnel { remote_addr });
            Ok(())
        }

        async fn modify_tunnel(&self, tunnel_id: u32, remote_addr: IpAddr) -> Result<()> {
            let mut inner = self.inner.lock().expect("lock poisoned");
            if inner.fail_modify_tunnel_for == Some(tunnel_id) {
                return Err(Error::Other("injected modify_tunnel failure".to_string()));
            }
            let tunnel = inner
                .tunnels
                .get_mut(&tunnel_id)
                .ok_or_else(|| Error::Other("tunnel not found".to_string()))?;
            tunnel.remote_addr = remote_addr;
            Ok(())
        }

        async fn delete_tunnel(&self, tunnel_id: u32) -> Result<()> {
            let mut inner = self.inner.lock().expect("lock poisoned");
            inner
                .tunnels
                .remove(&tunnel_id)
                .ok_or_else(|| Error::Other(format!("Tunnel not found: {}", tunnel_id)))?;
            inner.sessions.retain(|(tid, _), _| *tid != tunnel_id);
            Ok(())
        }

        async fn has_session(&self, tunnel_id: u32, session_id: u32) -> bool {
            self.inner
                .lock()
                .expect("lock poisoned")
                .sessions
                .contains_key(&(tunnel_id, session_id))
        }

        async fn add_session(
            &self,
            tunnel_id: u32,
            session_id: u32,
            _peer_session_id: u32,
            if_name: &str,
        ) -> Result<()> {
            let mut inner = self.inner.lock().expect("lock poisoned");
            if !inner.tunnels.contains_key(&tunnel_id) {
                return Err(Error::Other(format!("No such tunnel: {}", tunnel_id)));
            }
            if inner.fail_add_session_for == Some((tunnel_id, session_id)) {
                return Err(Error::Other("injected add_session failure".to_string()));
            }
            if inner.sessions.contains_key(&(tunnel_id, session_id)) {
                return Err(Error::Other("session exists".to_string()));
            }
            if inner
                .sessions
                .values()
                .any(|session| session.interface_name == if_name)
            {
                return Err(Error::Other(format!("interface exists: {}", if_name)));
            }
            inner.sessions.insert(
                (tunnel_id, session_id),
                MockSession {
                    interface_name: if_name.to_string(),
                },
            );
            Ok(())
        }

        async fn modify_session(
            &self,
            tunnel_id: u32,
            session_id: u32,
            ifname: &str,
        ) -> Result<()> {
            let mut inner = self.inner.lock().expect("lock poisoned");
            if !inner.sessions.contains_key(&(tunnel_id, session_id)) {
                return Err(Error::Other(format!(
                    "No such session {} in tunnel {}",
                    session_id, tunnel_id
                )));
            }
            let current_ifname = inner
                .sessions
                .get(&(tunnel_id, session_id))
                .expect("session exists")
                .interface_name
                .clone();
            if current_ifname == ifname {
                return Ok(());
            }
            if inner.sessions.iter().any(|(key, session)| {
                *key != (tunnel_id, session_id) && session.interface_name == ifname
            }) {
                return Err(Error::Other(format!("interface exists: {}", ifname)));
            }
            inner
                .sessions
                .get_mut(&(tunnel_id, session_id))
                .expect("session exists")
                .interface_name = ifname.to_string();
            Ok(())
        }

        async fn delete_session(&self, tunnel_id: u32, session_id: u32) -> Result<()> {
            let mut inner = self.inner.lock().expect("lock poisoned");
            inner
                .sessions
                .remove(&(tunnel_id, session_id))
                .ok_or_else(|| {
                    Error::Other(format!(
                        "No such session {} on tunnel {}",
                        session_id, tunnel_id
                    ))
                })?;
            Ok(())
        }
    }

    type TestTunnelInput<'a> = (&'a str, u32, u32, IpVersion, IpHost, Option<&'a str>);
    type TestSessionInput<'a> = (&'a str, &'a str, u32, u32, &'a str);

    fn test_config(
        tunnels: Vec<TestTunnelInput<'_>>,
        sessions: Vec<TestSessionInput<'_>>,
    ) -> Config {
        let mut config = Config::default();
        for (name, tunnel_id, peer_tunnel_id, ip_version, remote_addr, bind_interface) in tunnels {
            config.tunnels.insert(
                name.to_string(),
                crate::config::TunnelConfig {
                    tunnel_id,
                    peer_tunnel_id,
                    ip_version,
                    remote_addr,
                    bind_interface: bind_interface.map(|s| s.to_string()),
                },
            );
        }
        for (name, tunnel_name, session_id, peer_session_id, ifname) in sessions {
            config.sessions.insert(
                name.to_string(),
                crate::config::SessionConfig {
                    tunnel_name: tunnel_name.to_string(),
                    session_id,
                    peer_session_id,
                    interface_name: ifname.to_string(),
                },
            );
        }
        config
    }

    fn runtime_with_mock_state(mock: Arc<MockState>) -> Runtime {
        let (control_tx, _control_rx) = mpsc::channel(32);
        let state: Arc<dyn StateOps> = mock;
        Runtime::new_with_state_ops(state, control_tx)
    }

    #[tokio::test]
    async fn reconcile_persists_partial_apply_on_failure() {
        let mock = Arc::new(MockState::default());
        mock.inject_add_session_failure((10, 100));
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));

        let cfg = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V4,
                IpHost::V4Addr(Ipv4Addr::new(198, 51, 100, 1)),
                None,
            )],
            vec![("sess0", "tun0", 100, 100, "l2tp0")],
        );

        let reconcile = runtime.reconcile(&cfg).await;
        assert!(reconcile.is_err());
        assert!(runtime.tunnel_specs.contains_key(&10));
        assert!(runtime.session_specs.is_empty());
    }

    #[tokio::test]
    async fn reconcile_removes_resolver_for_deleted_tunnel() {
        let mock = Arc::new(MockState::default());
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));

        let cfg_with_tunnel = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V6,
                IpHost::V6Addr(Ipv6Addr::LOCALHOST),
                None,
            )],
            vec![],
        );
        runtime
            .reconcile(&cfg_with_tunnel)
            .await
            .expect("initial reconcile");
        assert!(runtime.resolvers.contains_key(&10));

        runtime
            .reconcile(&Config::default())
            .await
            .expect("delete reconcile");
        assert!(runtime.resolvers.is_empty());
        assert!(runtime.tunnel_specs.is_empty());
    }

    #[tokio::test]
    async fn reconcile_handles_interface_name_swap() {
        let mock = Arc::new(MockState::default());
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));

        let initial = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V4,
                IpHost::V4Addr(Ipv4Addr::new(203, 0, 113, 10)),
                None,
            )],
            vec![
                ("sess0", "tun0", 100, 100, "l2tp0"),
                ("sess1", "tun0", 101, 101, "l2tp1"),
            ],
        );
        runtime
            .reconcile(&initial)
            .await
            .expect("initial reconcile");

        let swapped = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V4,
                IpHost::V4Addr(Ipv4Addr::new(203, 0, 113, 10)),
                None,
            )],
            vec![
                ("sess0", "tun0", 100, 100, "l2tp1"),
                ("sess1", "tun0", 101, 101, "l2tp0"),
            ],
        );
        runtime.reconcile(&swapped).await.expect("swap reconcile");

        assert_eq!(mock.session_name(10, 100).as_deref(), Some("l2tp1"));
        assert_eq!(mock.session_name(10, 101).as_deref(), Some("l2tp0"));
        assert_eq!(
            runtime
                .session_specs
                .get(&(10, 100))
                .expect("session exists")
                .interface_name,
            "l2tp1"
        );
        assert_eq!(
            runtime
                .session_specs
                .get(&(10, 101))
                .expect("session exists")
                .interface_name,
            "l2tp0"
        );
    }

    #[tokio::test]
    async fn reconcile_recreate_failure_cleans_stale_resolver() {
        let mock = Arc::new(MockState::default());
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));

        let initial = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V4,
                IpHost::V4Addr(Ipv4Addr::new(203, 0, 113, 10)),
                None,
            )],
            vec![],
        );
        runtime
            .reconcile(&initial)
            .await
            .expect("initial reconcile should succeed");
        assert!(runtime.resolvers.contains_key(&10));

        mock.inject_add_tunnel_failure(10);
        let recreate = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V4,
                IpHost::V4Addr(Ipv4Addr::new(203, 0, 113, 10)),
                Some("vrf0"),
            )],
            vec![],
        );
        let result = runtime.reconcile(&recreate).await;
        assert!(result.is_err());
        assert!(!runtime.resolvers.contains_key(&10));
        assert!(!runtime.tunnel_specs.contains_key(&10));
        assert!(!mock.has_tunnel(10).await);
    }

    #[tokio::test]
    async fn reconcile_update_failure_removes_newly_created_resolver() {
        let mock = Arc::new(MockState::default());
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));

        let initial = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V4,
                IpHost::V4Addr(Ipv4Addr::new(198, 51, 100, 1)),
                None,
            )],
            vec![],
        );
        runtime
            .reconcile(&initial)
            .await
            .expect("initial reconcile should succeed");

        runtime.resolvers.clear();
        mock.inject_modify_tunnel_failure(10);

        let updated = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V4,
                IpHost::V4Addr(Ipv4Addr::new(198, 51, 100, 2)),
                None,
            )],
            vec![],
        );
        let result = runtime.reconcile(&updated).await;
        assert!(result.is_err());
        assert!(!runtime.resolvers.contains_key(&10));
        assert_eq!(
            runtime
                .tunnel_specs
                .get(&10)
                .expect("tunnel spec should rollback")
                .remote_addr,
            IpHost::V4Addr(Ipv4Addr::new(198, 51, 100, 1))
        );
    }

    #[tokio::test]
    async fn reconcile_update_failure_reverts_existing_resolver_target() {
        let mock = Arc::new(MockState::default());
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));

        let initial = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V4,
                IpHost::V4Addr(Ipv4Addr::new(198, 51, 100, 1)),
                None,
            )],
            vec![],
        );
        runtime
            .reconcile(&initial)
            .await
            .expect("initial reconcile should succeed");
        assert!(runtime.resolvers.contains_key(&10));

        mock.inject_modify_tunnel_failure(10);
        let updated = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V4,
                IpHost::V4Addr(Ipv4Addr::new(198, 51, 100, 2)),
                None,
            )],
            vec![],
        );
        let result = runtime.reconcile(&updated).await;
        assert!(result.is_err());

        mock.clear_modify_tunnel_failure();
        runtime.handle_dns_change(10).await;

        assert_eq!(
            mock.tunnel_remote_addr(10),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
        );
    }

    #[test]
    fn plan_tunnel_changes_detects_add_delete_update_and_recreate() {
        let current = BTreeMap::from([
            (
                1,
                DesiredTunnel {
                    tunnel_id: 1,
                    peer_tunnel_id: 11,
                    ip_version: IpVersion::V4,
                    remote_addr: IpHost::V4Addr(Ipv4Addr::new(192, 0, 2, 1)),
                    bind_interface: None,
                },
            ),
            (
                2,
                DesiredTunnel {
                    tunnel_id: 2,
                    peer_tunnel_id: 12,
                    ip_version: IpVersion::V4,
                    remote_addr: IpHost::V4Addr(Ipv4Addr::new(192, 0, 2, 2)),
                    bind_interface: None,
                },
            ),
        ]);

        let desired = BTreeMap::from([
            (
                1,
                DesiredTunnel {
                    tunnel_id: 1,
                    peer_tunnel_id: 11,
                    ip_version: IpVersion::V4,
                    remote_addr: IpHost::V4Addr(Ipv4Addr::new(198, 51, 100, 1)),
                    bind_interface: None,
                },
            ),
            (
                3,
                DesiredTunnel {
                    tunnel_id: 3,
                    peer_tunnel_id: 13,
                    ip_version: IpVersion::V6,
                    remote_addr: IpHost::V6Addr(Ipv6Addr::LOCALHOST),
                    bind_interface: Some("vrf0".to_string()),
                },
            ),
        ]);

        let plan = plan_tunnel_changes(&current, &desired);
        assert!(plan.to_update.contains(&1));
        assert!(plan.to_delete.contains(&2));
        assert!(plan.to_add.contains(&3));
    }

    #[test]
    fn plan_session_changes_detects_modify_recreate_and_add_delete() {
        let current = BTreeMap::from([
            (
                (1, 10),
                DesiredSession {
                    tunnel_id: 1,
                    session_id: 10,
                    peer_session_id: 100,
                    interface_name: "l2tp0".to_string(),
                },
            ),
            (
                (1, 11),
                DesiredSession {
                    tunnel_id: 1,
                    session_id: 11,
                    peer_session_id: 101,
                    interface_name: "l2tp1".to_string(),
                },
            ),
        ]);

        let desired = BTreeMap::from([
            (
                (1, 10),
                DesiredSession {
                    tunnel_id: 1,
                    session_id: 10,
                    peer_session_id: 100,
                    interface_name: "l2tp2".to_string(),
                },
            ),
            (
                (1, 11),
                DesiredSession {
                    tunnel_id: 1,
                    session_id: 11,
                    peer_session_id: 999,
                    interface_name: "l2tp1".to_string(),
                },
            ),
            (
                (1, 12),
                DesiredSession {
                    tunnel_id: 1,
                    session_id: 12,
                    peer_session_id: 102,
                    interface_name: "l2tp3".to_string(),
                },
            ),
        ]);

        let plan = plan_session_changes(&current, &desired);
        assert!(plan.to_modify.contains(&(1, 10)));
        assert!(plan.to_delete.contains(&(1, 11)));
        assert!(plan.to_add.contains(&(1, 11)));
        assert!(plan.to_add.contains(&(1, 12)));
    }
}
