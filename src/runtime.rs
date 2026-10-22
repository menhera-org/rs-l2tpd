//! The reconciler: applies a [`Config`] to the kernel and keeps it applied.
//!
//! A [`Runtime`] owns the kernel state it created and converges it towards
//! the configuration it was last given. It is driven by [`ControlEvent`]s
//! that the caller forwards from a channel; [`crate::service::Service`] does
//! this and is the easier entry point.
//!
//! Interfaces are identified by their index once they are known: a tunnel
//! socket remembers the index of the device it was bound to, and session
//! devices are renamed and configured by index. Configured names are only
//! resolved at the moment a binding is made or checked.

use async_trait::async_trait;
use futures_util::StreamExt;
use iphost::{AutoIpHostResolver, IpHost, IpHostResolver};
use l2tp::{L2tpIfName, L2tpIfNameExt};
use log::{debug, info, warn};
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::{link::LinkAttribute, RouteNetlinkMessage};
use rtnetlink::{new_multicast_connection, MulticastGroup};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use std::time::Duration;

use crate::config::{Config, HwAddr, IpVersion};
use crate::error::{Error, Result};
use crate::state;

pub(crate) type TunnelId = u32;
pub(crate) type SessionId = u32;
pub(crate) type SessionKey = (TunnelId, SessionId);

type DesiredTunnelMap = BTreeMap<TunnelId, DesiredTunnel>;
type DesiredSessionMap = BTreeMap<SessionKey, DesiredSession>;

const DNS_REFRESH_INTERVAL_SECS: u64 = 30;
const DNS_WATCH_POLL_INTERVAL_SECS: u64 = 1;
const DISCARD_REMOTE_ADDR: IpAddr = IpAddr::V6(Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0));

/// Events that drive a [`Runtime`].
///
/// The runtime itself produces the DNS, interface and address events; the
/// embedding program produces [`ReloadRequested`](Self::ReloadRequested)
/// and [`ShutdownRequested`](Self::ShutdownRequested), typically from
/// signals. The enum is `#[non_exhaustive]`.
#[derive(Debug)]
#[non_exhaustive]
pub enum ControlEvent {
    /// The configuration should be read again and applied.
    ReloadRequested,
    /// Every tunnel and session should be removed and the program should
    /// exit.
    ShutdownRequested,
    /// A tunnel's remote host name resolved to a different address.
    DnsChanged {
        /// The tunnel whose resolver changed.
        tunnel_id: u32,
    },
    /// A network interface appeared or changed; `None` means "re-check all".
    InterfaceChanged {
        /// The name the kernel reported, when it is a valid one.
        if_name: Option<L2tpIfName>,
    },
    /// A network interface was removed.
    InterfaceRemoved {
        /// The index of the removed interface.
        if_index: u32,
    },
    /// An address was added to or removed from an interface.
    LocalAddressChanged {
        /// The index of the interface whose addresses changed.
        if_index: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesiredTunnel {
    tunnel_id: u32,
    peer_tunnel_id: u32,
    ip_version: IpVersion,
    remote_addr: IpHost,
    bind_interface: Option<L2tpIfName>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesiredSession {
    tunnel_id: u32,
    session_id: u32,
    peer_session_id: u32,
    interface_name: L2tpIfName,
    interface_hwaddr: Option<HwAddr>,
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
    to_set_hwaddr: Vec<SessionKey>,
}

/// The kernel operations the reconciler needs, as a trait so that tests can
/// substitute a mock.
#[async_trait]
pub(crate) trait StateOps: Send + Sync {
    async fn has_tunnel(&self, tunnel_id: u32) -> bool;
    async fn add_tunnel(
        &self,
        tunnel_id: u32,
        peer_tunnel_id: u32,
        remote_addr: IpAddr,
        if_name: Option<&L2tpIfName>,
    ) -> Result<()>;
    async fn modify_tunnel(&self, tunnel_id: u32, remote_addr: IpAddr) -> Result<()>;
    async fn reconnect_tunnel(&self, tunnel_id: u32) -> Result<()>;
    async fn bind_tunnel_interface(&self, tunnel_id: u32, if_name: &L2tpIfName) -> Result<()>;
    /// The index of the device the tunnel socket is bound to, if any.
    async fn bound_interface_index(&self, tunnel_id: u32) -> Option<u32>;
    /// Forgets a binding whose device no longer exists.
    async fn forget_tunnel_binding(&self, tunnel_id: u32);
    async fn delete_tunnel(&self, tunnel_id: u32) -> Result<()>;
    async fn has_interface(&self, if_name: &L2tpIfName) -> Result<bool>;
    /// The current name of the interface with `index`, `None` when it is gone.
    async fn interface_name(&self, index: u32) -> Result<Option<L2tpIfName>>;
    async fn has_session(&self, tunnel_id: u32, session_id: u32) -> bool;
    async fn add_session(
        &self,
        tunnel_id: u32,
        session_id: u32,
        peer_session_id: u32,
        if_name: &L2tpIfName,
        hwaddr: Option<&HwAddr>,
    ) -> Result<()>;
    async fn modify_session(
        &self,
        tunnel_id: u32,
        session_id: u32,
        ifname: &L2tpIfName,
    ) -> Result<()>;
    async fn set_session_hwaddr(
        &self,
        tunnel_id: u32,
        session_id: u32,
        hwaddr: Option<&HwAddr>,
    ) -> Result<()>;
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
        if_name: Option<&L2tpIfName>,
    ) -> Result<()> {
        state::State::add_tunnel(self, tunnel_id, peer_tunnel_id, remote_addr, if_name).await
    }

    async fn modify_tunnel(&self, tunnel_id: u32, remote_addr: IpAddr) -> Result<()> {
        state::State::modify_tunnel(self, tunnel_id, remote_addr).await
    }

    async fn reconnect_tunnel(&self, tunnel_id: u32) -> Result<()> {
        state::State::reconnect_tunnel(self, tunnel_id).await
    }

    async fn bind_tunnel_interface(&self, tunnel_id: u32, if_name: &L2tpIfName) -> Result<()> {
        state::State::bind_tunnel_interface(self, tunnel_id, if_name).await
    }

    async fn bound_interface_index(&self, tunnel_id: u32) -> Option<u32> {
        state::State::bound_interface_index(self, tunnel_id).await
    }

    async fn forget_tunnel_binding(&self, tunnel_id: u32) {
        state::State::forget_tunnel_binding(self, tunnel_id).await
    }

    async fn delete_tunnel(&self, tunnel_id: u32) -> Result<()> {
        state::State::delete_tunnel(self, tunnel_id).await
    }

    async fn has_interface(&self, if_name: &L2tpIfName) -> Result<bool> {
        state::State::has_interface(if_name).await
    }

    async fn interface_name(&self, index: u32) -> Result<Option<L2tpIfName>> {
        state::State::interface_name(index).await
    }

    async fn has_session(&self, tunnel_id: u32, session_id: u32) -> bool {
        state::State::has_session(self, tunnel_id, session_id).await
    }

    async fn add_session(
        &self,
        tunnel_id: u32,
        session_id: u32,
        peer_session_id: u32,
        if_name: &L2tpIfName,
        hwaddr: Option<&HwAddr>,
    ) -> Result<()> {
        state::State::add_session(
            self,
            tunnel_id,
            session_id,
            peer_session_id,
            if_name,
            hwaddr,
        )
        .await
    }

    async fn modify_session(
        &self,
        tunnel_id: u32,
        session_id: u32,
        ifname: &L2tpIfName,
    ) -> Result<()> {
        state::State::modify_session(self, tunnel_id, session_id, ifname).await
    }

    async fn set_session_hwaddr(
        &self,
        tunnel_id: u32,
        session_id: u32,
        hwaddr: Option<&HwAddr>,
    ) -> Result<()> {
        state::State::set_session_hwaddr(self, tunnel_id, session_id, hwaddr).await
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
    use_discard_until_dns: Arc<AtomicBool>,
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
        let use_discard_until_dns = Arc::new(AtomicBool::new(matches!(
            desired.remote_addr,
            IpHost::Fqdn(_)
        )));
        let initial_addr = if matches!(desired.remote_addr, IpHost::Fqdn(_)) {
            None
        } else {
            Self::current_remote_addr_for(&resolver, desired.ip_version)
        };
        let last_queued_addr = Arc::new(StdRwLock::new(initial_addr));

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
                    .send(ControlEvent::DnsChanged { tunnel_id })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Self {
            resolver,
            ip_version,
            active,
            dns_event_pending,
            use_discard_until_dns,
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

        let replaced = self.resolver.replace_ip_host(desired.remote_addr.clone());
        let host_changed = match replaced {
            Ok(old) => old != desired.remote_addr,
            Err(_) => {
                warn!(
                    "failed to update resolver hostname immediately for tunnel_id={}",
                    desired.tunnel_id
                );
                true
            }
        };

        if let Ok(mut queued) = self.last_queued_addr.write() {
            if matches!(desired.remote_addr, IpHost::Fqdn(_)) && host_changed {
                self.use_discard_until_dns.store(true, Ordering::Release);
                *queued = None;
            } else if self.use_discard_until_dns.load(Ordering::Acquire) {
                *queued = None;
            } else {
                *queued = Self::current_remote_addr_for(&self.resolver, desired.ip_version);
            }
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

    fn current_remote_addr_for_apply(&self) -> Option<IpAddr> {
        if self.use_discard_until_dns.load(Ordering::Acquire) {
            return None;
        }
        self.current_remote_addr()
    }

    fn clear_discard_until_dns(&self) {
        self.use_discard_until_dns.store(false, Ordering::Release);
    }

    fn requeue_dns_change(&self) {
        self.dns_event_pending.store(false, Ordering::Release);
        if let Ok(mut queued) = self.last_queued_addr.write() {
            *queued = None;
        }
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

/// Owns the kernel tunnels and sessions it created and converges them to a
/// [`Config`].
///
/// Create one with [`Runtime::new`] inside a Tokio runtime, call
/// [`reconcile`](Self::reconcile) with each configuration, and feed the
/// [`ControlEvent`]s arriving on the channel to the matching `handle_*`
/// method. [`shutdown`](Self::shutdown) removes everything again.
///
/// Dropping a `Runtime` stops its background tasks and closes the tunnel
/// sockets, which tears the tunnels down; call `shutdown` first for an
/// orderly removal.
pub struct Runtime {
    state: Arc<dyn StateOps>,
    tunnel_specs: DesiredTunnelMap,
    session_specs: DesiredSessionMap,
    pending_bind_interfaces: BTreeMap<TunnelId, L2tpIfName>,
    resolvers: BTreeMap<TunnelId, ResolverRuntime>,
    /// One queued reconnect retry per interface index, so that a burst of
    /// address events on an unreachable interface cannot multiply retries.
    reconnect_retries: BTreeMap<u32, JoinHandle<()>>,
    control_tx: mpsc::Sender<ControlEvent>,
    interface_worker: JoinHandle<()>,
}

impl Runtime {
    /// Opens the kernel L2TP interface and starts watching links and
    /// addresses. Events are sent to `control_tx`; the caller reads the
    /// other end and dispatches them.
    pub async fn new(control_tx: mpsc::Sender<ControlEvent>) -> Result<Self> {
        let state = Arc::new(state::State::new().await?);
        Ok(Self::with_state_ops(state, control_tx))
    }

    fn with_state_ops(state: Arc<dyn StateOps>, control_tx: mpsc::Sender<ControlEvent>) -> Self {
        let interface_worker = spawn_interface_watcher(control_tx.clone());
        Self {
            state,
            tunnel_specs: BTreeMap::new(),
            session_specs: BTreeMap::new(),
            pending_bind_interfaces: BTreeMap::new(),
            resolvers: BTreeMap::new(),
            reconnect_retries: BTreeMap::new(),
            control_tx,
            interface_worker,
        }
    }

    #[cfg(test)]
    fn new_with_state_ops(
        state: Arc<dyn StateOps>,
        control_tx: mpsc::Sender<ControlEvent>,
    ) -> Self {
        let interface_worker = tokio::spawn(async {});
        Self {
            state,
            tunnel_specs: BTreeMap::new(),
            session_specs: BTreeMap::new(),
            pending_bind_interfaces: BTreeMap::new(),
            resolvers: BTreeMap::new(),
            reconnect_retries: BTreeMap::new(),
            control_tx,
            interface_worker,
        }
    }

    /// Converges the kernel state to `config`.
    ///
    /// Changes are applied in order: tunnels are deleted, added and
    /// updated, then sessions are renamed, re-addressed, deleted and added.
    /// On an error the work done so far is kept and recorded, so calling
    /// again with the same configuration continues where it stopped.
    pub async fn reconcile(&mut self, config: &Config) -> Result<()> {
        let (desired_tunnels, desired_sessions) = build_desired_maps(config)?;
        let mut applied_tunnel_specs = self.tunnel_specs.clone();
        let mut applied_session_specs = self.session_specs.clone();
        let mut applied_pending_bind_interfaces = self.pending_bind_interfaces.clone();

        macro_rules! try_apply {
            ($result:expr) => {
                if let Err(e) = $result {
                    self.tunnel_specs = applied_tunnel_specs;
                    self.session_specs = applied_session_specs;
                    self.pending_bind_interfaces = applied_pending_bind_interfaces;
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
            applied_pending_bind_interfaces.remove(tunnel_id);
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

            let remote_addr = match tunnel_remote_addr_for_apply(desired, resolver_runtime) {
                Ok(addr) => addr,
                Err(e) => {
                    if !applied_tunnel_specs.contains_key(tunnel_id) {
                        self.resolvers.remove(tunnel_id);
                    }
                    self.tunnel_specs = applied_tunnel_specs;
                    self.session_specs = applied_session_specs;
                    return Err(e);
                }
            };

            info!(
                "adding tunnel_id={} peer_tunnel_id={} remote_addr={}",
                desired.tunnel_id, desired.peer_tunnel_id, remote_addr
            );
            let bind_interface = self
                .bind_interface_for_tunnel_add(desired.tunnel_id, desired.bind_interface.as_ref())
                .await;
            let mut bound_interface = bind_interface.as_ref();
            if let Err(e) = self
                .state
                .add_tunnel(
                    desired.tunnel_id,
                    desired.peer_tunnel_id,
                    remote_addr,
                    bind_interface.as_ref(),
                )
                .await
            {
                if bind_interface.is_some() && is_missing_interface_bind_error(&e) {
                    warn!(
                        "bind interface vanished for tunnel_id={} if_name={}; creating unbound socket",
                        desired.tunnel_id,
                        desired
                            .bind_interface
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_default()
                    );
                    if let Err(e) = self
                        .state
                        .add_tunnel(desired.tunnel_id, desired.peer_tunnel_id, remote_addr, None)
                        .await
                    {
                        if !applied_tunnel_specs.contains_key(tunnel_id) {
                            self.resolvers.remove(tunnel_id);
                        }
                        self.tunnel_specs = applied_tunnel_specs;
                        self.session_specs = applied_session_specs;
                        self.pending_bind_interfaces = applied_pending_bind_interfaces;
                        return Err(e);
                    }
                    bound_interface = None;
                } else {
                    if !applied_tunnel_specs.contains_key(tunnel_id) {
                        self.resolvers.remove(tunnel_id);
                    }
                    self.tunnel_specs = applied_tunnel_specs;
                    self.session_specs = applied_session_specs;
                    self.pending_bind_interfaces = applied_pending_bind_interfaces;
                    return Err(e);
                }
            }
            record_tunnel_bind_interface(
                &mut applied_pending_bind_interfaces,
                desired,
                bound_interface,
            );
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

            let remote_addr = match tunnel_remote_addr_for_apply(desired, resolver_runtime) {
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
            self.reconcile_tunnel_bind_interface(desired, &mut applied_pending_bind_interfaces)
                .await;
            applied_tunnel_specs.insert(*tunnel_id, desired.clone());
        }

        let unchanged_tunnel_ids: Vec<TunnelId> = self
            .tunnel_specs
            .keys()
            .filter(|id| !tunnel_plan.to_delete.contains(id) && !tunnel_plan.to_update.contains(id))
            .copied()
            .collect();
        for tunnel_id in unchanged_tunnel_ids {
            if let Some(desired) = desired_tunnels.get(&tunnel_id) {
                if let Some(resolver_runtime) = self.resolvers.get(&tunnel_id) {
                    resolver_runtime.apply_tunnel_config(desired);
                }
                self.reconcile_tunnel_bind_interface(desired, &mut applied_pending_bind_interfaces)
                    .await;
                applied_tunnel_specs.insert(tunnel_id, desired.clone());
            }
        }

        let session_plan = plan_session_changes(&applied_session_specs, &desired_sessions);

        let mut reserved_interface_names: BTreeSet<L2tpIfName> = applied_session_specs
            .values()
            .map(|s| s.interface_name)
            .collect();
        reserved_interface_names.extend(desired_sessions.values().map(|s| s.interface_name));
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
            if let Some(applied) = applied_session_specs.get_mut(&(*tunnel_id, *session_id)) {
                applied.interface_name = desired.interface_name;
            }
        }

        for (tunnel_id, session_id) in &session_plan.to_set_hwaddr {
            let desired = desired_sessions
                .get(&(*tunnel_id, *session_id))
                .expect("session exists in desired map");
            info!(
                "setting session interface hardware address tunnel_id={} session_id={} to {}",
                tunnel_id,
                session_id,
                desired
                    .interface_hwaddr
                    .map_or_else(|| "<kernel default>".to_string(), |a| a.to_string())
            );
            try_apply!(
                self.state
                    .set_session_hwaddr(*tunnel_id, *session_id, desired.interface_hwaddr.as_ref())
                    .await
            );
            if let Some(applied) = applied_session_specs.get_mut(&(*tunnel_id, *session_id)) {
                applied.interface_hwaddr = desired.interface_hwaddr;
            }
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
                        desired.interface_hwaddr.as_ref(),
                    )
                    .await
            );
            applied_session_specs.insert((*tunnel_id, *session_id), desired.clone());
        }

        self.tunnel_specs = desired_tunnels;
        self.session_specs = desired_sessions;
        self.pending_bind_interfaces = applied_pending_bind_interfaces;
        self.handle_interface_change(None).await;
        Ok(())
    }

    /// Applies a tunnel's newly resolved remote address.
    pub async fn handle_dns_change(&self, tunnel_id: u32) {
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
            Ok(()) => {
                resolver_runtime.clear_discard_until_dns();
                info!(
                    "dns change applied tunnel_id={} remote_addr={}",
                    tunnel_id, remote_addr
                );
            }
            Err(e) => {
                warn!(
                    "failed to apply dns change tunnel_id={} remote_addr={} error={}",
                    tunnel_id, remote_addr, e
                );
                if resolver_runtime.current_remote_addr() == Some(remote_addr) {
                    resolver_runtime.requeue_dns_change();
                }
            }
        }
    }

    /// Binds tunnel sockets whose bind interface was absent, now that an
    /// interface appeared or changed. `None` re-checks every pending one.
    pub async fn handle_interface_change(&mut self, changed_if_name: Option<&L2tpIfName>) {
        let pending: Vec<(TunnelId, L2tpIfName)> = self
            .pending_bind_interfaces
            .iter()
            .filter(|(_, if_name)| {
                changed_if_name
                    .map(|changed| changed == *if_name)
                    .unwrap_or(true)
            })
            .map(|(tunnel_id, if_name)| (*tunnel_id, *if_name))
            .collect();

        for (tunnel_id, if_name) in pending {
            if !self.tunnel_specs.contains_key(&tunnel_id) {
                self.pending_bind_interfaces.remove(&tunnel_id);
                continue;
            }

            let exists = match self.state.has_interface(&if_name).await {
                Ok(exists) => exists,
                Err(e) => {
                    warn!(
                        "failed to check bind interface tunnel_id={} if_name={} error={}",
                        tunnel_id, if_name, e
                    );
                    continue;
                }
            };

            if !exists {
                continue;
            }

            match self.state.bind_tunnel_interface(tunnel_id, &if_name).await {
                Ok(()) => {
                    info!(
                        "bound tunnel_id={} socket to interface {}",
                        tunnel_id, if_name
                    );
                    self.pending_bind_interfaces.remove(&tunnel_id);
                }
                Err(e) => warn!(
                    "failed to bind tunnel_id={} socket to interface {}: {}",
                    tunnel_id, if_name, e
                ),
            }
        }
    }

    /// Forgets bindings to a removed interface, so that a new interface
    /// with the configured name is bound when it appears.
    pub async fn handle_interface_removed(&mut self, if_index: u32) {
        for desired in self.tunnel_specs.values() {
            let Some(if_name) = desired.bind_interface else {
                continue;
            };
            if self.state.bound_interface_index(desired.tunnel_id).await != Some(if_index) {
                continue;
            }
            info!(
                "bind interface {} (index {}) of tunnel_id={} was removed; waiting for it to reappear",
                if_name, if_index, desired.tunnel_id
            );
            self.state.forget_tunnel_binding(desired.tunnel_id).await;
            self.pending_bind_interfaces
                .insert(desired.tunnel_id, if_name);
        }
    }

    /// Reconnects the tunnels bound to the interface whose addresses
    /// changed, so that the kernel selects a source address again. A failed
    /// reconnect is retried after one second; at most one retry is queued
    /// per interface, however many events arrive meanwhile.
    pub async fn handle_local_address_change(&mut self, if_index: u32) {
        let mut retry_needed = false;
        for desired in self.tunnel_specs.values() {
            let Some(if_name) = desired.bind_interface.as_ref() else {
                continue;
            };
            if self.state.bound_interface_index(desired.tunnel_id).await != Some(if_index) {
                continue;
            }

            match self.state.reconnect_tunnel(desired.tunnel_id).await {
                Ok(()) => info!(
                    "reconnected tunnel_id={} after local address change on {} (index {})",
                    desired.tunnel_id, if_name, if_index
                ),
                Err(e) => {
                    retry_needed = true;
                    warn!(
                        "failed to reconnect tunnel_id={} after local address change on {} (index {}): {}; will retry",
                        desired.tunnel_id, if_name, if_index, e
                    );
                }
            }
        }

        self.reconnect_retries
            .retain(|_, retry| !retry.is_finished());
        if retry_needed && !self.reconnect_retries.contains_key(&if_index) {
            let control_tx = self.control_tx.clone();
            let retry = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let _ = control_tx
                    .send(ControlEvent::LocalAddressChanged { if_index })
                    .await;
            });
            self.reconnect_retries.insert(if_index, retry);
        }
    }

    /// Removes every tunnel and session. Each tunnel deletion may wait up
    /// to about two seconds for the kernel.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.reconcile(&Config::default()).await
    }

    async fn bind_interface_for_tunnel_add(
        &self,
        tunnel_id: u32,
        if_name: Option<&L2tpIfName>,
    ) -> Option<L2tpIfName> {
        let if_name = if_name?;

        match self.state.has_interface(if_name).await {
            Ok(true) => Some(*if_name),
            Ok(false) => {
                info!(
                    "bind interface {} is absent for tunnel_id={}; creating unbound socket",
                    if_name, tunnel_id
                );
                None
            }
            Err(e) => {
                warn!(
                    "failed to check bind interface tunnel_id={} if_name={}: {}; creating unbound socket",
                    tunnel_id, if_name, e
                );
                None
            }
        }
    }

    /// Checks that the tunnel is bound to a device currently carrying the
    /// configured name; otherwise queues a (re)bind, which
    /// [`handle_interface_change`](Self::handle_interface_change) performs
    /// as soon as such a device exists.
    async fn reconcile_tunnel_bind_interface(
        &self,
        desired: &DesiredTunnel,
        pending: &mut BTreeMap<TunnelId, L2tpIfName>,
    ) {
        let Some(if_name) = desired.bind_interface.as_ref() else {
            pending.remove(&desired.tunnel_id);
            return;
        };

        if pending.contains_key(&desired.tunnel_id) {
            return;
        }

        let bound_name = match self.state.bound_interface_index(desired.tunnel_id).await {
            Some(index) => match self.state.interface_name(index).await {
                Ok(name) => name,
                Err(e) => {
                    warn!(
                        "failed to check bind interface tunnel_id={} index={} error={}",
                        desired.tunnel_id, index, e
                    );
                    None
                }
            },
            None => None,
        };
        if bound_name.as_ref() == Some(if_name) {
            return;
        }

        if bound_name.is_some() {
            info!(
                "tunnel_id={} is bound to a device no longer named {}; rebinding",
                desired.tunnel_id, if_name
            );
            self.state.forget_tunnel_binding(desired.tunnel_id).await;
        }
        pending.insert(desired.tunnel_id, *if_name);
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.interface_worker.abort();
        for retry in self.reconnect_retries.values() {
            retry.abort();
        }
    }
}

fn spawn_interface_watcher(control_tx: mpsc::Sender<ControlEvent>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if control_tx.is_closed() {
                break;
            }

            let (connection, _handle, mut messages) =
                match new_multicast_connection(&[MulticastGroup::Link, MulticastGroup::Ipv6Ifaddr])
                {
                    Ok(parts) => parts,
                    Err(e) => {
                        warn!("failed to open rtnetlink link monitor: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
            let connection_task = tokio::spawn(connection);

            if control_tx
                .send(ControlEvent::InterfaceChanged { if_name: None })
                .await
                .is_err()
            {
                connection_task.abort();
                break;
            }

            while let Some((message, addr)) = messages.next().await {
                if control_tx.is_closed() {
                    break;
                }
                // Only the kernel (port 0) announces links and addresses. Any
                // process can unicast to this socket, and acting on such a
                // message would let an unprivileged user force reconnects.
                if addr.port_number() != 0 {
                    debug!(
                        "ignoring rtnetlink message from user-space port {}",
                        addr.port_number()
                    );
                    continue;
                }
                let Some(event) = control_event_for_netlink_payload(message.payload) else {
                    continue;
                };
                if control_tx.send(event).await.is_err() {
                    break;
                }
            }

            connection_task.abort();
            if control_tx.is_closed() {
                break;
            }
            warn!("rtnetlink link monitor stopped; reopening");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

fn control_event_for_netlink_payload(
    payload: NetlinkPayload<RouteNetlinkMessage>,
) -> Option<ControlEvent> {
    match payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
            Some(ControlEvent::InterfaceChanged {
                // A name the kernel reports that fails validation cannot be
                // one from the configuration; None re-checks every pending
                // interface, which is always correct.
                if_name: link.attributes.into_iter().find_map(|attr| match attr {
                    LinkAttribute::IfName(name) => L2tpIfName::from_name(&name).ok(),
                    _ => None,
                }),
            })
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link)) => {
            Some(ControlEvent::InterfaceRemoved {
                if_index: link.header.index,
            })
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(address))
        | NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelAddress(address)) => {
            Some(ControlEvent::LocalAddressChanged {
                if_index: address.header.index,
            })
        }
        NetlinkPayload::Overrun(_) => Some(ControlEvent::InterfaceChanged { if_name: None }),
        _ => None,
    }
}

fn record_tunnel_bind_interface(
    pending: &mut BTreeMap<TunnelId, L2tpIfName>,
    desired: &DesiredTunnel,
    bound_interface: Option<&L2tpIfName>,
) {
    if bound_interface.is_some() || desired.bind_interface.is_none() {
        pending.remove(&desired.tunnel_id);
    } else if let Some(if_name) = &desired.bind_interface {
        pending.insert(desired.tunnel_id, *if_name);
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
        if current_session.interface_hwaddr != desired_session.interface_hwaddr {
            plan.to_set_hwaddr.push(*key);
        }
    }

    for key in desired.keys() {
        if !current.contains_key(key) {
            plan.to_add.insert(*key);
        }
    }

    plan
}

fn allocate_temp_interface_name(
    used_names: &mut BTreeSet<L2tpIfName>,
    counter: &mut u32,
) -> L2tpIfName {
    loop {
        // "rsl2tp" plus eight hex digits is 14 bytes, always a valid name.
        let candidate = format!("rsl2tp{:08x}", *counter);
        *counter = counter.wrapping_add(1);
        let Ok(candidate) = L2tpIfName::from_name(&candidate) else {
            continue;
        };
        if used_names.insert(candidate) {
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

fn tunnel_remote_addr_for_apply(
    desired: &DesiredTunnel,
    resolver_runtime: &ResolverRuntime,
) -> Result<IpAddr> {
    if let Some(addr) = resolver_runtime.current_remote_addr_for_apply() {
        return Ok(addr);
    }

    if matches!(desired.remote_addr, IpHost::Fqdn(_)) {
        return Ok(DISCARD_REMOTE_ADDR);
    }

    resolve_ip_host_once(&desired.remote_addr, desired.ip_version)
}

fn is_missing_interface_bind_error(error: &Error) -> bool {
    match error {
        Error::L2tp(l2tp::Error::Io(e)) => e.raw_os_error() == Some(libc::ENODEV),
        Error::L2tp(l2tp::Error::KernelError { code, .. }) => *code == libc::ENODEV,
        _ => false,
    }
}

fn build_desired_maps(config: &Config) -> Result<(DesiredTunnelMap, DesiredSessionMap)> {
    let mut tunnels: DesiredTunnelMap = BTreeMap::new();
    for tunnel in config.tunnels().values() {
        let desired = DesiredTunnel {
            tunnel_id: tunnel.tunnel_id(),
            peer_tunnel_id: tunnel.peer_tunnel_id(),
            ip_version: tunnel.ip_version(),
            remote_addr: tunnel.remote_addr().clone(),
            bind_interface: tunnel.bind_interface().copied(),
        };

        if tunnels.insert(desired.tunnel_id, desired).is_some() {
            return Err(Error::InvalidConfig(format!(
                "duplicate tunnel_id in config: {}",
                tunnel.tunnel_id()
            )));
        }
    }

    let mut sessions: DesiredSessionMap = BTreeMap::new();
    let mut interface_names: BTreeMap<L2tpIfName, String> = BTreeMap::new();
    for (session_name, session) in config.sessions() {
        let tunnel = config.tunnels().get(session.tunnel_name()).ok_or_else(|| {
            Error::InvalidConfig(format!("tunnel not defined: {}", session.tunnel_name()))
        })?;
        let tunnel_id = tunnel.tunnel_id();

        if let Some(existing_tunnel) =
            interface_names.insert(*session.interface_name(), session_name.clone())
        {
            return Err(Error::InvalidConfig(format!(
                "duplicate session interface_name={} used by sessions {} and {}",
                session.interface_name(),
                existing_tunnel,
                session_name
            )));
        }

        let desired = DesiredSession {
            tunnel_id,
            session_id: session.session_id(),
            peer_session_id: session.peer_session_id(),
            interface_name: *session.interface_name(),
            interface_hwaddr: session.interface_hwaddr().copied(),
        };
        let key = (desired.tunnel_id, desired.session_id);

        if sessions.insert(key, desired).is_some() {
            return Err(Error::InvalidConfig(format!(
                "duplicate session_id={} in tunnel_id={}",
                session.session_id(),
                tunnel_id
            )));
        }
    }

    Ok((tunnels, sessions))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::{SessionConfig, TunnelConfig};
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;

    fn ifname(name: &str) -> L2tpIfName {
        L2tpIfName::from_name(name).unwrap()
    }

    fn hwaddr(s: &str) -> HwAddr {
        s.parse().unwrap()
    }

    #[derive(Debug, Clone)]
    struct MockTunnel {
        remote_addr: IpAddr,
        /// Name and index of the bound device, as the real state records.
        bound_interface: Option<(L2tpIfName, u32)>,
    }

    #[derive(Debug, Clone)]
    struct MockSession {
        interface_name: L2tpIfName,
        hwaddr: Option<HwAddr>,
    }

    #[derive(Default)]
    struct MockStateInner {
        tunnels: BTreeMap<u32, MockTunnel>,
        sessions: BTreeMap<(u32, u32), MockSession>,
        /// Interfaces by name, with the index each one was created with.
        interfaces: BTreeMap<L2tpIfName, u32>,
        next_interface_index: u32,
        fail_add_tunnel_for: Option<u32>,
        vanish_bind_interface_for: Option<u32>,
        fail_modify_tunnel_for: Option<u32>,
        fail_reconnect_tunnel_for: Option<u32>,
        fail_add_session_for: Option<(u32, u32)>,
        fail_set_hwaddr_for: Option<(u32, u32)>,
        reconnect_counts: BTreeMap<u32, u32>,
        hwaddr_sets: u32,
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

        fn inject_bind_interface_vanish(&self, tunnel_id: u32) {
            self.inner
                .lock()
                .expect("lock poisoned")
                .vanish_bind_interface_for = Some(tunnel_id);
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

        fn inject_set_hwaddr_failure(&self, key: Option<(u32, u32)>) {
            self.inner
                .lock()
                .expect("lock poisoned")
                .fail_set_hwaddr_for = key;
        }

        /// Creates an interface with a fresh index and returns the index.
        fn add_interface(&self, if_name: &str) -> u32 {
            let mut inner = self.inner.lock().expect("lock poisoned");
            inner.next_interface_index += 1;
            let index = inner.next_interface_index;
            inner.interfaces.insert(ifname(if_name), index);
            index
        }

        fn remove_interface(&self, if_name: &str) -> u32 {
            self.inner
                .lock()
                .expect("lock poisoned")
                .interfaces
                .remove(&ifname(if_name))
                .expect("interface exists")
        }

        fn rename_interface(&self, from: &str, to: &str) {
            let mut inner = self.inner.lock().expect("lock poisoned");
            let index = inner
                .interfaces
                .remove(&ifname(from))
                .expect("interface exists");
            inner.interfaces.insert(ifname(to), index);
        }

        fn session_name(&self, tunnel_id: u32, session_id: u32) -> Option<L2tpIfName> {
            self.inner
                .lock()
                .expect("lock poisoned")
                .sessions
                .get(&(tunnel_id, session_id))
                .map(|s| s.interface_name)
        }

        fn session_hwaddr(&self, tunnel_id: u32, session_id: u32) -> Option<HwAddr> {
            self.inner
                .lock()
                .expect("lock poisoned")
                .sessions
                .get(&(tunnel_id, session_id))
                .and_then(|s| s.hwaddr)
        }

        fn hwaddr_sets(&self) -> u32 {
            self.inner.lock().expect("lock poisoned").hwaddr_sets
        }

        fn tunnel_remote_addr(&self, tunnel_id: u32) -> Option<IpAddr> {
            self.inner
                .lock()
                .expect("lock poisoned")
                .tunnels
                .get(&tunnel_id)
                .map(|t| t.remote_addr)
        }

        fn tunnel_bound_interface(&self, tunnel_id: u32) -> Option<(L2tpIfName, u32)> {
            self.inner
                .lock()
                .expect("lock poisoned")
                .tunnels
                .get(&tunnel_id)
                .and_then(|t| t.bound_interface)
        }

        fn reconnect_count(&self, tunnel_id: u32) -> u32 {
            *self
                .inner
                .lock()
                .expect("lock poisoned")
                .reconnect_counts
                .get(&tunnel_id)
                .unwrap_or(&0)
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
            if_name: Option<&L2tpIfName>,
        ) -> Result<()> {
            let mut inner = self.inner.lock().expect("lock poisoned");
            if inner.fail_add_tunnel_for == Some(tunnel_id) {
                return Err(Error::Other("injected add_tunnel failure".to_string()));
            }
            if inner.tunnels.contains_key(&tunnel_id) {
                return Err(Error::Other("Duplicate tunnel_id".to_string()));
            }
            let mut bound_interface = None;
            if let Some(if_name) = if_name {
                if inner.vanish_bind_interface_for == Some(tunnel_id) {
                    inner.vanish_bind_interface_for = None;
                    inner.interfaces.remove(if_name);
                    return Err(Error::L2tp(l2tp::Error::Io(io::Error::from_raw_os_error(
                        libc::ENODEV,
                    ))));
                }
                let Some(index) = inner.interfaces.get(if_name).copied() else {
                    return Err(Error::Other(format!("interface not found: {}", if_name)));
                };
                bound_interface = Some((*if_name, index));
            }
            inner.tunnels.insert(
                tunnel_id,
                MockTunnel {
                    remote_addr,
                    bound_interface,
                },
            );
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

        async fn reconnect_tunnel(&self, tunnel_id: u32) -> Result<()> {
            let mut inner = self.inner.lock().expect("lock poisoned");
            if !inner.tunnels.contains_key(&tunnel_id) {
                return Err(Error::Other("tunnel not found".to_string()));
            }
            *inner.reconnect_counts.entry(tunnel_id).or_default() += 1;
            if inner.fail_reconnect_tunnel_for == Some(tunnel_id) {
                return Err(Error::Other("injected reconnect failure".to_string()));
            }
            Ok(())
        }

        async fn bind_tunnel_interface(&self, tunnel_id: u32, if_name: &L2tpIfName) -> Result<()> {
            let mut inner = self.inner.lock().expect("lock poisoned");
            let Some(index) = inner.interfaces.get(if_name).copied() else {
                return Err(Error::Other(format!("interface not found: {}", if_name)));
            };
            let tunnel = inner
                .tunnels
                .get_mut(&tunnel_id)
                .ok_or_else(|| Error::Other("tunnel not found".to_string()))?;
            tunnel.bound_interface = Some((*if_name, index));
            Ok(())
        }

        async fn bound_interface_index(&self, tunnel_id: u32) -> Option<u32> {
            self.tunnel_bound_interface(tunnel_id)
                .map(|(_, index)| index)
        }

        async fn forget_tunnel_binding(&self, tunnel_id: u32) {
            if let Some(tunnel) = self
                .inner
                .lock()
                .expect("lock poisoned")
                .tunnels
                .get_mut(&tunnel_id)
            {
                tunnel.bound_interface = None;
            }
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

        async fn has_interface(&self, if_name: &L2tpIfName) -> Result<bool> {
            Ok(self
                .inner
                .lock()
                .expect("lock poisoned")
                .interfaces
                .contains_key(if_name))
        }

        async fn interface_name(&self, index: u32) -> Result<Option<L2tpIfName>> {
            Ok(self
                .inner
                .lock()
                .expect("lock poisoned")
                .interfaces
                .iter()
                .find_map(|(name, i)| (*i == index).then_some(*name)))
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
            if_name: &L2tpIfName,
            hwaddr: Option<&HwAddr>,
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
                .any(|session| session.interface_name == *if_name)
            {
                return Err(Error::Other(format!("interface exists: {}", if_name)));
            }
            if hwaddr.is_some() {
                inner.hwaddr_sets += 1;
            }
            inner.sessions.insert(
                (tunnel_id, session_id),
                MockSession {
                    interface_name: *if_name,
                    hwaddr: hwaddr.copied(),
                },
            );
            Ok(())
        }

        async fn modify_session(
            &self,
            tunnel_id: u32,
            session_id: u32,
            ifname: &L2tpIfName,
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
                .interface_name;
            if current_ifname == *ifname {
                return Ok(());
            }
            if inner.sessions.iter().any(|(key, session)| {
                *key != (tunnel_id, session_id) && session.interface_name == *ifname
            }) {
                return Err(Error::Other(format!("interface exists: {}", ifname)));
            }
            inner
                .sessions
                .get_mut(&(tunnel_id, session_id))
                .expect("session exists")
                .interface_name = *ifname;
            Ok(())
        }

        async fn set_session_hwaddr(
            &self,
            tunnel_id: u32,
            session_id: u32,
            hwaddr: Option<&HwAddr>,
        ) -> Result<()> {
            let mut inner = self.inner.lock().expect("lock poisoned");
            if inner.fail_set_hwaddr_for == Some((tunnel_id, session_id)) {
                return Err(Error::Other(
                    "injected set_session_hwaddr failure".to_string(),
                ));
            }
            inner.hwaddr_sets += 1;
            let session = inner
                .sessions
                .get_mut(&(tunnel_id, session_id))
                .ok_or_else(|| {
                    Error::Other(format!(
                        "No such session {} in tunnel {}",
                        session_id, tunnel_id
                    ))
                })?;
            session.hwaddr = hwaddr.copied();
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
    type TestSessionInput<'a> = (&'a str, &'a str, u32, u32, &'a str, Option<&'a str>);

    fn test_config(
        tunnels: Vec<TestTunnelInput<'_>>,
        sessions: Vec<TestSessionInput<'_>>,
    ) -> Config {
        let mut config = Config::new();
        for (name, tunnel_id, peer_tunnel_id, ip_version, remote_addr, bind_interface) in tunnels {
            config
                .insert_tunnel(
                    name,
                    TunnelConfig::new(tunnel_id, ip_version, remote_addr)
                        .with_peer_tunnel_id(peer_tunnel_id)
                        .with_bind_interface(bind_interface.map(ifname)),
                )
                .expect("valid tunnel");
        }
        for (name, tunnel_name, session_id, peer_session_id, if_name, hw) in sessions {
            config
                .insert_session(
                    name,
                    SessionConfig::new(tunnel_name, session_id, ifname(if_name))
                        .with_peer_session_id(peer_session_id)
                        .with_interface_hwaddr(hw.map(hwaddr)),
                )
                .expect("valid session");
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
            vec![("sess0", "tun0", 100, 100, "l2tp0", None)],
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
                ("sess0", "tun0", 100, 100, "l2tp0", None),
                ("sess1", "tun0", 101, 101, "l2tp1", None),
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
                ("sess0", "tun0", 100, 100, "l2tp1", None),
                ("sess1", "tun0", 101, 101, "l2tp0", None),
            ],
        );
        runtime.reconcile(&swapped).await.expect("swap reconcile");

        assert_eq!(mock.session_name(10, 100), Some(ifname("l2tp1")));
        assert_eq!(mock.session_name(10, 101), Some(ifname("l2tp0")));
        assert_eq!(
            runtime
                .session_specs
                .get(&(10, 100))
                .expect("session exists")
                .interface_name,
            ifname("l2tp1")
        );
        assert_eq!(
            runtime
                .session_specs
                .get(&(10, 101))
                .expect("session exists")
                .interface_name,
            ifname("l2tp0")
        );
    }

    #[tokio::test]
    async fn reconcile_applies_changes_and_removes_session_hwaddr() {
        let mock = Arc::new(MockState::default());
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));
        let tunnel = (
            "tun0",
            10,
            10,
            IpVersion::V4,
            IpHost::V4Addr(Ipv4Addr::new(203, 0, 113, 10)),
            None,
        );

        let with_hwaddr = test_config(
            vec![tunnel.clone()],
            vec![(
                "sess0",
                "tun0",
                100,
                100,
                "l2tp0",
                Some("02:00:5e:00:53:01"),
            )],
        );
        runtime
            .reconcile(&with_hwaddr)
            .await
            .expect("initial reconcile");
        assert_eq!(
            mock.session_hwaddr(10, 100),
            Some(hwaddr("02:00:5e:00:53:01"))
        );
        assert_eq!(mock.hwaddr_sets(), 1);

        // Unchanged configuration: nothing is set again.
        runtime
            .reconcile(&with_hwaddr)
            .await
            .expect("idempotent reconcile");
        assert_eq!(mock.hwaddr_sets(), 1);

        // A changed address together with a rename applies both.
        let changed = test_config(
            vec![tunnel.clone()],
            vec![(
                "sess0",
                "tun0",
                100,
                100,
                "l2tp5",
                Some("02:00:5e:00:53:02"),
            )],
        );
        runtime.reconcile(&changed).await.expect("change reconcile");
        assert_eq!(mock.session_name(10, 100), Some(ifname("l2tp5")));
        assert_eq!(
            mock.session_hwaddr(10, 100),
            Some(hwaddr("02:00:5e:00:53:02"))
        );
        assert_eq!(mock.hwaddr_sets(), 2);

        // Dropping the address restores the kernel default (None).
        let without = test_config(
            vec![tunnel],
            vec![("sess0", "tun0", 100, 100, "l2tp5", None)],
        );
        runtime.reconcile(&without).await.expect("remove reconcile");
        assert_eq!(mock.session_hwaddr(10, 100), None);
        assert_eq!(mock.hwaddr_sets(), 3);
    }

    #[tokio::test]
    async fn reconcile_retries_failed_hwaddr_change_without_repeating_rename() {
        let mock = Arc::new(MockState::default());
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));
        let tunnel = (
            "tun0",
            10,
            10,
            IpVersion::V4,
            IpHost::V4Addr(Ipv4Addr::new(203, 0, 113, 10)),
            None,
        );
        let initial = test_config(
            vec![tunnel.clone()],
            vec![("sess0", "tun0", 100, 100, "l2tp0", None)],
        );
        runtime
            .reconcile(&initial)
            .await
            .expect("initial reconcile");

        mock.inject_set_hwaddr_failure(Some((10, 100)));
        let changed = test_config(
            vec![tunnel],
            vec![(
                "sess0",
                "tun0",
                100,
                100,
                "l2tp1",
                Some("02:00:5e:00:53:01"),
            )],
        );
        assert!(runtime.reconcile(&changed).await.is_err());
        // The rename was applied and recorded; the address was not.
        assert_eq!(mock.session_name(10, 100), Some(ifname("l2tp1")));
        let applied = runtime.session_specs.get(&(10, 100)).expect("session kept");
        assert_eq!(applied.interface_name, ifname("l2tp1"));
        assert_eq!(applied.interface_hwaddr, None);

        mock.inject_set_hwaddr_failure(None);
        runtime.reconcile(&changed).await.expect("retry reconcile");
        assert_eq!(
            mock.session_hwaddr(10, 100),
            Some(hwaddr("02:00:5e:00:53:01"))
        );
        assert_eq!(
            runtime
                .session_specs
                .get(&(10, 100))
                .unwrap()
                .interface_hwaddr,
            Some(hwaddr("02:00:5e:00:53:01"))
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

    #[tokio::test]
    async fn dns_apply_failure_requeues_current_address() {
        let mock = Arc::new(MockState::default());
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
            vec![],
        );
        runtime.reconcile(&cfg).await.expect("initial reconcile");

        let resolver = runtime.resolvers.get(&10).expect("resolver exists");
        resolver.dns_event_pending.store(true, Ordering::Release);
        *resolver.last_queued_addr.write().expect("queue lock") =
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));

        mock.inject_modify_tunnel_failure(10);
        runtime.handle_dns_change(10).await;

        let resolver = runtime.resolvers.get(&10).expect("resolver exists");
        assert!(!resolver.dns_event_pending.load(Ordering::Acquire));
        assert_eq!(*resolver.last_queued_addr.read().expect("queue lock"), None);
    }

    #[tokio::test]
    async fn reconcile_uses_discard_addr_for_unresolved_fqdn() {
        let mock = Arc::new(MockState::default());
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));

        let cfg = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V6,
                "unresolved.example.invalid".parse::<IpHost>().unwrap(),
                None,
            )],
            vec![],
        );

        runtime
            .reconcile(&cfg)
            .await
            .expect("reconcile should succeed");

        assert_eq!(mock.tunnel_remote_addr(10), Some(DISCARD_REMOTE_ADDR));
    }

    #[tokio::test]
    async fn reconcile_defers_missing_bind_interface_until_it_appears() {
        let mock = Arc::new(MockState::default());
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));

        let cfg = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V6,
                IpHost::V6Addr(Ipv6Addr::LOCALHOST),
                Some("vrf0"),
            )],
            vec![],
        );

        runtime.reconcile(&cfg).await.expect("initial reconcile");
        assert_eq!(mock.tunnel_bound_interface(10), None);
        assert_eq!(
            runtime.pending_bind_interfaces.get(&10).copied(),
            Some(ifname("vrf0"))
        );

        runtime.handle_interface_change(None).await;
        assert_eq!(mock.tunnel_bound_interface(10), None);

        let index = mock.add_interface("vrf0");
        runtime.handle_interface_change(Some(&ifname("vrf0"))).await;

        assert_eq!(
            mock.tunnel_bound_interface(10),
            Some((ifname("vrf0"), index))
        );
        assert!(!runtime.pending_bind_interfaces.contains_key(&10));
    }

    #[tokio::test]
    async fn removed_bind_interface_is_rebound_when_it_reappears() {
        let mock = Arc::new(MockState::default());
        let first = mock.add_interface("vrf0");
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));
        let cfg = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V6,
                IpHost::V6Addr(Ipv6Addr::LOCALHOST),
                Some("vrf0"),
            )],
            vec![],
        );
        runtime.reconcile(&cfg).await.expect("initial reconcile");
        assert_eq!(
            mock.tunnel_bound_interface(10),
            Some((ifname("vrf0"), first))
        );

        // An unrelated interface going away changes nothing.
        runtime.handle_interface_removed(first + 100).await;
        assert!(runtime.pending_bind_interfaces.is_empty());

        assert_eq!(mock.remove_interface("vrf0"), first);
        runtime.handle_interface_removed(first).await;
        assert_eq!(mock.tunnel_bound_interface(10), None);
        assert_eq!(
            runtime.pending_bind_interfaces.get(&10).copied(),
            Some(ifname("vrf0"))
        );

        let second = mock.add_interface("vrf0");
        assert_ne!(first, second);
        runtime.handle_interface_change(Some(&ifname("vrf0"))).await;
        assert_eq!(
            mock.tunnel_bound_interface(10),
            Some((ifname("vrf0"), second))
        );
        assert!(runtime.pending_bind_interfaces.is_empty());
    }

    #[tokio::test]
    async fn reconcile_rebinds_when_bound_device_was_renamed_away() {
        let mock = Arc::new(MockState::default());
        let first = mock.add_interface("vrf0");
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));
        let cfg = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V6,
                IpHost::V6Addr(Ipv6Addr::LOCALHOST),
                Some("vrf0"),
            )],
            vec![],
        );
        runtime.reconcile(&cfg).await.expect("initial reconcile");

        // The bound device keeps its identity under a new name: between
        // reconciles nothing happens to the binding.
        mock.rename_interface("vrf0", "vrf9");
        runtime.handle_interface_change(None).await;
        assert_eq!(
            mock.tunnel_bound_interface(10),
            Some((ifname("vrf0"), first))
        );

        // A reconcile notices the configured name is no longer the bound
        // device's name and waits for a device called vrf0.
        runtime
            .reconcile(&cfg)
            .await
            .expect("reconcile after rename");
        assert_eq!(mock.tunnel_bound_interface(10), None);
        assert_eq!(
            runtime.pending_bind_interfaces.get(&10).copied(),
            Some(ifname("vrf0"))
        );

        let second = mock.add_interface("vrf0");
        runtime
            .reconcile(&cfg)
            .await
            .expect("reconcile with new vrf0");
        assert_eq!(
            mock.tunnel_bound_interface(10),
            Some((ifname("vrf0"), second))
        );
        assert!(runtime.pending_bind_interfaces.is_empty());
    }

    #[tokio::test]
    async fn local_address_change_reconnects_tunnels_bound_to_changed_interface() {
        let mock = Arc::new(MockState::default());
        let underlay = mock.add_interface("underlay0");
        let other = mock.add_interface("other0");
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));
        let cfg = test_config(
            vec![
                (
                    "bound",
                    10,
                    10,
                    IpVersion::V6,
                    IpHost::V6Addr(Ipv6Addr::LOCALHOST),
                    Some("underlay0"),
                ),
                (
                    "unbound",
                    11,
                    11,
                    IpVersion::V6,
                    IpHost::V6Addr(Ipv6Addr::LOCALHOST),
                    None,
                ),
            ],
            vec![],
        );

        runtime.reconcile(&cfg).await.expect("initial reconcile");
        runtime.handle_local_address_change(other).await;
        assert_eq!(mock.reconnect_count(10), 0);

        runtime.handle_local_address_change(underlay).await;
        assert_eq!(mock.reconnect_count(10), 1);
        assert_eq!(mock.reconnect_count(11), 0);

        // The match is by the bound device's identity, not by its name: a
        // new device that takes over the name is not the bound one.
        mock.rename_interface("underlay0", "underlay9");
        let usurper = mock.add_interface("underlay0");
        runtime.handle_local_address_change(usurper).await;
        assert_eq!(mock.reconnect_count(10), 1);
        runtime.handle_local_address_change(underlay).await;
        assert_eq!(mock.reconnect_count(10), 2);
    }

    #[tokio::test]
    async fn local_address_change_retries_failed_reconnect_after_one_second() {
        let mock = Arc::new(MockState::default());
        let underlay = mock.add_interface("underlay0");
        let (control_tx, mut control_rx) = mpsc::channel(32);
        let mut runtime = Runtime::new_with_state_ops(mock.clone(), control_tx);
        let cfg = test_config(
            vec![(
                "bound",
                10,
                10,
                IpVersion::V6,
                IpHost::V6Addr(Ipv6Addr::LOCALHOST),
                Some("underlay0"),
            )],
            vec![],
        );
        runtime.reconcile(&cfg).await.unwrap();
        mock.inner.lock().unwrap().fail_reconnect_tunnel_for = Some(10);

        let started = tokio::time::Instant::now();
        runtime.handle_local_address_change(underlay).await;
        assert_eq!(mock.reconnect_count(10), 1);
        // A burst of further events while the retry is queued does not
        // queue more retries.
        runtime.handle_local_address_change(underlay).await;
        runtime.handle_local_address_change(underlay).await;
        assert_eq!(mock.reconnect_count(10), 3);
        assert_eq!(runtime.reconnect_retries.len(), 1);
        let event = tokio::time::timeout(Duration::from_secs(3), control_rx.recv())
            .await
            .expect("failed reconnect should schedule a retry")
            .expect("control channel remains open");
        assert!(started.elapsed() >= Duration::from_secs(1));
        let ControlEvent::LocalAddressChanged { if_index } = event else {
            panic!("expected a local address retry");
        };
        assert_eq!(if_index, underlay);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), control_rx.recv())
                .await
                .is_err(),
            "only one retry is queued per interface"
        );

        // The retry itself fails again: exactly one further retry follows.
        runtime.handle_local_address_change(if_index).await;
        assert_eq!(mock.reconnect_count(10), 4);
        assert_eq!(runtime.reconnect_retries.len(), 1);
        let event = tokio::time::timeout(Duration::from_secs(3), control_rx.recv())
            .await
            .expect("second retry")
            .expect("control channel remains open");
        assert!(matches!(event, ControlEvent::LocalAddressChanged { .. }));

        mock.inner.lock().unwrap().fail_reconnect_tunnel_for = None;
        runtime.handle_local_address_change(if_index).await;
        assert_eq!(mock.reconnect_count(10), 5);
        assert!(runtime.reconnect_retries.is_empty());
        assert_eq!(
            mock.tunnel_bound_interface(10),
            Some((ifname("underlay0"), underlay))
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(1100), control_rx.recv())
                .await
                .is_err(),
            "successful reconnect should not schedule another retry"
        );
    }

    #[tokio::test]
    async fn reconcile_retries_unbound_when_bind_interface_vanishes_during_add() {
        let mock = Arc::new(MockState::default());
        mock.add_interface("vrf0");
        mock.inject_bind_interface_vanish(10);
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));

        let cfg = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V6,
                IpHost::V6Addr(Ipv6Addr::LOCALHOST),
                Some("vrf0"),
            )],
            vec![],
        );

        runtime.reconcile(&cfg).await.expect("initial reconcile");

        assert_eq!(mock.tunnel_bound_interface(10), None);
        assert_eq!(
            runtime.pending_bind_interfaces.get(&10).copied(),
            Some(ifname("vrf0"))
        );
    }

    #[tokio::test]
    async fn reconcile_switches_from_ip_to_fqdn_with_discard_addr_until_dns_resolves() {
        let mock = Arc::new(MockState::default());
        let mut runtime = runtime_with_mock_state(Arc::clone(&mock));

        let initial = test_config(
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
            .reconcile(&initial)
            .await
            .expect("initial reconcile");

        let fqdn = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V6,
                "unresolved.example.invalid".parse::<IpHost>().unwrap(),
                None,
            )],
            vec![],
        );
        runtime.reconcile(&fqdn).await.expect("fqdn reconcile");

        assert_eq!(mock.tunnel_remote_addr(10), Some(DISCARD_REMOTE_ADDR));
    }

    #[test]
    fn build_desired_maps_rejects_duplicate_session_interface_names() {
        let cfg = test_config(
            vec![(
                "tun0",
                10,
                10,
                IpVersion::V6,
                IpHost::V6Addr(Ipv6Addr::LOCALHOST),
                None,
            )],
            vec![
                ("sess0", "tun0", 100, 100, "l2tp0", None),
                ("sess1", "tun0", 101, 101, "l2tp0", None),
            ],
        );

        let result = build_desired_maps(&cfg);
        assert!(matches!(result, Err(Error::InvalidConfig(_))));
    }

    #[test]
    fn build_desired_maps_rejects_duplicate_tunnel_ids() {
        let cfg = test_config(
            vec![
                (
                    "a",
                    10,
                    10,
                    IpVersion::V6,
                    IpHost::V6Addr(Ipv6Addr::LOCALHOST),
                    None,
                ),
                (
                    "b",
                    10,
                    11,
                    IpVersion::V6,
                    IpHost::V6Addr(Ipv6Addr::LOCALHOST),
                    None,
                ),
            ],
            vec![],
        );
        assert!(matches!(
            build_desired_maps(&cfg),
            Err(Error::InvalidConfig(_))
        ));
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
                    bind_interface: Some(ifname("vrf0")),
                },
            ),
        ]);

        let plan = plan_tunnel_changes(&current, &desired);
        assert!(plan.to_update.contains(&1));
        assert!(plan.to_delete.contains(&2));
        assert!(plan.to_add.contains(&3));
    }

    #[test]
    fn plan_session_changes_detects_modify_recreate_add_delete_and_hwaddr() {
        let session = |id: u32, peer: u32, name: &str, hw: Option<&str>| DesiredSession {
            tunnel_id: 1,
            session_id: id,
            peer_session_id: peer,
            interface_name: ifname(name),
            interface_hwaddr: hw.map(hwaddr),
        };
        let current = BTreeMap::from([
            ((1, 10), session(10, 100, "l2tp0", None)),
            ((1, 11), session(11, 101, "l2tp1", None)),
            (
                (1, 13),
                session(13, 103, "l2tp4", Some("02:00:5e:00:53:01")),
            ),
        ]);

        let desired = BTreeMap::from([
            (
                (1, 10),
                session(10, 100, "l2tp2", Some("02:00:5e:00:53:02")),
            ),
            ((1, 11), session(11, 999, "l2tp1", None)),
            ((1, 12), session(12, 102, "l2tp3", None)),
            ((1, 13), session(13, 103, "l2tp4", None)),
        ]);

        let plan = plan_session_changes(&current, &desired);
        assert!(plan.to_modify.contains(&(1, 10)));
        assert!(plan.to_set_hwaddr.contains(&(1, 10)));
        assert!(plan.to_delete.contains(&(1, 11)));
        assert!(plan.to_add.contains(&(1, 11)));
        assert!(plan.to_add.contains(&(1, 12)));
        assert!(plan.to_set_hwaddr.contains(&(1, 13)));
        assert!(!plan.to_modify.contains(&(1, 13)));
    }

    #[test]
    fn temp_interface_names_are_valid_and_unique() {
        let mut used = BTreeSet::from([ifname("rsl2tp00000000")]);
        let mut counter = 0;
        let first = allocate_temp_interface_name(&mut used, &mut counter);
        let second = allocate_temp_interface_name(&mut used, &mut counter);
        assert_eq!(first, ifname("rsl2tp00000001"));
        assert_eq!(second, ifname("rsl2tp00000002"));
        assert_eq!(used.len(), 3);
    }
}
