pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod state;

use async_trait::async_trait;
use clap::{ArgAction, Parser};
use config::*;
use error::*;
use iphost::{AutoIpHostResolver, IpHost, IpHostResolver};
use log::{debug, error, info, warn};
use tokio::sync::mpsc;
use tokio::sync::RwLock;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use std::time::Duration;

/// This is the path to the main configuration file.
pub(crate) const CONFIG_FILE_PATH: &str = env!("CONFIG_FILE_PATH");

/// This is where configuration overrides (filenames ending in .toml) live.
pub(crate) const CONFIG_DIR_PATH: &str = env!("CONFIG_DIR_PATH");

const DNS_REFRESH_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Parser)]
#[command(version, disable_help_flag = false, disable_version_flag = false)]
struct Args {
    /// Increase log verbosity.
    #[arg(short, long, action = ArgAction::SetTrue)]
    verbose: bool,

    /// Validate and print the merged configuration, then exit.
    #[arg(short = 'c', long, action = ArgAction::SetTrue)]
    check: bool,
}

#[derive(Debug)]
enum ControlEvent {
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

type TunnelId = u32;
type SessionId = u32;
type SessionKey = (TunnelId, SessionId);
type DesiredTunnelMap = BTreeMap<TunnelId, DesiredTunnel>;
type DesiredSessionMap = BTreeMap<SessionKey, DesiredSession>;
const MAX_INTERFACE_NAME_LEN: usize = 15;

#[async_trait]
trait StateOps: Send + Sync {
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
}

impl ResolverRuntime {
    fn new(
        tunnel_id: u32,
        desired: &DesiredTunnel,
        control_tx: mpsc::UnboundedSender<ControlEvent>,
    ) -> Self {
        let resolver = AutoIpHostResolver::new(
            desired.remote_addr.clone(),
            Duration::from_secs(DNS_REFRESH_INTERVAL_SECS),
        );
        let ip_version = Arc::new(StdRwLock::new(desired.ip_version));
        let active = Arc::new(AtomicBool::new(true));

        let watcher_resolver = resolver.clone();
        let subscriber = watcher_resolver.subscribe_changes();
        let watcher_active = Arc::clone(&active);
        std::thread::spawn(move || loop {
            let change = subscriber.wait_for_change_blocking();
            if change.is_none() {
                break;
            }
            if !watcher_active.load(Ordering::Relaxed) {
                continue;
            }
            if control_tx
                .send(ControlEvent::DnsChanged { tunnel_id })
                .is_err()
            {
                break;
            }
        });

        Self {
            resolver,
            ip_version,
            active,
        }
    }

    fn apply_tunnel_config(&self, desired: &DesiredTunnel) {
        if let Ok(mut version) = self.ip_version.write() {
            *version = desired.ip_version;
        }
        self.active.store(true, Ordering::Relaxed);

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
    }

    fn deactivate(&self) {
        self.active.store(false, Ordering::Relaxed);
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    fn current_remote_addr(&self) -> Option<IpAddr> {
        let ip_version = self.ip_version.read().ok().map(|v| *v)?;
        match ip_version {
            IpVersion::V4 => self.resolver.ipv4_addr().map(IpAddr::V4),
            IpVersion::V6 => self.resolver.ipv6_addr().map(IpAddr::V6),
        }
    }
}

struct Runtime {
    state: Arc<dyn StateOps>,
    tunnel_specs: DesiredTunnelMap,
    session_specs: DesiredSessionMap,
    resolvers: BTreeMap<TunnelId, ResolverRuntime>,
    control_tx: mpsc::UnboundedSender<ControlEvent>,
}

impl Runtime {
    fn new(state: Arc<dyn StateOps>, control_tx: mpsc::UnboundedSender<ControlEvent>) -> Self {
        Self {
            state,
            tunnel_specs: BTreeMap::new(),
            session_specs: BTreeMap::new(),
            resolvers: BTreeMap::new(),
            control_tx,
        }
    }

    async fn reconcile(&mut self, config: &Config) -> Result<()> {
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
        macro_rules! try_apply_value {
            ($result:expr) => {
                match $result {
                    Ok(value) => value,
                    Err(e) => {
                        self.tunnel_specs = applied_tunnel_specs;
                        self.session_specs = applied_session_specs;
                        return Err(e);
                    }
                }
            };
        }

        let current_tunnel_ids: BTreeSet<u32> = self.tunnel_specs.keys().copied().collect();
        let desired_tunnel_ids: BTreeSet<u32> = desired_tunnels.keys().copied().collect();

        let mut tunnels_to_delete: BTreeSet<u32> = current_tunnel_ids
            .difference(&desired_tunnel_ids)
            .copied()
            .collect();
        let mut tunnels_to_add: BTreeSet<u32> = desired_tunnel_ids
            .difference(&current_tunnel_ids)
            .copied()
            .collect();

        for tunnel_id in current_tunnel_ids.intersection(&desired_tunnel_ids) {
            let current = self
                .tunnel_specs
                .get(tunnel_id)
                .expect("tunnel exists in current set");
            let desired = desired_tunnels
                .get(tunnel_id)
                .expect("tunnel exists in desired set");

            let requires_recreate = current.peer_tunnel_id != desired.peer_tunnel_id
                || current.bind_interface != desired.bind_interface;
            if requires_recreate {
                tunnels_to_delete.insert(*tunnel_id);
                tunnels_to_add.insert(*tunnel_id);
            }
        }

        for tunnel_id in &tunnels_to_delete {
            if let Some(resolver_runtime) = self.resolvers.get(tunnel_id) {
                resolver_runtime.deactivate();
            }
        }

        for tunnel_id in &tunnels_to_delete {
            if self.state.has_tunnel(*tunnel_id).await {
                info!("deleting tunnel_id={}", tunnel_id);
                try_apply!(self.state.delete_tunnel(*tunnel_id).await);
            }
            self.resolvers.remove(tunnel_id);
            applied_tunnel_specs.remove(tunnel_id);
            applied_session_specs.retain(|(tid, _), _| tid != tunnel_id);
        }

        for tunnel_id in &tunnels_to_add {
            let desired = desired_tunnels
                .get(tunnel_id)
                .expect("tunnel exists in desired map");

            if !self.resolvers.contains_key(tunnel_id) {
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
                try_apply_value!(resolve_ip_host_once(&desired.remote_addr, desired.ip_version))
            };

            info!(
                "adding tunnel_id={} peer_tunnel_id={} remote_addr={}",
                desired.tunnel_id, desired.peer_tunnel_id, remote_addr
            );
            try_apply!(
                self.state
                    .add_tunnel(
                        desired.tunnel_id,
                        desired.peer_tunnel_id,
                        remote_addr,
                        desired.bind_interface.as_deref(),
                    )
                    .await
            );
            applied_tunnel_specs.insert(*tunnel_id, desired.clone());
        }

        for tunnel_id in current_tunnel_ids.intersection(&desired_tunnel_ids) {
            if tunnels_to_delete.contains(tunnel_id) || tunnels_to_add.contains(tunnel_id) {
                continue;
            }

            let current = self
                .tunnel_specs
                .get(tunnel_id)
                .expect("tunnel exists in current map");
            let desired = desired_tunnels
                .get(tunnel_id)
                .expect("tunnel exists in desired map");

            let mutable_changed = current.remote_addr != desired.remote_addr
                || current.ip_version != desired.ip_version;
            if !mutable_changed {
                if let Some(resolver_runtime) = self.resolvers.get(tunnel_id) {
                    resolver_runtime.apply_tunnel_config(desired);
                }
                continue;
            }

            if !self.resolvers.contains_key(tunnel_id) {
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
                try_apply_value!(resolve_ip_host_once(&desired.remote_addr, desired.ip_version))
            };

            info!(
                "updating tunnel_id={} remote_addr={}",
                desired.tunnel_id, remote_addr
            );
            try_apply!(
                self.state
                    .modify_tunnel(desired.tunnel_id, remote_addr)
                    .await
            );
            applied_tunnel_specs.insert(*tunnel_id, desired.clone());
        }

        let effective_current_sessions = applied_session_specs.clone();

        let mut sessions_to_delete = BTreeSet::new();
        let mut sessions_to_add = BTreeSet::new();
        let mut sessions_to_modify = Vec::new();

        for (key, current) in &effective_current_sessions {
            let Some(desired) = desired_sessions.get(key) else {
                sessions_to_delete.insert(*key);
                continue;
            };

            if current.peer_session_id != desired.peer_session_id {
                sessions_to_delete.insert(*key);
                sessions_to_add.insert(*key);
                continue;
            }

            if current.interface_name != desired.interface_name {
                sessions_to_modify.push(*key);
            }
        }

        for key in desired_sessions.keys() {
            if !effective_current_sessions.contains_key(key) {
                sessions_to_add.insert(*key);
            }
        }

        let mut reserved_interface_names: BTreeSet<String> = effective_current_sessions
            .values()
            .map(|s| s.interface_name.clone())
            .collect();
        reserved_interface_names
            .extend(desired_sessions.values().map(|s| s.interface_name.clone()));
        let mut temp_interface_counter: u32 = 0;

        for (tunnel_id, session_id) in &sessions_to_modify {
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
                applied.interface_name = temp_ifname.clone();
            }
        }

        for (tunnel_id, session_id) in sessions_to_modify {
            let desired = desired_sessions
                .get(&(tunnel_id, session_id))
                .expect("session exists in desired map");
            info!(
                "renaming session interface tunnel_id={} session_id={} to {}",
                tunnel_id, session_id, desired.interface_name
            );
            try_apply!(
                self.state
                    .modify_session(tunnel_id, session_id, &desired.interface_name)
                    .await
            );
            applied_session_specs.insert((tunnel_id, session_id), desired.clone());
        }

        for (tunnel_id, session_id) in sessions_to_delete {
            if self.state.has_session(tunnel_id, session_id).await {
                info!(
                    "deleting session tunnel_id={} session_id={}",
                    tunnel_id, session_id
                );
                try_apply!(self.state.delete_session(tunnel_id, session_id).await);
            }
            applied_session_specs.remove(&(tunnel_id, session_id));
        }

        for (tunnel_id, session_id) in sessions_to_add {
            let desired = desired_sessions
                .get(&(tunnel_id, session_id))
                .expect("session exists in desired map");
            info!(
                "adding session tunnel_id={} session_id={} interface_name={}",
                tunnel_id, session_id, desired.interface_name
            );
            try_apply!(
                self.state
                    .add_session(
                        tunnel_id,
                        session_id,
                        desired.peer_session_id,
                        &desired.interface_name,
                    )
                    .await
            );
            applied_session_specs.insert((tunnel_id, session_id), desired.clone());
        }

        self.tunnel_specs = desired_tunnels;
        self.session_specs = desired_sessions;
        Ok(())
    }

    async fn handle_dns_change(&self, tunnel_id: u32) {
        if !self.tunnel_specs.contains_key(&tunnel_id) {
            return;
        }

        let Some(resolver_runtime) = self.resolvers.get(&tunnel_id) else {
            return;
        };

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

    async fn shutdown(&mut self) -> Result<()> {
        self.reconcile(&Config::default()).await
    }
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

fn list_toml_files_at(file: &Path, dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if file.is_file() {
        files.push(file.to_path_buf());
    }

    match fs::read_dir(dir) {
        Ok(entries) => {
            files.extend(
                entries
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| {
                        p.is_file()
                            && p.extension()
                                .and_then(|s| s.to_str())
                                .map(|ext| ext.eq_ignore_ascii_case("toml"))
                                .unwrap_or(false)
                    }),
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // directory does not exist -> not an error
        }

        Err(e) => return Err(Error::Other(e.to_string())),
    }

    files.sort(); // lexicographic order (important for drop-ins)
    Ok(files)
}

fn list_toml_files() -> Result<Vec<PathBuf>> {
    let file = Path::new(CONFIG_FILE_PATH);
    let dir = Path::new(CONFIG_DIR_PATH);
    list_toml_files_at(file, dir)
}

fn load_config_blocking() -> Result<Config> {
    let mut partial = PartialConfig::default();

    let config_paths = list_toml_files()?;
    for path in &config_paths {
        let other = PartialConfig::from_path(path)?;
        partial.merge(other);
    }

    let config = Config::from_partial(partial)?;

    Ok(config)
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

#[cfg(unix)]
fn install_signal_handlers(control_tx: mpsc::UnboundedSender<ControlEvent>) -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut hup = signal(SignalKind::hangup())
        .map_err(|e| Error::Other(format!("failed to install SIGHUP handler: {e}")))?;
    let hup_tx = control_tx.clone();
    tokio::spawn(async move {
        loop {
            if hup.recv().await.is_none() {
                break;
            }
            if hup_tx.send(ControlEvent::ReloadRequested).is_err() {
                break;
            }
        }
    });

    let mut term = signal(SignalKind::terminate())
        .map_err(|e| Error::Other(format!("failed to install SIGTERM handler: {e}")))?;
    let mut int = signal(SignalKind::interrupt())
        .map_err(|e| Error::Other(format!("failed to install SIGINT handler: {e}")))?;
    tokio::spawn(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        let _ = control_tx.send(ControlEvent::ShutdownRequested);
    });

    Ok(())
}

#[cfg(not(unix))]
fn install_signal_handlers(_control_tx: mpsc::UnboundedSender<ControlEvent>) -> Result<()> {
    Err(Error::Other(
        "this daemon requires unix signal support".to_string(),
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let level = if args.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::new()
        .filter_level(level)
        .try_init()
        .map_err(|e| Error::Other(e.to_string()))?;

    let initial_config = load_config_blocking()?;
    if args.check {
        let rendered = toml::to_string_pretty(&initial_config)
            .map_err(|e| Error::Other(format!("failed to render config as TOML: {e}")))?;
        println!("{rendered}");
        return Ok(());
    }
    let config = Arc::new(RwLock::new(initial_config.clone()));

    let state: Arc<dyn StateOps> = Arc::new(state::State::new().await?);
    let (control_tx, mut control_rx) = mpsc::unbounded_channel();

    install_signal_handlers(control_tx.clone())?;

    let mut runtime = Runtime::new(Arc::clone(&state), control_tx.clone());
    runtime.reconcile(&initial_config).await?;
    info!("initial configuration applied");

    loop {
        let Some(event) = control_rx.recv().await else {
            warn!("control channel closed");
            break;
        };

        match event {
            ControlEvent::ReloadRequested => {
                info!("received SIGHUP: reloading configuration");
                let loaded = tokio::task::spawn_blocking(load_config_blocking).await;
                let new_config = match loaded {
                    Ok(Ok(config)) => config,
                    Ok(Err(e)) => {
                        warn!("failed to load configuration: {}", e);
                        continue;
                    }
                    Err(e) => {
                        warn!("config loader task failed: {}", e);
                        continue;
                    }
                };

                match runtime.reconcile(&new_config).await {
                    Ok(()) => {
                        *config.write().await = new_config;
                        info!("configuration reload completed");
                    }
                    Err(e) => {
                        warn!("failed to apply reloaded configuration: {}", e);
                    }
                }
            }

            ControlEvent::ShutdownRequested => {
                info!("shutdown requested");
                if let Err(e) = runtime.shutdown().await {
                    error!("shutdown cleanup failed: {}", e);
                }
                break;
            }

            ControlEvent::DnsChanged { tunnel_id } => {
                runtime.handle_dns_change(tunnel_id).await;
            }
        }
    }

    if let Err(e) = runtime.shutdown().await {
        warn!("final cleanup failed: {}", e);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        fail_add_session_for: Option<(u32, u32)>,
    }

    #[derive(Default)]
    struct MockState {
        inner: Mutex<MockStateInner>,
    }

    impl MockState {
        fn inject_add_session_failure(&self, key: (u32, u32)) {
            self.inner.lock().unwrap().fail_add_session_for = Some(key);
        }

        fn session_name(&self, tunnel_id: u32, session_id: u32) -> Option<String> {
            self.inner
                .lock()
                .unwrap()
                .sessions
                .get(&(tunnel_id, session_id))
                .map(|s| s.interface_name.clone())
        }
    }

    #[async_trait]
    impl StateOps for MockState {
        async fn has_tunnel(&self, tunnel_id: u32) -> bool {
            self.inner.lock().unwrap().tunnels.contains_key(&tunnel_id)
        }

        async fn add_tunnel(
            &self,
            tunnel_id: u32,
            _peer_tunnel_id: u32,
            remote_addr: IpAddr,
            _if_name: Option<&str>,
        ) -> Result<()> {
            let mut inner = self.inner.lock().unwrap();
            if inner.tunnels.contains_key(&tunnel_id) {
                return Err(Error::Other("Duplicate tunnel_id".to_string()));
            }
            inner.tunnels.insert(tunnel_id, MockTunnel { remote_addr });
            Ok(())
        }

        async fn modify_tunnel(&self, tunnel_id: u32, remote_addr: IpAddr) -> Result<()> {
            let mut inner = self.inner.lock().unwrap();
            let tunnel = inner
                .tunnels
                .get_mut(&tunnel_id)
                .ok_or_else(|| Error::Other("tunnel not found".to_string()))?;
            tunnel.remote_addr = remote_addr;
            Ok(())
        }

        async fn delete_tunnel(&self, tunnel_id: u32) -> Result<()> {
            let mut inner = self.inner.lock().unwrap();
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
                .unwrap()
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
            let mut inner = self.inner.lock().unwrap();
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
            let mut inner = self.inner.lock().unwrap();
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
            let mut inner = self.inner.lock().unwrap();
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
                TunnelConfig {
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
                SessionConfig {
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
        let (control_tx, _control_rx) = mpsc::unbounded_channel();
        let state: Arc<dyn StateOps> = mock;
        Runtime::new(state, control_tx)
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock monotonic")
            .as_nanos();
        path.push(format!(
            "rs-l2tpd-tests-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn list_toml_files_at_keeps_main_when_dropin_dir_missing() {
        let temp_dir = unique_temp_dir("config-main");
        let main_file = temp_dir.join("rs-l2tpd.toml");
        let dropin_dir = temp_dir.join("rs-l2tpd.toml.d");

        fs::write(&main_file, b"[tunnels]\n").expect("write main config");
        let files = list_toml_files_at(&main_file, &dropin_dir).expect("list files");

        assert_eq!(files, vec![main_file.clone()]);
        fs::remove_dir_all(temp_dir).expect("cleanup temp dir");
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
}
