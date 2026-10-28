//! Resolvers (V1–V15): lookups for tunnels with a host name, answer
//! selection and retention by the daemon itself (V5, V6), answers bound to
//! a host name, family and resolver incarnation (V7), and the runtime
//! device checks of V9 and V12 before a resolver starts.
//!
//! The lookups run behind [`Resolve`], on threads of their own (A9);
//! [`IphostResolve`] is the real one, over `iphost`.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::config::{
    Config, Dhcpv6Identity, Family, L2tpIfName, Method, RemoteAddr, ResolverConfig, TunnelConfig,
};
use crate::kernel::Kernel;

use super::{Reconciler, report};

/// The resolver host-defect and device retry (V9, V12, M14).
const DEVICE_RETRY: Duration = Duration::from_secs(30);
/// The refresh period after the previous lookup returned (V4).
const REFRESH: Duration = Duration::from_secs(30);

/// The DHCPv6 client identifier, with the device's address already read
/// (V12).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientId {
    /// A DUID-LL of this Ethernet address.
    DuidLl([u8; 6]),
    /// No Client Identifier (RFC 7844).
    None,
    /// A DUID-LL of a random address, new at every start.
    RandomDuidLl,
    /// An exact DUID.
    Raw(Vec<u8>),
}

/// A resolver whose devices the reconciler validated (V2, V9, V12).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolverSpec {
    /// The libc resolver (V3).
    System,
    /// Name servers by address, optionally bound to a link (V2, V9).
    Static {
        /// The servers, link-local ones with their scope.
        servers: Vec<SocketAddr>,
        /// The bind link.
        bind: Option<String>,
    },
    /// Router advertisements on a link (V10).
    Ra {
        /// The link.
        interface: String,
    },
    /// DHCPv6 Information-Request on a link (V12).
    Dhcpv6 {
        /// The link.
        interface: String,
        /// The client identifier.
        client_id: ClientId,
    },
    /// Both, DHCPv6 first (V14).
    Ipv6 {
        /// The link.
        interface: String,
        /// The client identifier.
        client_id: ClientId,
    },
}

/// One host name to look up now and thirty seconds after every lookup
/// returned (V4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    /// Identifies the results; a new one per incarnation (V7).
    pub id: u64,
    /// The host name.
    pub host: String,
    /// The resolver.
    pub resolver: ResolverSpec,
}

/// The lookups, run in the background (A9, V15).
pub trait Resolve: Send {
    /// Starts looking `lookup` up. An error is a host defect of the
    /// resolver (V12), retried thirty seconds later.
    fn watch(&mut self, lookup: Lookup) -> io::Result<()>;
    /// Stops a lookup; its late results are ignored by id anyway (V7).
    fn unwatch(&mut self, id: u64);
    /// The addresses returned since the last poll, per lookup id, in the
    /// resolver's order.
    fn poll(&mut self) -> Vec<(u64, Vec<IpAddr>)>;
}

/// The answers of one tunnel (V5–V7).
struct Watch {
    id: u64,
    /// What the answers belong to: host name, family, resolver name and
    /// its configuration (V7).
    key: (String, Family, Option<String>, Option<ResolverConfig>),
    /// The resolver as started, `None` while its devices do not allow it.
    started: Option<ResolverSpec>,
    selected: Option<IpAddr>,
    retry_at: Option<Instant>,
}

pub(crate) struct Resolvers {
    resolve: Box<dyn Resolve>,
    next_id: u64,
    watches: BTreeMap<u32, Watch>,
}

fn key(
    config: &Config,
    tunnel: &TunnelConfig,
) -> Option<(String, Family, Option<String>, Option<ResolverConfig>)> {
    let RemoteAddr::Host(host) = tunnel.remote_addr()? else {
        return None;
    };
    let name = tunnel.resolver_name().map(str::to_owned);
    let resolver = name.as_ref().map(|n| config.resolvers()[n].clone());
    Some((host.clone(), tunnel.family(), name, resolver))
}

impl Resolvers {
    pub fn new(resolve: Box<dyn Resolve>) -> Self {
        Resolvers {
            resolve,
            next_id: 1,
            watches: BTreeMap::new(),
        }
    }

    /// Discards the answers whose host name, family, resolver or resolver
    /// configuration changed (V7).
    pub fn reload(&mut self, _old: &Config, new: &Config) {
        let ids: Vec<u32> = self.watches.keys().copied().collect();
        for id in ids {
            let still = new
                .tunnels()
                .values()
                .find(|t| t.tunnel_id() == id)
                .and_then(|t| key(new, t));
            if still.as_ref() != Some(&self.watches[&id].key) {
                self.forget(id);
            }
        }
    }

    pub fn forget(&mut self, tunnel_id: u32) {
        if let Some(watch) = self.watches.remove(&tunnel_id) {
            self.resolve.unwatch(watch.id);
        }
    }

    pub fn selected(&self, tunnel_id: u32) -> Option<IpAddr> {
        self.watches.get(&tunnel_id)?.selected
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.watches.values().filter_map(|w| w.retry_at).min()
    }

    pub fn any(&self) -> bool {
        !self.watches.is_empty()
    }
}

/// V5: the previous address while the answer still holds it, else the
/// first usable one; `None` when nothing is usable.
pub(crate) fn select(
    previous: Option<IpAddr>,
    answer: &[IpAddr],
    family: Family,
    bound: bool,
) -> Option<IpAddr> {
    let usable = |a: &IpAddr| {
        let unicast =
            !a.is_unspecified() && !a.is_multicast() && *a != IpAddr::from([255, 255, 255, 255]);
        match a {
            IpAddr::V4(_) => family == Family::V4 && unicast,
            // A link-local answer has no zone: usable only on a bound
            // tunnel (T27, V5).
            IpAddr::V6(v6) => {
                family == Family::V6
                    && unicast
                    && v6.to_ipv4_mapped().is_none()
                    && (bound || !v6.is_unicast_link_local())
            }
        }
    };
    previous
        .filter(|p| answer.contains(p))
        .or_else(|| answer.iter().copied().find(usable))
}

impl<K: Kernel> Reconciler<K> {
    /// Starts the lookups of a tunnel with a host name, once its
    /// resolver's devices allow (V4, V9, V12).
    pub(super) fn ensure_lookup(&mut self, tunnel_id: u32) {
        let Some(record) = self.tunnels.get(&tunnel_id) else {
            return;
        };
        let Some(key) = key(&self.accepted, &record.config) else {
            return;
        };
        let label = report::tunnel(&record.name, tunnel_id);
        let now = self.k.now();
        let r = &mut self.resolvers;
        let next_id = &mut r.next_id;
        let watch = r.watches.entry(tunnel_id).or_insert_with(|| {
            *next_id += 1;
            Watch {
                id: *next_id,
                key: key.clone(),
                started: None,
                selected: None,
                retry_at: None,
            }
        });
        if watch.started.is_some() || watch.retry_at.is_some_and(|t| t > now) {
            return;
        }
        let (host, id) = (watch.key.0.clone(), watch.id);
        let spec = match &key.3 {
            None => Ok(ResolverSpec::System),
            Some(config) => self.resolver_spec(config),
        };
        let started = spec.and_then(|spec| {
            self.resolvers
                .resolve
                .watch(Lookup {
                    id,
                    host,
                    resolver: spec.clone(),
                })
                .map(|()| spec)
                .map_err(|e| report::describe(&e))
        });
        let watch = self.resolvers.watches.get_mut(&tunnel_id).unwrap();
        match started {
            Ok(spec) => {
                watch.started = Some(spec);
                watch.retry_at = None;
                self.report
                    .end(&label, "resolver", || "its resolver started".into());
            }
            Err(why) => {
                watch.retry_at = Some(now + DEVICE_RETRY);
                self.report.begin(&label, "resolver", || {
                    format!("its resolver waits: {why} (V9, V12)")
                });
            }
        }
    }

    /// The resolver as `iphost` gets it, its devices checked now (V9, V12).
    fn resolver_spec(&mut self, config: &ResolverConfig) -> Result<ResolverSpec, String> {
        let link = |k: &mut K, name: &L2tpIfName| -> Result<(u32, String), String> {
            let text = name
                .to_str()
                .map_err(|_| format!("the device name {} is not UTF-8", name.to_string_lossy()))?
                .to_owned();
            match k.link_by_name(name) {
                Ok(Some(l)) if l.vrf => Err(format!("{text} is a VRF, not a link")),
                Ok(Some(l)) => Ok((l.index, text)),
                Ok(None) => Err(format!("{text} does not exist")),
                Err(e) => Err(report::describe(&e)),
            }
        };
        let bind = match config.bind_interface() {
            Some(name) => Some(link(&mut self.k, name)?),
            None => None,
        };
        let Some(method) = config.method() else {
            let mut servers = Vec::new();
            for server in config.addresses() {
                let addr = match (server.addr(), server.zone()) {
                    (IpAddr::V6(v6), zone) if v6.is_unicast_link_local() => {
                        let scope = match (zone, &bind) {
                            (Some(zone), Some((index, _))) => {
                                let (z, _) = link(&mut self.k, zone)?;
                                if z != *index {
                                    return Err("a server's zone is not its bind link".into());
                                }
                                z
                            }
                            (Some(zone), None) => link(&mut self.k, zone)?.0,
                            (None, Some((index, _))) => *index,
                            (None, None) => return Err("a link-local server has no scope".into()),
                        };
                        SocketAddr::V6(SocketAddrV6::new(v6, server.port(), 0, scope))
                    }
                    (addr, _) => SocketAddr::new(addr, server.port()),
                };
                servers.push(addr);
            }
            return Ok(ResolverSpec::Static {
                servers,
                bind: bind.map(|(_, n)| n),
            });
        };
        let (index, interface) = bind.ok_or("a discovery resolver has no bind link")?;
        let client_id = match config.dhcpv6_identity() {
            Dhcpv6Identity::LinkLayer if method != Method::Ra => match self.k.ether_addr(index) {
                Ok(Some(mac)) => Some(ClientId::DuidLl(mac.octets())),
                _ => None,
            },
            Dhcpv6Identity::LinkLayer => Some(ClientId::None),
            Dhcpv6Identity::Anonymous => Some(ClientId::None),
            Dhcpv6Identity::Random => Some(ClientId::RandomDuidLl),
            Dhcpv6Identity::Duid(bytes) => Some(ClientId::Raw(bytes.clone())),
        };
        Ok(match (method, client_id) {
            (Method::Ra, _) => ResolverSpec::Ra { interface },
            (Method::Dhcpv6, Some(client_id)) => ResolverSpec::Dhcpv6 {
                interface,
                client_id,
            },
            (Method::Dhcpv6, None) => {
                return Err(format!("{interface} has no Ethernet address for a DUID-LL"));
            }
            (Method::Ipv6, Some(client_id)) => ResolverSpec::Ipv6 {
                interface,
                client_id,
            },
            // V12: without a DUID-LL the unified method uses RA only.
            (Method::Ipv6, None) => ResolverSpec::Ra { interface },
        })
    }

    /// Takes the answers that arrived (V4–V6) and reconnects the tunnels
    /// whose selected address changed (E10, T15).
    pub(super) fn poll_answers(&mut self) {
        for (id, answer) in self.resolvers.resolve.poll() {
            // A result of an earlier incarnation is ignored (V7, E10).
            let Some((&tunnel_id, watch)) =
                self.resolvers.watches.iter_mut().find(|(_, w)| w.id == id)
            else {
                continue;
            };
            let bound = self
                .tunnels
                .get(&tunnel_id)
                .is_some_and(|t| t.config.bind_interface().is_some());
            let label = self
                .tunnels
                .get(&tunnel_id)
                .map_or(String::new(), |t| report::tunnel(&t.name, tunnel_id));
            let family = watch.key.1;
            // A negative or failed answer keeps the one in force (V6).
            let Some(selected) = select(watch.selected, &answer, family, bound) else {
                if !answer.is_empty() {
                    log::warn!("{label}: the answer holds no usable address of {family}");
                }
                continue;
            };
            if watch.selected != Some(selected) {
                watch.selected = Some(selected);
                log::info!("{label}: {} resolves to {selected}", watch.key.0);
                if self.tunnels.contains_key(&tunnel_id) {
                    self.converge_tunnel(tunnel_id);
                }
            }
        }
    }

    /// A device a resolver depends on appeared, disappeared or changed:
    /// restart its lookups after validating it again (V9, V13, E1, E3).
    pub(super) fn resolver_device_changed(&mut self, name: &L2tpIfName) {
        let affected: Vec<u32> = self
            .resolvers
            .watches
            .iter()
            .filter(|(_, w)| {
                w.key.3.as_ref().is_some_and(|r| {
                    r.bind_interface() == Some(name)
                        || r.addresses().iter().any(|s| s.zone() == Some(name))
                })
            })
            .map(|(id, _)| *id)
            .collect();
        for tunnel_id in affected {
            let watch = self.resolvers.watches.get_mut(&tunnel_id).unwrap();
            // Answers in force are kept; only the lookups restart.
            if watch.started.take().is_some() {
                self.resolvers.resolve.unwatch(watch.id);
                self.resolvers.next_id += 1;
                watch.id = self.resolvers.next_id;
            }
            watch.retry_at = None;
            self.ensure_lookup(tunnel_id);
        }
    }

    /// The thirty-second device retries that are due (V9, V12).
    pub(super) fn retry_resolvers(&mut self) {
        let now = self.k.now();
        let due: Vec<u32> = self
            .resolvers
            .watches
            .iter()
            .filter(|(_, w)| w.retry_at.is_some_and(|t| t <= now))
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            self.resolvers.watches.get_mut(&id).unwrap().retry_at = None;
            self.ensure_lookup(id);
        }
    }
}

/// A lookup's id and the addresses it returned.
type Answer = (u64, Vec<IpAddr>);

/// [`Resolve`] over `iphost`: one refresh thread per lookup, a lookup now
/// and thirty seconds after each one returned (V4, V15).
pub struct IphostResolve {
    results: (mpsc::Sender<Answer>, mpsc::Receiver<Answer>),
    stops: BTreeMap<u64, mpsc::Sender<()>>,
    // Discovery resolvers own sockets and threads: one per spec, shared
    // by the host names that use it (V15).
    shared: Vec<(ResolverSpec, iphost::Resolver)>,
}

impl Default for IphostResolve {
    fn default() -> Self {
        IphostResolve {
            results: mpsc::channel(),
            stops: BTreeMap::new(),
            shared: Vec::new(),
        }
    }
}

impl IphostResolve {
    fn resolver(&mut self, spec: &ResolverSpec) -> io::Result<iphost::Resolver> {
        if let Some((_, r)) = self.shared.iter().find(|(s, _)| s == spec) {
            return Ok(r.clone());
        }
        let client = |id: &ClientId| match id {
            ClientId::DuidLl(mac) => iphost::ClientId::DuidLl(*mac),
            ClientId::None => iphost::ClientId::None,
            ClientId::RandomDuidLl => iphost::ClientId::RandomDuidLl,
            ClientId::Raw(bytes) => iphost::ClientId::Raw(bytes.clone()),
        };
        let resolver = match spec {
            ResolverSpec::System => iphost::Resolver::System,
            ResolverSpec::Static { servers, bind } => {
                let mut config = iphost::StaticResolverConfig::new(servers.iter().copied());
                if let Some(bind) = bind {
                    config = config.with_bind_device(iphost::BindDevice::Interface(bind.clone()));
                }
                iphost::Resolver::Static(config)
            }
            ResolverSpec::Ra { interface } => {
                iphost::Resolver::Ra(iphost::RaResolverConfig::new(interface.clone())?)
            }
            ResolverSpec::Dhcpv6 {
                interface,
                client_id,
            } => iphost::Resolver::Dhcpv6(iphost::Dhcpv6ResolverConfig::new(
                interface.clone(),
                client(client_id),
            )?),
            ResolverSpec::Ipv6 {
                interface,
                client_id,
            } => iphost::Resolver::Ipv6(iphost::Ipv6ResolverConfig::new(
                interface.clone(),
                client(client_id),
            )?),
        };
        self.shared.push((spec.clone(), resolver.clone()));
        Ok(resolver)
    }
}

impl Resolve for IphostResolve {
    fn watch(&mut self, lookup: Lookup) -> io::Result<()> {
        let host: iphost::IpHost = lookup
            .host
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a host name"))?;
        let resolver = self.resolver(&lookup.resolver)?;
        let (stop, stopped) = mpsc::channel();
        let results = self.results.0.clone();
        let id = lookup.id;
        std::thread::Builder::new()
            .name("rs-l2tpd-lookup".into())
            .spawn(move || {
                let lookups = iphost::IpHostResolver::new_with_config(host, false, false)
                    .with_resolver(resolver);
                loop {
                    if results.send((id, lookups.resolve())).is_err() {
                        return;
                    }
                    match stopped.recv_timeout(REFRESH) {
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        _ => return,
                    }
                }
            })?;
        self.stops.insert(id, stop);
        Ok(())
    }

    // shortcut: a discovery resolver, once created, stays until the
    // process ends; drop unused ones when frequent resolver reloads matter.
    fn unwatch(&mut self, id: u64) {
        // Dropping the sender stops the refresh thread.
        self.stops.remove(&id);
    }

    fn poll(&mut self) -> Vec<(u64, Vec<IpAddr>)> {
        self.results.1.try_iter().collect()
    }
}
