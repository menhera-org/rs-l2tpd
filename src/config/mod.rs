//! Configuration types: always-valid `Config` and its entries, the kernel
//! identities entries are matched by, and the conversions from merged
//! documents (spec C1–C17, L4).
//!
//! A [`Config`] is built in code with the entry builders and the `insert_*`
//! methods, which validate, or converted from a [`PartialConfig`], the
//! merged but unvalidated form of the configuration documents.

mod partial;
#[cfg(feature = "serde")]
mod serde;
#[cfg(test)]
mod tests;
mod text;

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

pub use l2tp::L2tpIfName;
pub use partial::{Effect, EntryKind, PartialConfig, Problem, ProblemKind};

use crate::{Error, Result};

/// A rule an entry breaks: the field at fault, the message, and whether
/// the mistake is hard (the entry is left out) or tolerated (C10).
#[derive(Debug)]
pub(crate) struct Mistake {
    field: Option<&'static str>,
    message: String,
    hard: bool,
}

impl Mistake {
    fn hard(field: &'static str, message: impl Into<String>) -> Self {
        Mistake {
            field: Some(field),
            message: message.into(),
            hard: true,
        }
    }

    fn tolerated(field: &'static str, message: impl Into<String>) -> Self {
        Mistake {
            hard: false,
            ..Mistake::hard(field, message)
        }
    }

    fn into_error(self) -> Error {
        match self.field {
            Some(field) => Error::InvalidConfig(format!("{field}: {}", self.message)),
            None => Error::InvalidConfig(self.message),
        }
    }
}

/// The address family of a tunnel's peer (`ip_version`, C7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl Family {
    fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Family::V4 => "V4",
            Family::V6 => "V6",
        })
    }
}

/// A unicast Ethernet address, not all zero (`interface_hwaddr`, C8).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HwAddr([u8; 6]);

impl HwAddr {
    /// Validates the six octets: unicast and not all zero.
    pub fn new(octets: [u8; 6]) -> Result<Self> {
        if octets[0] & 1 != 0 || octets == [0; 6] {
            return Err(Error::InvalidConfig(format!(
                "{} is not a unicast hardware address",
                HwAddr(octets)
            )));
        }
        Ok(HwAddr(octets))
    }

    /// The six octets.
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for HwAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl fmt::Debug for HwAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HwAddr({self})")
    }
}

/// A session cookie of 4 or 8 bytes (C8). It has no `Display`, and its
/// `Debug` gives the length only, so that it is never logged (O5).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cookie(l2tp::Cookie);

impl Cookie {
    /// Validates the length: 4 or 8 bytes (RFC 3931).
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if let Ok(short) = <[u8; 4]>::try_from(bytes) {
            return Ok(Cookie(short.into()));
        }
        <[u8; 8]>::try_from(bytes)
            .map(|long| Cookie(long.into()))
            .map_err(|_| {
                Error::InvalidConfig(format!("a cookie is 4 or 8 bytes, not {}", bytes.len()))
            })
    }

    /// The cookie's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cookie({} bytes)", self.0.len())
    }
}

/// A tunnel's `remote_addr` (C7).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoteAddr {
    /// A literal; an IPv4-mapped IPv6 address is held as IPv4. A zone is
    /// valid only for a link-local IPv6 address.
    Ip {
        /// The address.
        addr: IpAddr,
        /// The interface after `%`.
        zone: Option<L2tpIfName>,
    },
    /// A host name, without a trailing dot.
    Host(String),
}

impl RemoteAddr {
    fn normalized(self) -> Self {
        match self {
            RemoteAddr::Ip { addr, zone } => RemoteAddr::Ip {
                addr: addr.to_canonical(),
                zone,
            },
            RemoteAddr::Host(name) => match text::host_name(&name) {
                Some(stripped) => RemoteAddr::Host(stripped.to_owned()),
                None => RemoteAddr::Host(name),
            },
        }
    }
}

impl fmt::Display for RemoteAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemoteAddr::Ip { addr, zone: None } => addr.fmt(f),
            RemoteAddr::Ip {
                addr,
                zone: Some(zone),
            } => write!(f, "{addr}%{}", zone.to_string_lossy()),
            RemoteAddr::Host(name) => f.write_str(name),
        }
    }
}

/// The kernel identity of a tunnel: the fields the kernel cannot change
/// (C14, T23).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TunnelIdentity {
    tunnel_id: u32,
    peer_tunnel_id: u32,
}

/// The kernel identity of a session: its tunnel's identity, its
/// identifiers and its cookies, an absent `peer_cookie` as its default
/// (C14, S17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionIdentity {
    tunnel: TunnelIdentity,
    session_id: u32,
    peer_session_id: u32,
    cookie: Option<Cookie>,
    peer_cookie: Option<Cookie>,
}

impl TunnelIdentity {
    /// The identity of a kernel tunnel, as an adopted one reports it (S28).
    pub(crate) fn new(tunnel_id: u32, peer_tunnel_id: u32) -> Self {
        TunnelIdentity {
            tunnel_id,
            peer_tunnel_id,
        }
    }

    /// The tunnel identifier.
    pub fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }
}

impl SessionIdentity {
    /// The identity of a kernel session in `tunnel`, `peer_cookie` as the
    /// kernel holds it (S28).
    pub(crate) fn new(
        tunnel: TunnelIdentity,
        session_id: u32,
        peer_session_id: u32,
        cookie: Option<Cookie>,
        peer_cookie: Option<Cookie>,
    ) -> Self {
        SessionIdentity {
            tunnel,
            session_id,
            peer_session_id,
            cookie,
            peer_cookie,
        }
    }

    /// The tunnel's identity.
    pub fn tunnel(&self) -> TunnelIdentity {
        self.tunnel
    }

    /// The session identifier.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }
}

/// A tunnel entry (C7). Built with [`TunnelConfig::builder`].
///
/// A tunnel without a peer (`remote_addr` absent) is valid: it is what an
/// unusable endpoint becomes (C10), and it is created disconnected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelConfig {
    tunnel_id: u32,
    peer_tunnel_id: Option<u32>,
    remote_addr: Option<RemoteAddr>,
    // Always set when `remote_addr` is not a literal.
    ip_version: Option<Family>,
    bind_interface: Option<L2tpIfName>,
    resolver_name: Option<String>,
}

/// Builder of a [`TunnelConfig`]; [`build`](Self::build) validates.
#[derive(Clone, Debug)]
pub struct TunnelConfigBuilder(TunnelConfig);

impl TunnelConfig {
    /// Starts a tunnel with `tunnel_id`.
    pub fn builder(tunnel_id: u32) -> TunnelConfigBuilder {
        TunnelConfigBuilder(TunnelConfig {
            tunnel_id,
            peer_tunnel_id: None,
            remote_addr: None,
            ip_version: None,
            bind_interface: None,
            resolver_name: None,
        })
    }

    /// The local tunnel identifier.
    pub fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }

    /// The peer's tunnel identifier, `tunnel_id` unless configured.
    pub fn peer_tunnel_id(&self) -> u32 {
        self.peer_tunnel_id.unwrap_or(self.tunnel_id)
    }

    /// The peer; `None` for a tunnel without one.
    pub fn remote_addr(&self) -> Option<&RemoteAddr> {
        self.remote_addr.as_ref()
    }

    /// The peer's family: `ip_version`, or the literal's family.
    pub fn family(&self) -> Family {
        // One of the two is always set; IPv6 is the C10 default.
        self.ip_version
            .or(self.literal_family())
            .unwrap_or(Family::V6)
    }

    /// The device or VRF the socket is bound to.
    pub fn bind_interface(&self) -> Option<&L2tpIfName> {
        self.bind_interface.as_ref()
    }

    /// The resolver of a host name; `None` for the system resolver.
    pub fn resolver_name(&self) -> Option<&str> {
        self.resolver_name.as_deref()
    }

    /// The kernel identity (C14).
    pub fn identity(&self) -> TunnelIdentity {
        TunnelIdentity {
            tunnel_id: self.tunnel_id,
            peer_tunnel_id: self.peer_tunnel_id(),
        }
    }

    fn literal_family(&self) -> Option<Family> {
        match &self.remote_addr {
            Some(RemoteAddr::Ip { addr, .. }) => Some(Family::of(*addr)),
            _ => None,
        }
    }

    /// Drops the peer, keeping the family C10 names.
    fn make_peerless(&mut self, hint: Option<Family>) {
        let family = self.ip_version.or(hint).unwrap_or(self.family());
        self.remote_addr = None;
        self.ip_version = Some(family);
    }

    /// The rules of C7 that need no other entry, in field order.
    fn check(&self) -> std::result::Result<(), Mistake> {
        check_id(self.tunnel_id, "tunnel_id")?;
        check_id(self.peer_tunnel_id.unwrap_or(1), "peer_tunnel_id")?;
        if let Some(name) = &self.bind_interface {
            text::ifname(name.as_bytes()).map_err(|e| Mistake::hard("bind_interface", e))?;
        }
        match &self.remote_addr {
            None if self.ip_version.is_none() => {
                return Err(Mistake::hard(
                    "ip_version",
                    "required for a tunnel without a peer",
                ));
            }
            None => {}
            Some(RemoteAddr::Host(name)) => {
                if text::host_name(name) != Some(name.as_str()) {
                    return Err(Mistake::tolerated(
                        "remote_addr",
                        format!("{name:?} is not a host name"),
                    ));
                }
                if self.ip_version.is_none() {
                    return Err(Mistake::tolerated("ip_version", "required for a host name"));
                }
            }
            Some(RemoteAddr::Ip { addr, zone }) => {
                text::unicast(*addr).map_err(|e| Mistake::tolerated("remote_addr", e))?;
                if let Some(family) = self.ip_version
                    && family != Family::of(*addr)
                {
                    return Err(Mistake::tolerated(
                        "ip_version",
                        format!("{family} does not match {addr}"),
                    ));
                }
                match zone {
                    Some(zone) => text::zone(*addr, zone.as_bytes())
                        .map(drop)
                        .map_err(|e| Mistake::tolerated("remote_addr", e))?,
                    None if text::link_local(*addr) && self.bind_interface.is_none() => {
                        // spec: T27, R47
                        return Err(Mistake::hard(
                            "remote_addr",
                            format!("{addr} is link-local: it needs a zone or bind_interface"),
                        ));
                    }
                    None => {}
                }
            }
        }
        if let Some(resolver) = &self.resolver_name
            && !matches!(self.remote_addr, Some(RemoteAddr::Host(_)))
        {
            return Err(Mistake::tolerated(
                "resolver_name",
                format!("{resolver:?} is used only with a host name"),
            ));
        }
        Ok(())
    }
}

impl TunnelConfigBuilder {
    /// The peer's tunnel identifier.
    pub fn peer_tunnel_id(mut self, id: u32) -> Self {
        self.0.peer_tunnel_id = Some(id);
        self
    }

    /// The peer.
    pub fn remote_addr(mut self, addr: RemoteAddr) -> Self {
        self.0.remote_addr = Some(addr);
        self
    }

    /// The peer's family; required for a host name and without a peer.
    pub fn ip_version(mut self, family: Family) -> Self {
        self.0.ip_version = Some(family);
        self
    }

    /// The device or VRF to bind the socket to.
    pub fn bind_interface(mut self, name: L2tpIfName) -> Self {
        self.0.bind_interface = Some(name);
        self
    }

    /// The resolver of a host name.
    pub fn resolver_name(mut self, name: impl Into<String>) -> Self {
        self.0.resolver_name = Some(name.into());
        self
    }

    /// Validates the entry by C7; every mistake is an error here.
    pub fn build(self) -> Result<TunnelConfig> {
        let mut tunnel = self.0;
        tunnel.remote_addr = tunnel.remote_addr.map(RemoteAddr::normalized);
        tunnel.check().map_err(Mistake::into_error)?;
        Ok(tunnel)
    }
}

/// A session entry (C8). Built with [`SessionConfig::builder`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionConfig {
    tunnel_name: String,
    session_id: u32,
    peer_session_id: Option<u32>,
    interface_name: L2tpIfName,
    interface_hwaddr: Option<HwAddr>,
    cookie: Option<Cookie>,
    peer_cookie: Option<Cookie>,
}

/// Builder of a [`SessionConfig`]; [`build`](Self::build) validates.
#[derive(Clone, Debug)]
pub struct SessionConfigBuilder(SessionConfig);

impl SessionConfig {
    /// Starts a session of the tunnel named `tunnel_name`.
    pub fn builder(
        tunnel_name: impl Into<String>,
        session_id: u32,
        interface_name: L2tpIfName,
    ) -> SessionConfigBuilder {
        SessionConfigBuilder(SessionConfig {
            tunnel_name: tunnel_name.into(),
            session_id,
            peer_session_id: None,
            interface_name,
            interface_hwaddr: None,
            cookie: None,
            peer_cookie: None,
        })
    }

    /// The configuration name of the session's tunnel.
    pub fn tunnel_name(&self) -> &str {
        &self.tunnel_name
    }

    /// The local session identifier.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// The peer's session identifier, `session_id` unless configured.
    pub fn peer_session_id(&self) -> u32 {
        self.peer_session_id.unwrap_or(self.session_id)
    }

    /// The name of the session's interface.
    pub fn interface_name(&self) -> &L2tpIfName {
        &self.interface_name
    }

    /// The configured hardware address; `None` keeps the kernel's.
    pub fn interface_hwaddr(&self) -> Option<HwAddr> {
        self.interface_hwaddr
    }

    /// The cookie sent in every frame.
    pub fn cookie(&self) -> Option<Cookie> {
        self.cookie
    }

    /// The cookie required in every frame received, `cookie` unless
    /// configured.
    pub fn peer_cookie(&self) -> Option<Cookie> {
        self.peer_cookie.or(self.cookie)
    }

    fn check(&self) -> std::result::Result<(), Mistake> {
        check_id(self.session_id, "session_id")?;
        check_id(self.peer_session_id.unwrap_or(1), "peer_session_id")?;
        text::ifname(self.interface_name.as_bytes())
            .map(drop)
            .map_err(|e| Mistake::hard("interface_name", e))
    }
}

impl SessionConfigBuilder {
    /// The peer's session identifier.
    pub fn peer_session_id(mut self, id: u32) -> Self {
        self.0.peer_session_id = Some(id);
        self
    }

    /// The interface's hardware address.
    pub fn interface_hwaddr(mut self, addr: HwAddr) -> Self {
        self.0.interface_hwaddr = Some(addr);
        self
    }

    /// The cookie sent in every frame.
    pub fn cookie(mut self, cookie: Cookie) -> Self {
        self.0.cookie = Some(cookie);
        self
    }

    /// The cookie required in every frame received.
    pub fn peer_cookie(mut self, cookie: Cookie) -> Self {
        self.0.peer_cookie = Some(cookie);
        self
    }

    /// Validates the entry by C8.
    pub fn build(self) -> Result<SessionConfig> {
        self.0.check().map_err(Mistake::into_error)?;
        Ok(self.0)
    }
}

/// A name server of a resolver of the address kind (C16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameServer {
    addr: IpAddr,
    zone: Option<L2tpIfName>,
    port: u16,
}

impl NameServer {
    /// Validates the server: a unicast address (an IPv4-mapped one is
    /// taken as IPv4), a zone only on a link-local IPv6 address, a port
    /// other than 0 (53 is the default of the files).
    pub fn new(addr: IpAddr, zone: Option<L2tpIfName>, port: u16) -> Result<Self> {
        let addr = addr.to_canonical();
        text::unicast(addr).map_err(Error::InvalidConfig)?;
        if let Some(zone) = &zone {
            text::zone(addr, zone.as_bytes()).map_err(Error::InvalidConfig)?;
        }
        if port == 0 {
            return Err(Error::InvalidConfig("port 0 is not a port".into()));
        }
        Ok(NameServer { addr, zone, port })
    }

    /// The address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The zone of a link-local address.
    pub fn zone(&self) -> Option<&L2tpIfName> {
        self.zone.as_ref()
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for NameServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let zone = self
            .zone
            .as_ref()
            .map(|z| format!("%{}", z.to_string_lossy()));
        let zone = zone.as_deref().unwrap_or("");
        match (self.addr, self.port) {
            (addr, 53) => write!(f, "{addr}{zone}"),
            (IpAddr::V4(addr), port) => write!(f, "{addr}:{port}"),
            (IpAddr::V6(addr), port) => write!(f, "[{addr}{zone}]:{port}"),
        }
    }
}

/// The discovery method of a resolver (C16, V2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Method {
    /// Router advertisements (V10).
    Ra,
    /// DHCPv6 Information-Request (V12).
    Dhcpv6,
    /// Both, DHCPv6 servers first (V14).
    Ipv6,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Method::Ra => "ra",
            Method::Dhcpv6 => "dhcpv6",
            Method::Ipv6 => "ipv6",
        })
    }
}

/// The DHCPv6 client identifier of a resolver (C16, V12).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dhcpv6Identity {
    /// A DUID-LL (type 3, hardware type 1) from the bind interface's
    /// Ethernet address: `"link-layer"`, the default.
    LinkLayer,
    /// No Client Identifier (RFC 7844): `"anonymous"`.
    Anonymous,
    /// A DUID-LL from a random locally administered address: `"random"`.
    Random,
    /// An exact DUID of 3 to 130 bytes: `dhcpv6_duid`.
    Duid(Vec<u8>),
}

/// A resolver entry (C16): name servers by address, or a discovery
/// method on a bind interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverConfig {
    addresses: Vec<NameServer>,
    method: Option<Method>,
    bind_interface: Option<L2tpIfName>,
    dhcpv6_identity: Option<Dhcpv6Identity>,
}

impl ResolverConfig {
    /// A resolver of the address kind: `addresses`, non-empty, tried in
    /// order.
    pub fn with_addresses(
        addresses: Vec<NameServer>,
        bind_interface: Option<L2tpIfName>,
    ) -> Result<Self> {
        ResolverConfig {
            addresses,
            method: None,
            bind_interface,
            dhcpv6_identity: None,
        }
        .checked()
    }

    /// A resolver that discovers its servers on `bind_interface`, a link.
    /// `dhcpv6_identity` is for [`Method::Dhcpv6`] and [`Method::Ipv6`]
    /// only.
    pub fn with_method(
        method: Method,
        bind_interface: L2tpIfName,
        dhcpv6_identity: Option<Dhcpv6Identity>,
    ) -> Result<Self> {
        ResolverConfig {
            addresses: Vec::new(),
            method: Some(method),
            bind_interface: Some(bind_interface),
            dhcpv6_identity,
        }
        .checked()
    }

    fn checked(self) -> Result<Self> {
        self.check().map_err(Mistake::into_error)?;
        Ok(self)
    }

    /// The name servers of the address kind; empty with a method.
    pub fn addresses(&self) -> &[NameServer] {
        &self.addresses
    }

    /// The discovery method; `None` for the address kind.
    pub fn method(&self) -> Option<Method> {
        self.method
    }

    /// The interface the queries are bound to.
    pub fn bind_interface(&self) -> Option<&L2tpIfName> {
        self.bind_interface.as_ref()
    }

    /// The DHCPv6 client identifier, [`Dhcpv6Identity::LinkLayer`] unless
    /// configured; meaningful with a DHCPv6 method only.
    pub fn dhcpv6_identity(&self) -> &Dhcpv6Identity {
        self.dhcpv6_identity
            .as_ref()
            .unwrap_or(&Dhcpv6Identity::LinkLayer)
    }

    fn check(&self) -> std::result::Result<(), Mistake> {
        if let Some(name) = &self.bind_interface {
            text::ifname(name.as_bytes()).map_err(|e| Mistake::hard("bind_interface", e))?;
        }
        match (self.addresses.is_empty(), self.method) {
            (true, None) => {
                return Err(Mistake::hard(
                    "addresses",
                    "either addresses or method is required",
                ));
            }
            (false, Some(_)) => {
                return Err(Mistake::hard(
                    "method",
                    "addresses and method are exclusive",
                ));
            }
            (true, Some(method)) if self.bind_interface.is_none() => {
                return Err(Mistake::hard(
                    "bind_interface",
                    format!("required with method {method}"),
                ));
            }
            _ => {}
        }
        if self.bind_interface.is_none()
            && let Some(server) = self
                .addresses
                .iter()
                .find(|s| s.zone.is_none() && text::link_local(s.addr))
        {
            return Err(Mistake::hard(
                "addresses",
                format!("{server} is link-local: it needs a zone or bind_interface"),
            ));
        }
        match (&self.dhcpv6_identity, self.method) {
            (Some(Dhcpv6Identity::Duid(duid)), _) if !(3..=130).contains(&duid.len()) => Err(
                Mistake::hard("dhcpv6_duid", format!("{} bytes, not 3 to 130", duid.len())),
            ),
            (None, _) | (Some(_), Some(Method::Dhcpv6 | Method::Ipv6)) => Ok(()),
            (Some(Dhcpv6Identity::Duid(_)), _) => Err(Mistake::tolerated(
                "dhcpv6_duid",
                "used only with method dhcpv6 or ipv6",
            )),
            (Some(_), _) => Err(Mistake::tolerated(
                "dhcpv6_identity",
                "used only with method dhcpv6 or ipv6",
            )),
        }
    }
}

/// The `host` table (C17).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostConfig {
    fix_bindv6only: Option<bool>,
}

impl HostConfig {
    /// The defaults.
    pub fn new() -> Self {
        HostConfig::default()
    }

    /// Whether to keep `net.ipv6.bindv6only` at 0 (P25).
    pub fn with_fix_bindv6only(mut self, fix: bool) -> Self {
        self.fix_bindv6only = Some(fix);
        self
    }

    /// Whether to keep `net.ipv6.bindv6only` at 0; `true` by default.
    pub fn fix_bindv6only(&self) -> bool {
        self.fix_bindv6only.unwrap_or(true)
    }
}

/// A configuration that satisfies every rule of the specification (L4):
/// each entry is valid, names are unique where C9 says, and every name an
/// entry refers to exists.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    host: HostConfig,
    resolvers: BTreeMap<String, ResolverConfig>,
    tunnels: BTreeMap<String, TunnelConfig>,
    sessions: BTreeMap<String, SessionConfig>,
}

impl Config {
    /// The empty configuration, which is valid (C10).
    pub fn new() -> Self {
        Config::default()
    }

    /// The host settings.
    pub fn host(&self) -> &HostConfig {
        &self.host
    }

    /// The resolvers by configuration name.
    pub fn resolvers(&self) -> &BTreeMap<String, ResolverConfig> {
        &self.resolvers
    }

    /// The tunnels by configuration name.
    pub fn tunnels(&self) -> &BTreeMap<String, TunnelConfig> {
        &self.tunnels
    }

    /// The sessions by configuration name.
    pub fn sessions(&self) -> &BTreeMap<String, SessionConfig> {
        &self.sessions
    }

    /// Replaces the host settings.
    pub fn set_host(&mut self, host: HostConfig) {
        self.host = host;
    }

    /// Inserts or replaces a resolver.
    pub fn insert_resolver(
        &mut self,
        name: impl Into<String>,
        resolver: ResolverConfig,
    ) -> Result<()> {
        self.insert(name.into(), resolver)
            .map_err(Mistake::into_error)
    }

    /// Inserts or replaces a tunnel: its `tunnel_id` must be free and its
    /// `resolver_name` must name a resolver (C7, C9).
    pub fn insert_tunnel(&mut self, name: impl Into<String>, tunnel: TunnelConfig) -> Result<()> {
        self.insert(name.into(), tunnel)
            .map_err(Mistake::into_error)
    }

    /// Inserts or replaces a session: its tunnel must exist, its
    /// `session_id` and `interface_name` must be free (C8, C9).
    pub fn insert_session(
        &mut self,
        name: impl Into<String>,
        session: SessionConfig,
    ) -> Result<()> {
        self.insert(name.into(), session)
            .map_err(Mistake::into_error)
    }

    /// The kernel identity of the session named `name` (C14).
    pub fn session_identity(&self, name: &str) -> Option<SessionIdentity> {
        let session = self.sessions.get(name)?;
        // Every session's tunnel exists (L4).
        let tunnel = &self.tunnels[&session.tunnel_name];
        Some(SessionIdentity {
            tunnel: tunnel.identity(),
            session_id: session.session_id,
            peer_session_id: session.peer_session_id(),
            cookie: session.cookie,
            peer_cookie: session.peer_cookie(),
        })
    }

    fn insert<E: Entry>(&mut self, name: String, entry: E) -> std::result::Result<(), Mistake> {
        check_name(&name)?;
        entry.fits(&name, self)?;
        E::table_mut(self).insert(name, entry);
        Ok(())
    }
}

/// What the conversions need of each kind of entry.
trait Entry: Clone {
    const KIND: EntryKind;
    fn table(config: &Config) -> &BTreeMap<String, Self>;
    fn table_mut(config: &mut Config) -> &mut BTreeMap<String, Self>;
    /// The rules against the rest of the configuration: uniqueness (C9)
    /// and references.
    fn fits(&self, name: &str, config: &Config) -> std::result::Result<(), Mistake>;
}

impl Entry for ResolverConfig {
    const KIND: EntryKind = EntryKind::Resolver;
    fn table(config: &Config) -> &BTreeMap<String, Self> {
        &config.resolvers
    }
    fn table_mut(config: &mut Config) -> &mut BTreeMap<String, Self> {
        &mut config.resolvers
    }
    fn fits(&self, _: &str, _: &Config) -> std::result::Result<(), Mistake> {
        Ok(())
    }
}

impl Entry for TunnelConfig {
    const KIND: EntryKind = EntryKind::Tunnel;
    fn table(config: &Config) -> &BTreeMap<String, Self> {
        &config.tunnels
    }
    fn table_mut(config: &mut Config) -> &mut BTreeMap<String, Self> {
        &mut config.tunnels
    }
    fn fits(&self, name: &str, config: &Config) -> std::result::Result<(), Mistake> {
        if let Some((other, _)) =
            others(&config.tunnels, name).find(|(_, t)| t.tunnel_id == self.tunnel_id)
        {
            return Err(Mistake::hard(
                "tunnel_id",
                format!(
                    "{} is already the tunnel_id of tunnel {other:?}",
                    self.tunnel_id
                ),
            ));
        }
        match &self.resolver_name {
            Some(resolver) if !config.resolvers.contains_key(resolver) => Err(Mistake::hard(
                "resolver_name",
                format!("no resolver {resolver:?} in the configuration"),
            )),
            _ => Ok(()),
        }
    }
}

impl Entry for SessionConfig {
    const KIND: EntryKind = EntryKind::Session;
    fn table(config: &Config) -> &BTreeMap<String, Self> {
        &config.sessions
    }
    fn table_mut(config: &mut Config) -> &mut BTreeMap<String, Self> {
        &mut config.sessions
    }
    fn fits(&self, name: &str, config: &Config) -> std::result::Result<(), Mistake> {
        if !config.tunnels.contains_key(&self.tunnel_name) {
            return Err(Mistake::hard(
                "tunnel_name",
                format!("no tunnel {:?} in the configuration", self.tunnel_name),
            ));
        }
        for (other, session) in others(&config.sessions, name) {
            if session.session_id == self.session_id {
                return Err(Mistake::hard(
                    "session_id",
                    format!(
                        "{} is already the session_id of session {other:?}",
                        self.session_id
                    ),
                ));
            }
            if session.interface_name == self.interface_name {
                return Err(Mistake::hard(
                    "interface_name",
                    format!(
                        "{} is already the interface_name of session {other:?}",
                        self.interface_name.to_string_lossy()
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// The entries of `table` other than `name`, which an insertion replaces.
fn others<'a, E>(
    table: &'a BTreeMap<String, E>,
    name: &'a str,
) -> impl Iterator<Item = (&'a String, &'a E)> {
    table.iter().filter(move |(other, _)| *other != name)
}

/// C5: non-empty, at most 64 bytes, no control character.
fn check_name(name: &str) -> std::result::Result<(), Mistake> {
    if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
        return Err(Mistake {
            field: None,
            message: format!("the name {name:?} is not 1 to 64 bytes without control characters"),
            hard: true,
        });
    }
    Ok(())
}

fn check_id(id: u32, field: &'static str) -> std::result::Result<(), Mistake> {
    match id {
        0 => Err(Mistake::hard(field, "0 is not an identifier")),
        _ => Ok(()),
    }
}
