//! Desired configuration: tunnels and the sessions riding on them.
//!
//! A [`Config`] is validated as a whole: identifiers are non-zero and
//! unique, every session names a tunnel that exists, a literal remote
//! address is unicast and of the tunnel's address family, interface names
//! satisfy the kernel's rules and are unique, hardware addresses are unicast
//! and cookies are four or eight bytes. It is built in code with
//! [`Config::new`] and the `insert_*` methods or, with the `serde` feature,
//! deserialised from any format (deserialising runs the same validation and
//! applies the same defaults). A merged [`PartialConfig`] becomes a `Config`
//! either strictly, with [`PartialConfig::into_config`], or leniently, with
//! [`PartialConfig::into_config_lenient`], which keeps everything usable,
//! connects a tunnel with an unusable endpoint to the discard address, gives
//! a session with an unusable hardware address the kernel's, and reports
//! each problem as a [`ConfigProblem`]; the daemon loads its configuration
//! that way.
//! This module does no I/O and assumes no serialisation format: the daemon
//! binary reads its TOML files and feeds the documents in as
//! [`PartialConfig`] values.
//!
//! The serialised shape is a `tunnels` map and a `sessions` map, each keyed
//! by a configuration name; see [`TunnelConfig`] and [`SessionConfig`] for
//! the fields. Several documents can be merged field by field with
//! [`PartialConfig::merge`], later ones overriding earlier ones, which is
//! how the daemon layers its drop-in directory over its main file.

use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};

use crate::error::{Error, Result};

/// A tunnel's remote endpoint: an address or a host name, parsed from a
/// string. Re-exported from the `iphost` crate so that it can be named
/// without a dependency of a matching version; [`FQDN`] is the type inside
/// its host-name variant.
pub use iphost::{IpHost, FQDN};
/// A checked interface name and the extension trait that constructs it from
/// bytes and resolves it to and from an interface index. Re-exported from
/// the `l2tp` crate so that they can be named without a dependency of a
/// matching version; a name also parses from a string.
pub use l2tp::{L2tpIfName, L2tpIfNameExt};

/// Serde adapter rendering checked interface names as strings. Reading goes
/// through the partial configurations, which keep strings until their
/// overrides are merged and check them when completing the configuration.
#[cfg(feature = "serde")]
pub(crate) mod ifname_serde {
    use l2tp::L2tpIfName;
    use serde::Serializer;

    fn text<E: serde::ser::Error>(name: &L2tpIfName) -> Result<&str, E> {
        name.to_str()
            .map_err(|_| E::custom(format!("interface name {name:?} is not UTF-8")))
    }

    pub(crate) fn serialize<S: Serializer>(name: &L2tpIfName, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(text(name)?)
    }

    pub(crate) fn serialize_option<S: Serializer>(
        name: &Option<L2tpIfName>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match name {
            None => s.serialize_none(),
            Some(name) => s.serialize_some(text(name)?),
        }
    }
}

/// A unicast Ethernet hardware (MAC) address, written as six
/// colon-separated hexadecimal octets such as `02:00:5e:00:53:01`.
///
/// Multicast addresses (lowest bit of the first octet set) and the all-zero
/// address are rejected, as the kernel refuses them for an interface.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HwAddr([u8; 6]);

impl HwAddr {
    /// Checks `octets` and wraps them.
    pub fn new(octets: [u8; 6]) -> Result<Self> {
        if octets[0] & 0x01 != 0 {
            return Err(Error::InvalidConfig(format!(
                "hardware address {} is a multicast address",
                Self(octets)
            )));
        }
        if octets == [0; 6] {
            return Err(Error::InvalidConfig(
                "hardware address 00:00:00:00:00:00 is not valid".to_string(),
            ));
        }
        Ok(Self(octets))
    }

    /// The six octets of the address.
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// Whether the locally administered bit is set.
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Interprets a link-layer address reported by the kernel, which may
    /// belong to a device that is not Ethernet or carry a multicast or
    /// zero address; those are `None`.
    pub(crate) fn from_kernel(bytes: &[u8]) -> Option<Self> {
        let octets: [u8; 6] = bytes.try_into().ok()?;
        Self::new(octets).ok()
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

impl FromStr for HwAddr {
    type Err = Error;

    /// Parses `xx:xx:xx:xx:xx:xx`; `-` is accepted as the separator too, and
    /// hexadecimal digits may use either case.
    fn from_str(s: &str) -> Result<Self> {
        let invalid = || Error::InvalidConfig(format!("invalid hardware address {s:?}"));
        let mut octets = [0_u8; 6];
        let mut parts = s.split([':', '-']);
        for octet in &mut octets {
            let part = parts.next().ok_or_else(invalid)?;
            if part.len() != 2 {
                return Err(invalid());
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| invalid())?;
        }
        if parts.next().is_some() {
            return Err(invalid());
        }
        Self::new(octets)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for HwAddr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for HwAddr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// An L2TPv3 session cookie: four or eight bytes, written as 8 or 16
/// hexadecimal digits such as `0011223344556677`.
///
/// The kernel appends a session's [`cookie`](SessionConfig::cookie) to every
/// frame it sends and discards received frames that do not carry the
/// session's [`peer_cookie`](SessionConfig::peer_cookie). L2TPv3 over IP
/// delivers data frames by session identifier alone, so without cookies any
/// host that can reach this one with IP protocol 115 and knows the session
/// identifier can inject frames into the pseudowire. Both ends must agree on
/// the values. `Display` renders the digits in lower case; `Debug` only
/// gives the length, so that a cookie does not end up in a log by accident.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cookie(CookieBytes);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum CookieBytes {
    Four([u8; 4]),
    Eight([u8; 8]),
}

impl Cookie {
    /// Wraps `bytes`, which must be four or eight long.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if let Ok(four) = <[u8; 4]>::try_from(bytes) {
            return Ok(Self::from(four));
        }
        if let Ok(eight) = <[u8; 8]>::try_from(bytes) {
            return Ok(Self::from(eight));
        }
        Err(Error::InvalidConfig(format!(
            "a cookie is 4 or 8 bytes long, not {}",
            bytes.len()
        )))
    }

    /// The four or eight bytes of the cookie.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            CookieBytes::Four(bytes) => bytes,
            CookieBytes::Eight(bytes) => bytes,
        }
    }

    pub(crate) fn to_l2tp(self) -> l2tp::Cookie {
        match self.0 {
            CookieBytes::Four(bytes) => l2tp::Cookie::from(bytes),
            CookieBytes::Eight(bytes) => l2tp::Cookie::from(bytes),
        }
    }
}

impl From<[u8; 4]> for Cookie {
    fn from(bytes: [u8; 4]) -> Self {
        Self(CookieBytes::Four(bytes))
    }
}

impl From<[u8; 8]> for Cookie {
    fn from(bytes: [u8; 8]) -> Self {
        Self(CookieBytes::Eight(bytes))
    }
}

impl fmt::Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cookie(<{} bytes>)", self.as_bytes().len())
    }
}

impl FromStr for Cookie {
    type Err = Error;

    /// Parses 8 or 16 hexadecimal digits of either case. Signs, prefixes
    /// and separators are not accepted.
    fn from_str(s: &str) -> Result<Self> {
        let invalid = || {
            Error::InvalidConfig(format!(
                "invalid cookie {s:?}: expected 8 or 16 hexadecimal digits"
            ))
        };
        let digits = s.as_bytes();
        if !(digits.len() == 8 || digits.len() == 16) || !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(invalid());
        }
        let mut bytes = [0_u8; 8];
        for (byte, pair) in bytes.iter_mut().zip(digits.chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Self::new(&bytes[..digits.len() / 2])
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Cookie {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Cookie {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Whether `addr` can be a tunnel's peer: a unicast address other than the
/// unspecified one. Multicast and IPv4 broadcast addresses cannot answer,
/// and the kernel connects a socket to the unspecified address by pointing
/// it at the host itself. Loopback is allowed, for local testing.
/// IPv4-mapped IPv6 addresses are judged as the IPv4 address they carry.
pub(crate) fn is_usable_remote_addr(addr: IpAddr) -> bool {
    match addr.to_canonical() {
        IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()),
        IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_multicast()),
    }
}

/// Which address family a tunnel's remote endpoint is resolved to.
///
/// Serialised as `"V4"`/`"V6"`; `"v4"`/`"v6"` are accepted when reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum IpVersion {
    /// IPv4; the tunnel socket uses an IPv4-mapped IPv6 address.
    #[cfg_attr(feature = "serde", serde(alias = "v4"))]
    V4,
    /// IPv6.
    #[cfg_attr(feature = "serde", serde(alias = "v6"))]
    V6,
}

impl IpVersion {
    /// The family of a literal address; a host name has none until resolved.
    fn of_literal(remote_addr: &IpHost) -> Option<Self> {
        match remote_addr {
            IpHost::V4Addr(_) => Some(IpVersion::V4),
            IpHost::V6Addr(_) => Some(IpVersion::V6),
            IpHost::Fqdn(_) => None,
        }
    }

    fn describe(self) -> &'static str {
        match self {
            IpVersion::V4 => "IPv4",
            IpVersion::V6 => "IPv6",
        }
    }
}

impl FromStr for IpVersion {
    type Err = Error;

    /// Parses `"V4"` or `"V6"`, in either case.
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "V4" | "v4" => Ok(IpVersion::V4),
            "V6" | "v6" => Ok(IpVersion::V6),
            other => Err(Error::InvalidConfig(format!(
                "invalid ip_version {other:?}: expected \"V4\" or \"V6\""
            ))),
        }
    }
}

/// Which kind of entry a [`ConfigProblem`] concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EntryKind {
    /// An entry of the `tunnels` map.
    Tunnel,
    /// An entry of the `sessions` map.
    Session,
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EntryKind::Tunnel => "tunnel",
            EntryKind::Session => "session",
        })
    }
}

/// What became of an entry a lenient conversion found a problem with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProblemEffect {
    /// The entry was left out; a left-out tunnel takes its sessions with it.
    Rejected,
    /// The tunnel was kept but has no usable peer: it is connected to
    /// [`TunnelConfig::NO_PEER_ADDR`] until its endpoint is corrected, and
    /// its sessions are created as usual. Correcting the endpoint, with the
    /// identifiers and `bind_interface` unchanged, reconnects the tunnel in
    /// place.
    NoPeer,
    /// The session was kept with the hardware address the kernel assigns,
    /// its `interface_hwaddr` being unusable. Correcting it applies the
    /// address in place, once the interface is down if it is up.
    KernelHwAddr,
    /// The entry would have been rejected, so the tunnel or session of the
    /// same name from the previous configuration was kept instead; see
    /// [`Config::from_partial_with_previous`].
    KeptPrevious,
}

/// A problem a lenient conversion found with a tunnel or session, and what
/// became of the entry.
///
/// Displays as `tunnel <name>: <reason>` or `session <name>: <reason>`; the
/// underlying [`Error`] is its source.
#[derive(Debug)]
pub struct ConfigProblem {
    kind: EntryKind,
    name: String,
    effect: ProblemEffect,
    error: Error,
}

impl ConfigProblem {
    fn new(kind: EntryKind, name: &str, effect: ProblemEffect, error: Error) -> Self {
        Self {
            kind,
            name: name.to_string(),
            effect,
            error,
        }
    }

    /// Whether the entry is a tunnel or a session.
    pub fn kind(&self) -> EntryKind {
        self.kind
    }

    /// The entry's configuration name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What became of the entry.
    pub fn effect(&self) -> ProblemEffect {
        self.effect
    }

    /// What is wrong with the entry.
    pub fn error(&self) -> &Error {
        &self.error
    }

    fn reason(&self) -> String {
        match &self.error {
            Error::InvalidConfig(message) => message.clone(),
            other => other.to_string(),
        }
    }
}

impl fmt::Display for ConfigProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.kind, self.name, self.reason())
    }
}

impl std::error::Error for ConfigProblem {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[cfg(feature = "serde")]
fn merge_opt<T>(dst: &mut Option<T>, src: Option<T>) {
    if let Some(v) = src {
        *dst = Some(v);
    }
}

/// Parses an optional text field, naming the field in the error.
#[cfg(feature = "serde")]
fn parse_field<T: FromStr<Err = Error>>(field: &str, text: Option<String>) -> Result<Option<T>> {
    text.map(|text| text.parse().map_err(|e| field_error(field, e)))
        .transpose()
}

/// Prefixes an error with the field it concerns.
#[cfg(feature = "serde")]
fn field_error(field: &str, error: impl Into<Error>) -> Error {
    let message = match error.into() {
        Error::InvalidConfig(message) => message,
        other => other.to_string(),
    };
    Error::InvalidConfig(format!("{field}: {message}"))
}

/// A configuration as deserialised from one document: every field is
/// optional so that several documents can be merged before the result is
/// validated. Values that have a textual form (addresses, names, hardware
/// addresses, cookies, the address family) stay text until then, so a later
/// document can replace an invalid placeholder and, in a lenient
/// conversion, a mistake in one entry rejects only that entry. Only a value
/// of the wrong type, such as a string where a number is expected, fails
/// deserialising the document itself.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct PartialConfig {
    #[serde(default)]
    tunnels: BTreeMap<String, PartialTunnelConfig>,
    #[serde(default)]
    sessions: BTreeMap<String, PartialSessionConfig>,
}

#[cfg(feature = "serde")]
impl PartialConfig {
    /// Overlays `latter` on this configuration: fields set in `latter` win,
    /// fields it leaves out are kept.
    pub fn merge(&mut self, latter: Self) {
        for (key, value) in latter.tunnels {
            let tunnel = self.tunnels.entry(key).or_default();
            tunnel.merge(value);
        }
        for (key, value) in latter.sessions {
            let session = self.sessions.entry(key).or_default();
            session.merge(value);
        }
    }

    /// Validates the merged result into a [`Config`], failing on the first
    /// invalid entry.
    pub fn into_config(self) -> Result<Config> {
        Config::from_partial(self)
    }

    /// Validates the merged result into a [`Config`] of everything usable
    /// and reports each problem with what became of its entry. See
    /// [`Config::from_partial_lenient`].
    pub fn into_config_lenient(self) -> (Config, Vec<ConfigProblem>) {
        Config::from_partial_lenient(self)
    }

    /// Like [`into_config_lenient`](Self::into_config_lenient), for a
    /// reload: an entry that would be rejected keeps its values from
    /// `previous` instead. See [`Config::from_partial_with_previous`].
    pub fn into_config_with_previous(self, previous: &Config) -> (Config, Vec<ConfigProblem>) {
        Config::from_partial_with_previous(self, previous)
    }
}

#[cfg(feature = "serde")]
#[derive(Debug, Clone, serde::Deserialize, Default)]
struct PartialTunnelConfig {
    tunnel_id: Option<u32>,
    peer_tunnel_id: Option<u32>,
    ip_version: Option<String>,
    remote_addr: Option<String>,
    bind_interface: Option<String>,
}

#[cfg(feature = "serde")]
impl PartialTunnelConfig {
    fn merge(&mut self, latter: Self) {
        merge_opt(&mut self.tunnel_id, latter.tunnel_id);
        merge_opt(&mut self.peer_tunnel_id, latter.peer_tunnel_id);
        merge_opt(&mut self.ip_version, latter.ip_version);
        merge_opt(&mut self.remote_addr, latter.remote_addr);
        merge_opt(&mut self.bind_interface, latter.bind_interface);
    }

    /// The complete tunnel, with the problem of its endpoint if that had to
    /// be replaced by [`TunnelConfig::NO_PEER_ADDR`]. Anything else wrong is
    /// an error.
    fn into_full(self) -> Result<(TunnelConfig, Option<Error>)> {
        let tunnel_id = self
            .tunnel_id
            .ok_or(Error::InvalidConfig("tunnel_id is missing".to_string()))?;
        let bind_interface = self
            .bind_interface
            .map(|name| L2tpIfName::from_name(&name).map_err(|e| field_error("bind_interface", e)))
            .transpose()?;
        let (ip_version, remote_addr, endpoint_problem) =
            match Self::endpoint(self.ip_version, self.remote_addr) {
                Ok((ip_version, remote_addr)) => (ip_version, remote_addr, None),
                Err(problem) => (
                    IpVersion::V6,
                    IpHost::V6Addr(TunnelConfig::NO_PEER_ADDR),
                    Some(problem),
                ),
            };

        let config = TunnelConfig {
            tunnel_id,
            peer_tunnel_id: self.peer_tunnel_id.unwrap_or(tunnel_id),
            ip_version,
            remote_addr,
            bind_interface,
        };
        config.validate()?;
        Ok((config, endpoint_problem))
    }

    /// The endpoint, or why it cannot be used.
    fn endpoint(
        ip_version: Option<String>,
        remote_addr: Option<String>,
    ) -> Result<(IpVersion, IpHost)> {
        let text = remote_addr.ok_or(Error::InvalidConfig("remote_addr is missing".to_string()))?;
        let remote_addr: IpHost = text
            .parse()
            .map_err(|e| Error::InvalidConfig(format!("remote_addr {text:?}: {e}")))?;
        // A literal address implies its family; a host name needs to be
        // told which of its answers to use.
        let ip_version = match ip_version {
            Some(text) => text.parse()?,
            None => IpVersion::of_literal(&remote_addr).ok_or_else(|| {
                Error::InvalidConfig(
                    "ip_version is missing: it selects the address family a host name resolves to"
                        .to_string(),
                )
            })?,
        };
        TunnelConfig::validate_endpoint(ip_version, &remote_addr)?;
        Ok((ip_version, remote_addr))
    }
}

#[cfg(feature = "serde")]
impl TryFrom<PartialTunnelConfig> for TunnelConfig {
    type Error = Error;

    /// Strict: an unusable endpoint is an error here.
    fn try_from(partial: PartialTunnelConfig) -> Result<Self> {
        match partial.into_full()? {
            (config, None) => Ok(config),
            (_, Some(endpoint_problem)) => Err(endpoint_problem),
        }
    }
}

#[cfg(feature = "serde")]
#[derive(Debug, Clone, serde::Deserialize, Default)]
struct PartialSessionConfig {
    tunnel_name: Option<String>,
    session_id: Option<u32>,
    peer_session_id: Option<u32>,
    interface_name: Option<String>,
    interface_hwaddr: Option<String>,
    cookie: Option<String>,
    peer_cookie: Option<String>,
}

#[cfg(feature = "serde")]
impl PartialSessionConfig {
    fn merge(&mut self, latter: Self) {
        merge_opt(&mut self.tunnel_name, latter.tunnel_name);
        merge_opt(&mut self.session_id, latter.session_id);
        merge_opt(&mut self.peer_session_id, latter.peer_session_id);
        merge_opt(&mut self.interface_name, latter.interface_name);
        merge_opt(&mut self.interface_hwaddr, latter.interface_hwaddr);
        merge_opt(&mut self.cookie, latter.cookie);
        merge_opt(&mut self.peer_cookie, latter.peer_cookie);
    }

    /// The complete session, with the problem of its hardware address if
    /// that had to be left to the kernel. Anything else wrong is an error.
    fn into_full(self) -> Result<(SessionConfig, Option<Error>)> {
        let tunnel_name = self
            .tunnel_name
            .ok_or(Error::InvalidConfig("tunnel_name is missing".to_string()))?;
        let session_id = self
            .session_id
            .ok_or(Error::InvalidConfig("session_id is missing".to_string()))?;
        let interface_name = self.interface_name.ok_or(Error::InvalidConfig(
            "interface_name is missing".to_string(),
        ))?;
        let interface_name =
            L2tpIfName::from_name(&interface_name).map_err(|e| field_error("interface_name", e))?;
        let (interface_hwaddr, hwaddr_problem) =
            match parse_field("interface_hwaddr", self.interface_hwaddr) {
                Ok(hwaddr) => (hwaddr, None),
                Err(problem) => (None, Some(problem)),
            };
        let cookie: Option<Cookie> = parse_field("cookie", self.cookie)?;
        let peer_cookie = parse_field("peer_cookie", self.peer_cookie)?;

        let config = SessionConfig {
            tunnel_name,
            session_id,
            peer_session_id: self.peer_session_id.unwrap_or(session_id),
            interface_name,
            interface_hwaddr,
            cookie,
            peer_cookie: peer_cookie.or(cookie),
        };
        config.validate()?;
        Ok((config, hwaddr_problem))
    }
}

#[cfg(feature = "serde")]
impl TryFrom<PartialSessionConfig> for SessionConfig {
    type Error = Error;

    /// Strict: an unusable hardware address is an error here.
    fn try_from(partial: PartialSessionConfig) -> Result<Self> {
        match partial.into_full()? {
            (config, None) => Ok(config),
            (_, Some(hwaddr_problem)) => Err(hwaddr_problem),
        }
    }
}

/// A validated set of tunnels and sessions, keyed by their configuration
/// names.
///
/// With the `serde` feature, deserialising a `Config` runs the same
/// validation as [`PartialConfig::into_config`], so a `Config` is
/// consistent however it was obtained.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "PartialConfig")
)]
pub struct Config {
    #[cfg_attr(feature = "serde", serde(default))]
    tunnels: BTreeMap<String, TunnelConfig>,
    #[cfg_attr(feature = "serde", serde(default))]
    sessions: BTreeMap<String, SessionConfig>,
}

impl Config {
    /// An empty configuration: applying it removes every tunnel and session.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates a merged [`PartialConfig`], failing on the first problem,
    /// an unusable endpoint included; the error names the entry.
    #[cfg(feature = "serde")]
    pub fn from_partial(partial: PartialConfig) -> Result<Self> {
        let (config, problems) = Self::from_partial_lenient(partial);
        match problems.into_iter().next() {
            Some(first) => Err(Error::InvalidConfig(first.to_string())),
            None => Ok(config),
        }
    }

    /// Validates a merged [`PartialConfig`] entry by entry, keeping
    /// everything usable and reporting each problem with what became of
    /// its entry. The result may well be empty, which is a valid
    /// configuration.
    ///
    /// A tunnel whose endpoint cannot be used (`remote_addr` missing or
    /// neither an address nor a host name, `ip_version` invalid or missing
    /// for a host name, a literal address that is not unicast or of the
    /// other family) is kept with [`TunnelConfig::NO_PEER_ADDR`] as its
    /// peer, since only connectivity is affected
    /// ([`ProblemEffect::NoPeer`]). A session whose `interface_hwaddr`
    /// cannot be used is kept with the hardware address the kernel assigns
    /// ([`ProblemEffect::KernelHwAddr`]). Any other problem leaves the
    /// entry out ([`ProblemEffect::Rejected`]). Tunnels are taken in name
    /// order, then sessions: a duplicate identifier or interface name
    /// rejects the later entry, and a session whose tunnel was rejected is
    /// rejected too. The daemon starts this way, so one mistake does not
    /// keep every other tunnel down; it reloads with
    /// [`from_partial_with_previous`](Self::from_partial_with_previous).
    #[cfg(feature = "serde")]
    pub fn from_partial_lenient(partial: PartialConfig) -> (Self, Vec<ConfigProblem>) {
        Self::complete(partial, None)
    }

    /// Like [`from_partial_lenient`](Self::from_partial_lenient), for a
    /// reload: an entry that would be rejected keeps the tunnel or session
    /// of the same name from `previous`, the configuration in force, when
    /// there is one and it still fits the rest
    /// ([`ProblemEffect::KeptPrevious`]); otherwise it is rejected as usual.
    /// A session of a tunnel that kept its previous values is taken as
    /// given, since that tunnel still exists. So a mistake made while the
    /// daemon runs never takes a running tunnel or session down.
    #[cfg(feature = "serde")]
    pub fn from_partial_with_previous(
        partial: PartialConfig,
        previous: &Config,
    ) -> (Self, Vec<ConfigProblem>) {
        Self::complete(partial, Some(previous))
    }

    #[cfg(feature = "serde")]
    fn complete(partial: PartialConfig, previous: Option<&Config>) -> (Self, Vec<ConfigProblem>) {
        let mut full = Config::default();
        let mut problems: Vec<ConfigProblem> = Vec::new();
        for (name, tunnel) in partial.tunnels {
            let result = tunnel.into_full().and_then(|(tunnel, endpoint_problem)| {
                full.insert_tunnel(name.as_str(), tunnel)
                    .map(|()| endpoint_problem)
            });
            let (effect, error) = match result {
                Ok(None) => continue,
                Ok(Some(endpoint_problem)) => (ProblemEffect::NoPeer, endpoint_problem),
                Err(error) => {
                    let kept = previous
                        .and_then(|previous| previous.tunnels.get(&name))
                        .is_some_and(|old| full.insert_tunnel(name.as_str(), old.clone()).is_ok());
                    let effect = if kept {
                        ProblemEffect::KeptPrevious
                    } else {
                        ProblemEffect::Rejected
                    };
                    (effect, error)
                }
            };
            problems.push(ConfigProblem::new(EntryKind::Tunnel, &name, effect, error));
        }
        for (name, session) in partial.sessions {
            let result = session.into_full().and_then(|(session, hwaddr_problem)| {
                let tunnel_rejected = problems.iter().any(|p| {
                    p.kind == EntryKind::Tunnel
                        && p.effect == ProblemEffect::Rejected
                        && p.name == session.tunnel_name
                });
                if tunnel_rejected {
                    return Err(Error::InvalidConfig(format!(
                        "its tunnel {} was rejected",
                        session.tunnel_name
                    )));
                }
                full.insert_session(name.as_str(), session)
                    .map(|()| hwaddr_problem)
            });
            let (effect, error) = match result {
                Ok(None) => continue,
                Ok(Some(hwaddr_problem)) => (ProblemEffect::KernelHwAddr, hwaddr_problem),
                Err(error) => {
                    let kept = previous
                        .and_then(|previous| previous.sessions.get(&name))
                        .is_some_and(|old| full.insert_session(name.as_str(), old.clone()).is_ok());
                    let effect = if kept {
                        ProblemEffect::KeptPrevious
                    } else {
                        ProblemEffect::Rejected
                    };
                    (effect, error)
                }
            };
            problems.push(ConfigProblem::new(EntryKind::Session, &name, effect, error));
        }
        (full, problems)
    }

    /// Adds or replaces the tunnel called `name`. Its identifier must not be
    /// in use by a tunnel of another name.
    pub fn insert_tunnel(&mut self, name: impl Into<String>, tunnel: TunnelConfig) -> Result<()> {
        tunnel.validate()?;
        let name = name.into();
        if let Some(other) = self
            .tunnels
            .iter()
            .find(|(other, existing)| **other != name && existing.tunnel_id == tunnel.tunnel_id)
            .map(|(other, _)| other)
        {
            return Err(Error::InvalidConfig(format!(
                "tunnel_id {} is already used by tunnel {other}",
                tunnel.tunnel_id
            )));
        }
        self.tunnels.insert(name, tunnel);
        Ok(())
    }

    /// Adds or replaces the session called `name`, whose tunnel must already
    /// be present. Neither its identifier nor its interface name may be in
    /// use by another session, whatever its tunnel, except by the session
    /// of the same name it replaces: L2TPv3 over IP delivers frames by
    /// session identifier alone, so the kernel keeps them unique per host.
    pub fn insert_session(
        &mut self,
        name: impl Into<String>,
        session: SessionConfig,
    ) -> Result<()> {
        session.validate()?;
        let name = name.into();
        if !self.tunnels.contains_key(&session.tunnel_name) {
            return Err(Error::InvalidConfig(format!(
                "tunnel not defined: {}",
                session.tunnel_name
            )));
        }
        for (other, existing) in &self.sessions {
            if *other == name {
                continue;
            }
            if existing.interface_name == session.interface_name {
                return Err(Error::InvalidConfig(format!(
                    "interface_name {} is already used by session {other}",
                    session.interface_name
                )));
            }
            if existing.session_id == session.session_id {
                return Err(Error::InvalidConfig(format!(
                    "session_id {} is already used by session {other} (L2TPv3 session identifiers are unique per host)",
                    session.session_id
                )));
            }
        }
        self.sessions.insert(name, session);
        Ok(())
    }

    /// The tunnels, by configuration name.
    pub fn tunnels(&self) -> &BTreeMap<String, TunnelConfig> {
        &self.tunnels
    }

    /// The sessions, by configuration name.
    pub fn sessions(&self) -> &BTreeMap<String, SessionConfig> {
        &self.sessions
    }
}

#[cfg(feature = "serde")]
impl TryFrom<PartialConfig> for Config {
    type Error = Error;

    fn try_from(partial: PartialConfig) -> Result<Self> {
        Self::from_partial(partial)
    }
}

/// One L2TPv3-over-IP tunnel.
///
/// Serialised fields: `tunnel_id`, `peer_tunnel_id` (defaults to
/// `tunnel_id`), `remote_addr` (an address or a host name), `ip_version`
/// (optional for a literal address, whose family it then is; required for
/// a host name, as it selects which of its answers are used) and the
/// optional `bind_interface`. A literal address of the other family than
/// an explicit `ip_version`, or one that is not unicast, is an unusable
/// endpoint: an error here and when deserialising strictly, while a lenient
/// conversion keeps the tunnel connected to
/// [`NO_PEER_ADDR`](Self::NO_PEER_ADDR) instead.
///
/// A host name is resolved in the background: the tunnel is first
/// connected to the discard address [`NO_PEER_ADDR`](Self::NO_PEER_ADDR)
/// and moved to the resolved address once known, so its creation needs an
/// IPv6 route covering that address (a default route suffices) but no
/// reachability. A literal address is connected to directly, and creating
/// the tunnel fails (and is retried) until the kernel has a route to it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "PartialTunnelConfig")
)]
pub struct TunnelConfig {
    tunnel_id: u32,
    peer_tunnel_id: u32,
    ip_version: IpVersion,
    remote_addr: IpHost,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "ifname_serde::serialize_option")
    )]
    bind_interface: Option<L2tpIfName>,
}

impl TunnelConfig {
    /// The discard address `100::`, which a tunnel is connected to while it
    /// has no usable peer: before a host name resolves, and in place of an
    /// endpoint a lenient conversion could not use. Frames sent there are
    /// dropped. Connecting to it needs an IPv6 route that covers it but no
    /// reachability; the runtime routes it to a null device of its own on
    /// a host that has none.
    pub const NO_PEER_ADDR: Ipv6Addr = Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0);

    /// A tunnel whose peer uses the same identifier and whose socket is not
    /// bound to a device. A literal `remote_addr` must be of the
    /// `ip_version` family; see [`for_address`](Self::for_address).
    pub fn new(tunnel_id: u32, ip_version: IpVersion, remote_addr: IpHost) -> Self {
        Self {
            tunnel_id,
            peer_tunnel_id: tunnel_id,
            ip_version,
            remote_addr,
            bind_interface: None,
        }
    }

    /// A tunnel to a literal address, whose family is the `ip_version`;
    /// otherwise like [`new`](Self::new).
    pub fn for_address(tunnel_id: u32, remote_addr: IpAddr) -> Self {
        let (ip_version, remote_addr) = match remote_addr {
            IpAddr::V4(addr) => (IpVersion::V4, IpHost::V4Addr(addr)),
            IpAddr::V6(addr) => (IpVersion::V6, IpHost::V6Addr(addr)),
        };
        Self::new(tunnel_id, ip_version, remote_addr)
    }

    /// Sets the identifier the peer uses for this tunnel.
    pub fn with_peer_tunnel_id(mut self, peer_tunnel_id: u32) -> Self {
        self.peer_tunnel_id = peer_tunnel_id;
        self
    }

    /// Binds the tunnel socket to a device (`SO_BINDTODEVICE`), for example
    /// a VRF. The device may appear later; the socket is bound once it does.
    pub fn with_bind_interface(mut self, bind_interface: Option<L2tpIfName>) -> Self {
        self.bind_interface = bind_interface;
        self
    }

    /// The local tunnel identifier.
    pub fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }

    /// The peer's tunnel identifier.
    pub fn peer_tunnel_id(&self) -> u32 {
        self.peer_tunnel_id
    }

    /// The address family the remote endpoint is resolved to.
    pub fn ip_version(&self) -> IpVersion {
        self.ip_version
    }

    /// The remote endpoint, an address or a host name.
    pub fn remote_addr(&self) -> &IpHost {
        &self.remote_addr
    }

    /// The device the tunnel socket is bound to, if any.
    pub fn bind_interface(&self) -> Option<&L2tpIfName> {
        self.bind_interface.as_ref()
    }

    fn validate(&self) -> Result<()> {
        if self.tunnel_id == 0 {
            return Err(Error::InvalidConfig("tunnel_id is zero".to_string()));
        }
        if self.peer_tunnel_id == 0 {
            return Err(Error::InvalidConfig("peer_tunnel_id is zero".to_string()));
        }
        Self::validate_endpoint(self.ip_version, &self.remote_addr)
    }

    /// Checks that a literal `remote_addr` is of the `ip_version` family
    /// and unicast. A host name is checked when it resolves.
    fn validate_endpoint(ip_version: IpVersion, remote_addr: &IpHost) -> Result<()> {
        let addr = match remote_addr {
            IpHost::V4Addr(addr) => IpAddr::V4(*addr),
            IpHost::V6Addr(addr) => IpAddr::V6(*addr),
            IpHost::Fqdn(_) => return Ok(()),
        };
        // A literal of the other family could never be connected to; refuse
        // it here rather than retrying the tunnel forever.
        if let Some(family) = IpVersion::of_literal(remote_addr).filter(|f| *f != ip_version) {
            return Err(Error::InvalidConfig(format!(
                "remote_addr {addr} is {} but ip_version is {}",
                family.describe(),
                ip_version.describe()
            )));
        }
        if !is_usable_remote_addr(addr) {
            return Err(Error::InvalidConfig(format!(
                "remote_addr {addr} is not a unicast address"
            )));
        }
        Ok(())
    }
}

/// One Ethernet pseudowire session, which appears as an `l2tpeth` device.
///
/// Serialised fields: `tunnel_name` (a key of the `tunnels` map),
/// `session_id` (unique on this host, whatever the tunnel: L2TPv3 over IP
/// delivers frames by session identifier alone), `peer_session_id`
/// (defaults to `session_id`), `interface_name`, the optional
/// `interface_hwaddr`, and the optional `cookie` and `peer_cookie`
/// (`peer_cookie` defaults to `cookie`).
///
/// Cookies are off unless configured, which is the only setting an
/// rs-l2tpd 0.1.x peer supports. The kernel cannot change the cookies of an
/// existing session, so changing them re-creates the session and its
/// device. An `interface_hwaddr` that is not a unicast address is an error
/// when deserialising strictly, while a lenient conversion keeps the
/// session with the address the kernel assigns.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "PartialSessionConfig")
)]
pub struct SessionConfig {
    tunnel_name: String,
    session_id: u32,
    peer_session_id: u32,
    #[cfg_attr(feature = "serde", serde(serialize_with = "ifname_serde::serialize"))]
    interface_name: L2tpIfName,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    interface_hwaddr: Option<HwAddr>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    cookie: Option<Cookie>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    peer_cookie: Option<Cookie>,
}

impl SessionConfig {
    /// A session whose peer uses the same identifier, whose device keeps
    /// the hardware address the kernel assigns and which uses no cookies.
    pub fn new(
        tunnel_name: impl Into<String>,
        session_id: u32,
        interface_name: L2tpIfName,
    ) -> Self {
        Self {
            tunnel_name: tunnel_name.into(),
            session_id,
            peer_session_id: session_id,
            interface_name,
            interface_hwaddr: None,
            cookie: None,
            peer_cookie: None,
        }
    }

    /// Uses `cookie` in both directions: it is appended to every frame this
    /// end sends and required in every frame it receives. `None` turns
    /// cookies off, which is the default. The peer must be configured the
    /// same way. See [`with_cookies`](Self::with_cookies) for a pair of
    /// different values.
    pub fn with_cookie(self, cookie: Option<Cookie>) -> Self {
        self.with_cookies(cookie, cookie)
    }

    /// Sets the cookie appended to every frame this end sends (`cookie`)
    /// and the cookie required in every frame it receives (`peer_cookie`)
    /// separately. Each `None` turns that direction off. This end's `cookie`
    /// must be the peer's `peer_cookie` and vice versa.
    pub fn with_cookies(mut self, cookie: Option<Cookie>, peer_cookie: Option<Cookie>) -> Self {
        self.cookie = cookie;
        self.peer_cookie = peer_cookie;
        self
    }

    /// Sets the identifier the peer uses for this session.
    pub fn with_peer_session_id(mut self, peer_session_id: u32) -> Self {
        self.peer_session_id = peer_session_id;
        self
    }

    /// Sets the hardware address of the session's device. `None` leaves the
    /// kernel-assigned address in place, and restores it if the address was
    /// configured before.
    pub fn with_interface_hwaddr(mut self, interface_hwaddr: Option<HwAddr>) -> Self {
        self.interface_hwaddr = interface_hwaddr;
        self
    }

    /// The configuration name of the tunnel the session belongs to.
    pub fn tunnel_name(&self) -> &str {
        &self.tunnel_name
    }

    /// The local session identifier.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// The peer's session identifier.
    pub fn peer_session_id(&self) -> u32 {
        self.peer_session_id
    }

    /// The name of the session's device.
    pub fn interface_name(&self) -> &L2tpIfName {
        &self.interface_name
    }

    /// The configured hardware address of the session's device, if any.
    pub fn interface_hwaddr(&self) -> Option<&HwAddr> {
        self.interface_hwaddr.as_ref()
    }

    /// The cookie appended to every frame this end sends, if any.
    pub fn cookie(&self) -> Option<&Cookie> {
        self.cookie.as_ref()
    }

    /// The cookie required in every frame this end receives, if any.
    pub fn peer_cookie(&self) -> Option<&Cookie> {
        self.peer_cookie.as_ref()
    }

    fn validate(&self) -> Result<()> {
        if self.session_id == 0 {
            return Err(Error::InvalidConfig("session_id is zero".to_string()));
        }
        if self.peer_session_id == 0 {
            return Err(Error::InvalidConfig("peer_session_id is zero".to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_usable_remote_addr, Config, Cookie, HwAddr, IpHost, IpVersion, SessionConfig,
        TunnelConfig,
    };
    use crate::error::Error;
    use l2tp::{L2tpIfName, L2tpIfNameExt};
    use std::net::IpAddr;

    fn hwaddr(s: &str) -> HwAddr {
        s.parse().unwrap()
    }

    fn ifname(s: &str) -> L2tpIfName {
        L2tpIfName::from_name(s).unwrap()
    }

    fn cookie(s: &str) -> Cookie {
        s.parse().unwrap()
    }

    #[test]
    fn cookie_parsing_and_rendering() {
        assert_eq!(cookie("DEADBEEF").as_bytes(), [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(cookie("DEADBEEF").to_string(), "deadbeef");
        assert_eq!(
            cookie("0011223344556677").as_bytes(),
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        );
        assert_eq!(cookie("0011223344556677").to_string(), "0011223344556677");
        assert_eq!(
            cookie("0011223344556677").to_l2tp().as_bytes(),
            cookie("0011223344556677").as_bytes()
        );
        assert_eq!(cookie("deadbeef").to_l2tp().len(), 4);
        for bad in [
            "",
            "deadbee",
            "deadbeefa",
            "deadbeefdead",
            "0x00112233",
            "+eadbeef",
            "-eadbeef",
            "dead beef",
            "zzzzzzzz",
            "00:11:22:33",
            "deadbeef\n",
        ] {
            assert!(bad.parse::<Cookie>().is_err(), "{bad:?}");
        }
        assert!(Cookie::new(&[1, 2, 3]).is_err());
        assert!(Cookie::new(&[]).is_err());
        assert!(Cookie::new(&[0; 16]).is_err());
        assert_eq!(Cookie::new(&[0; 4]).unwrap(), Cookie::from([0; 4]));
        assert_eq!(Cookie::new(&[7; 8]).unwrap(), Cookie::from([7; 8]));
        assert_ne!(Cookie::from([0; 4]), Cookie::from([0; 8]));
        // The value stays out of Debug output.
        assert_eq!(format!("{:?}", cookie("deadbeef")), "Cookie(<4 bytes>)");
        assert_eq!(
            format!("{:?}", cookie("0011223344556677")),
            "Cookie(<8 bytes>)"
        );
    }

    #[test]
    fn cookie_builders() {
        let session = SessionConfig::new("tun0", 100, ifname("l2tp0"));
        assert_eq!(session.cookie(), None);
        assert_eq!(session.peer_cookie(), None);
        let symmetric = session.clone().with_cookie(Some(cookie("deadbeef")));
        assert_eq!(symmetric.cookie(), Some(&cookie("deadbeef")));
        assert_eq!(symmetric.peer_cookie(), Some(&cookie("deadbeef")));
        let asymmetric = symmetric
            .clone()
            .with_cookies(Some(cookie("0011223344556677")), None);
        assert_eq!(asymmetric.cookie(), Some(&cookie("0011223344556677")));
        assert_eq!(asymmetric.peer_cookie(), None);
        assert_eq!(symmetric.with_cookie(None), session);
    }

    #[test]
    fn remote_addr_must_be_unicast() {
        for bad in [
            "::",
            "0.0.0.0",
            "::ffff:0.0.0.0",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "::ffff:255.255.255.255",
        ] {
            let addr: IpAddr = bad.parse().unwrap();
            assert!(!is_usable_remote_addr(addr), "{bad}");
            let version = if addr.is_ipv4() {
                IpVersion::V4
            } else {
                IpVersion::V6
            };
            let err = Config::new()
                .insert_tunnel("tun0", TunnelConfig::new(10, version, bad.parse().unwrap()))
                .unwrap_err();
            assert!(err.to_string().contains("not a unicast address"), "{err}");
        }
        for good in [
            "::1",
            "127.0.0.1",
            "100::",
            "fe80::1",
            "2001:db8::1",
            "192.0.2.1",
        ] {
            let addr: IpAddr = good.parse().unwrap();
            assert!(is_usable_remote_addr(addr), "{good}");
            let version = if addr.is_ipv4() {
                IpVersion::V4
            } else {
                IpVersion::V6
            };
            Config::new()
                .insert_tunnel(
                    "tun0",
                    TunnelConfig::new(10, version, good.parse().unwrap()),
                )
                .unwrap_or_else(|e| panic!("{good}: {e}"));
        }
        // Host names are checked when they resolve, not here.
        Config::new()
            .insert_tunnel(
                "tun0",
                TunnelConfig::new(10, IpVersion::V6, "peer.example.org".parse().unwrap()),
            )
            .unwrap();
    }

    #[test]
    fn literal_remote_addr_must_match_ip_version() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let tunnel = TunnelConfig::for_address(10, v4);
        assert_eq!(tunnel.ip_version(), IpVersion::V4);
        assert_eq!(
            tunnel.remote_addr(),
            &IpHost::V4Addr("192.0.2.1".parse().unwrap())
        );
        assert_eq!(tunnel.peer_tunnel_id(), 10);
        assert_eq!(
            tunnel,
            TunnelConfig::new(10, IpVersion::V4, "192.0.2.1".parse().unwrap())
        );
        assert_eq!(
            TunnelConfig::for_address(10, v6).ip_version(),
            IpVersion::V6
        );
        Config::new()
            .insert_tunnel("tun0", TunnelConfig::for_address(10, v6))
            .unwrap();

        for (ip_version, addr, expected) in [
            (IpVersion::V6, "192.0.2.1", "is IPv4 but ip_version is IPv6"),
            (
                IpVersion::V4,
                "2001:db8::1",
                "is IPv6 but ip_version is IPv4",
            ),
            // An IPv4-mapped literal is written as IPv6 and judged as such.
            (
                IpVersion::V4,
                "::ffff:192.0.2.1",
                "is IPv6 but ip_version is IPv4",
            ),
        ] {
            let err = Config::new()
                .insert_tunnel(
                    "tun0",
                    TunnelConfig::new(10, ip_version, addr.parse().unwrap()),
                )
                .unwrap_err();
            assert!(err.to_string().contains(expected), "{addr}: {err}");
        }
        // Host names take either family.
        for ip_version in [IpVersion::V4, IpVersion::V6] {
            Config::new()
                .insert_tunnel(
                    "tun0",
                    TunnelConfig::new(10, ip_version, "peer.example.org".parse().unwrap()),
                )
                .unwrap();
        }
    }

    #[test]
    fn config_rejects_duplicate_ids_and_interface_names() {
        let mut config = Config::new();
        let tunnel = |id: u32| TunnelConfig::for_address(id, "2001:db8::1".parse().unwrap());
        config.insert_tunnel("a", tunnel(10)).unwrap();
        let err = config.insert_tunnel("b", tunnel(10)).unwrap_err();
        assert!(
            err.to_string()
                .contains("tunnel_id 10 is already used by tunnel a"),
            "{err}"
        );
        // Replacing a tunnel under its own name is fine, with any identifier.
        config.insert_tunnel("a", tunnel(10)).unwrap();
        config.insert_tunnel("a", tunnel(12)).unwrap();
        config.insert_tunnel("b", tunnel(10)).unwrap();

        let session =
            |tunnel: &str, id: u32, name: &str| SessionConfig::new(tunnel, id, ifname(name));
        config
            .insert_session("s0", session("a", 100, "l2tp0"))
            .unwrap();
        let err = config
            .insert_session("s1", session("b", 100, "l2tp0"))
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("interface_name l2tp0 is already used by session s0"),
            "{err}"
        );
        // Session identifiers are unique per host, not per tunnel.
        for tunnel in ["a", "b"] {
            let err = config
                .insert_session("s1", session(tunnel, 100, "l2tp1"))
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("session_id 100 is already used by session s0"),
                "{err}"
            );
        }
        // Another identifier on another tunnel, and replacing s0 itself,
        // are fine.
        config
            .insert_session("s1", session("b", 101, "l2tp1"))
            .unwrap();
        config
            .insert_session("s0", session("a", 100, "l2tp0"))
            .unwrap();
        config
            .insert_session("s0", session("a", 102, "l2tp9"))
            .unwrap();
        assert_eq!(config.sessions().len(), 2);
    }

    #[test]
    fn hwaddr_parsing_and_rendering() {
        assert_eq!(hwaddr("02-00-5e-00-53-01").to_string(), "02:00:5e:00:53:01");
        assert_eq!(
            hwaddr("AA:BB:CC:DD:EE:FF").octets(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert!(hwaddr("02:00:5e:00:53:01").is_local());
        for bad in [
            "",
            "02:00:5e:00:53",
            "02:00:5e:00:53:01:02",
            "02:00:5e:00:53:0g",
            "2:0:5e:0:53:1",
            "01:00:5e:00:53:01",
            "ff:ff:ff:ff:ff:ff",
            "00:00:00:00:00:00",
        ] {
            assert!(bad.parse::<HwAddr>().is_err(), "{bad}");
        }
        assert!(HwAddr::from_kernel(&[0x02, 0, 0x5e, 0, 0x53, 1]).is_some());
        assert!(HwAddr::from_kernel(&[0; 6]).is_none());
        assert!(HwAddr::from_kernel(&[0x02, 0, 0x5e, 0]).is_none());
    }

    #[test]
    fn builders_apply_defaults_and_validate() {
        let tunnel = TunnelConfig::new(10, IpVersion::V6, "2001:db8::1".parse().unwrap());
        assert_eq!(tunnel.peer_tunnel_id(), 10);
        assert_eq!(tunnel.bind_interface(), None);
        let tunnel = tunnel
            .with_peer_tunnel_id(11)
            .with_bind_interface(Some(ifname("vrf0")));
        assert_eq!(tunnel.peer_tunnel_id(), 11);
        assert_eq!(tunnel.bind_interface(), Some(&ifname("vrf0")));

        let session = SessionConfig::new("tun0", 100, ifname("l2tp0"));
        assert_eq!(session.peer_session_id(), 100);
        assert_eq!(session.interface_hwaddr(), None);
        let session = session
            .with_peer_session_id(101)
            .with_interface_hwaddr(Some(hwaddr("02:00:5e:00:53:01")));
        assert_eq!(session.peer_session_id(), 101);
        assert_eq!(
            session.interface_hwaddr(),
            Some(&hwaddr("02:00:5e:00:53:01"))
        );

        let mut config = Config::new();
        let zero = TunnelConfig::new(0, IpVersion::V4, "192.0.2.1".parse().unwrap());
        assert!(matches!(
            config.insert_tunnel("tun0", zero),
            Err(Error::InvalidConfig(_))
        ));
        let bad_peer = tunnel.clone().with_peer_tunnel_id(0);
        assert!(config.insert_tunnel("tun0", bad_peer).is_err());
        // Sessions need their tunnel first.
        let err = config.insert_session("sess0", session.clone()).unwrap_err();
        assert!(err.to_string().contains("tunnel not defined"), "{err}");
        config.insert_tunnel("tun0", tunnel).unwrap();
        assert!(config
            .insert_session("sess0", session.clone().with_peer_session_id(0))
            .is_err());
        assert!(config
            .insert_session("sess0", SessionConfig::new("tun0", 0, ifname("l2tp0")))
            .is_err());
        config.insert_session("sess0", session).unwrap();
        assert_eq!(config.tunnels().len(), 1);
        assert_eq!(config.sessions()["sess0"].tunnel_name(), "tun0");
    }

    // The serde tests use TOML as one format; the library assumes none.
    #[cfg(feature = "bin")]
    mod serde {
        use super::{cookie, hwaddr, ifname, Config, Error, IpHost, IpVersion, TunnelConfig};
        use crate::config::{EntryKind, PartialConfig, ProblemEffect};

        const VALID: &str = r#"
[tunnels.tun0]
tunnel_id = 10
ip_version = "v6"
remote_addr = "2001:db8::1"
bind_interface = "vrf0"

[sessions.sess0]
tunnel_name = "tun0"
session_id = 100
interface_name = "l2tp0"
interface_hwaddr = "02:00:5E:00:53:01"
"#;

        fn partial(toml: &str) -> Result<PartialConfig, Error> {
            toml::from_str(toml).map_err(|e| Error::InvalidConfig(e.to_string()))
        }

        fn full(toml: &str) -> Result<Config, Error> {
            partial(toml)?.into_config()
        }

        fn render(config: &Config) -> String {
            toml::to_string_pretty(config).expect("render config")
        }

        #[test]
        fn parses_interface_names_into_checked_type() {
            let config = full(VALID).unwrap();
            assert_eq!(
                config.tunnels()["tun0"].bind_interface(),
                Some(&ifname("vrf0"))
            );
            assert_eq!(
                config.sessions()["sess0"].interface_name(),
                &ifname("l2tp0")
            );
            assert_eq!(
                config.sessions()["sess0"].interface_hwaddr(),
                Some(&hwaddr("02:00:5e:00:53:01"))
            );
        }

        #[test]
        fn rejects_invalid_interface_name_after_merging() {
            for bad in [
                "this-interface-name-is-way-too-long",
                "",
                "with space",
                "a/b",
                "a:b",
                ".",
            ] {
                let toml = VALID.replace("\"l2tp0\"", &format!("{bad:?}"));
                let err = partial(&toml).unwrap().into_config().expect_err(bad);
                assert!(matches!(err, Error::InvalidConfig(_)), "{bad}: {err}");
                assert!(toml::from_str::<Config>(&toml).is_err(), "{bad}");

                let toml = VALID.replace("\"vrf0\"", &format!("{bad:?}"));
                let err = partial(&toml).unwrap().into_config().expect_err(bad);
                assert!(matches!(err, Error::InvalidConfig(_)), "{bad}: {err}");
                assert!(toml::from_str::<Config>(&toml).is_err(), "{bad}");
            }
        }

        #[test]
        fn later_documents_replace_invalid_interface_placeholders() {
            for placeholder in ["", "this-interface-name-is-way-too-long", "a b", "a/b"] {
                let base = VALID
                    .replace("\"l2tp0\"", &format!("{placeholder:?}"))
                    .replace("\"vrf0\"", &format!("{placeholder:?}"));
                let mut merged = partial(&base).expect("parse base placeholders");
                merged.merge(
                    partial(
                        "[sessions.sess0]\ninterface_name = \"l2tp9\"\n\
                         [tunnels.tun0]\nbind_interface = \"vrf1\"\n",
                    )
                    .unwrap(),
                );
                let config = merged.into_config().expect("validate overridden names");
                assert_eq!(
                    config.sessions()["sess0"].interface_name(),
                    &ifname("l2tp9")
                );
                assert_eq!(
                    config.tunnels()["tun0"].bind_interface(),
                    Some(&ifname("vrf1"))
                );
            }

            // A bad final override still fails, even if the base was valid.
            for invalid in [
                "[sessions.sess0]\ninterface_name = \"\"\n",
                "[tunnels.tun0]\nbind_interface = \"a/b\"\n",
            ] {
                let mut merged = partial(VALID).unwrap();
                merged.merge(partial(invalid).unwrap());
                assert!(merged.into_config().is_err());
            }
        }

        #[test]
        fn invalid_values_reject_only_their_entry() {
            // A bad value is a validation error of its entry, not a parse
            // error of the whole document. A bad hardware address does not
            // even reject the session: the kernel's address is used.
            let bad_hwaddr = VALID.replace("\"02:00:5E:00:53:01\"", "\"01:00:5e:00:53:01\"");
            let err = partial(&bad_hwaddr).unwrap().into_config().unwrap_err();
            assert!(
                err.to_string()
                    .contains("session sess0: interface_hwaddr: hardware address"),
                "{err}"
            );
            assert!(toml::from_str::<Config>(&bad_hwaddr).is_err());
            let (config, problems) = partial(&bad_hwaddr).unwrap().into_config_lenient();
            assert_eq!(config.tunnels().len(), 1);
            assert_eq!(config.sessions()["sess0"].interface_hwaddr(), None);
            assert_eq!(config.sessions()["sess0"].tunnel_name(), "tun0");
            assert_eq!(problems.len(), 1);
            assert_eq!(problems[0].kind(), EntryKind::Session);
            assert_eq!(problems[0].name(), "sess0");
            assert_eq!(problems[0].effect(), ProblemEffect::KernelHwAddr);
            assert!(matches!(problems[0].error(), Error::InvalidConfig(_)));
            for bad in ["\"\"", "\"02:00:5e:00:53\"", "\"zz:00:5e:00:53:01\""] {
                let toml = VALID.replace("\"02:00:5E:00:53:01\"", bad);
                let (config, problems) = partial(&toml).unwrap().into_config_lenient();
                assert_eq!(config.sessions()["sess0"].interface_hwaddr(), None, "{bad}");
                assert_eq!(problems.len(), 1, "{bad}");
                assert_eq!(problems[0].effect(), ProblemEffect::KernelHwAddr, "{bad}");
                assert!(
                    problems[0]
                        .to_string()
                        .starts_with("session sess0: interface_hwaddr: invalid hardware address"),
                    "{bad}: {}",
                    problems[0]
                );
            }
            // A session rejected for another reason stays rejected.
            let rejected = bad_hwaddr.replace("session_id = 100", "session_id = 0");
            let (config, problems) = partial(&rejected).unwrap().into_config_lenient();
            assert!(config.sessions().is_empty());
            assert_eq!(problems.len(), 1);
            assert_eq!(problems[0].effect(), ProblemEffect::Rejected);

            for (replace, with, expected) in [
                ("\"v6\"", "\"v5\"", "tunnel tun0: invalid ip_version \"v5\""),
                (
                    "\"2001:db8::1\"",
                    "\"not a host!\"",
                    "tunnel tun0: remote_addr \"not a host!\": ",
                ),
                ("\"vrf0\"", "\"a/b\"", "tunnel tun0: bind_interface: "),
                ("\"l2tp0\"", "\"a/b\"", "session sess0: interface_name: "),
            ] {
                let toml = VALID.replace(replace, with);
                let err = partial(&toml).unwrap().into_config().unwrap_err();
                assert!(err.to_string().contains(expected), "{expected}: {err}");
            }
        }

        #[test]
        fn lenient_conversion_keeps_valid_entries_and_reports_the_rest() {
            let toml = "\
[tunnels.alpha]
tunnel_id = 10
remote_addr = \"2001:db8::1\"

[tunnels.beta]
tunnel_id = 11
ip_version = \"V6\"
remote_addr = \"192.0.2.1\"

[tunnels.gamma]
tunnel_id = 10
remote_addr = \"2001:db8::2\"

[sessions.on-alpha]
tunnel_name = \"alpha\"
session_id = 100
interface_name = \"l2tp0\"

[sessions.on-beta]
tunnel_name = \"beta\"
session_id = 103
interface_name = \"l2tp1\"

[sessions.on-gamma]
tunnel_name = \"gamma\"
session_id = 100
interface_name = \"l2tp2\"

[sessions.orphan]
tunnel_name = \"nope\"
session_id = 102
interface_name = \"l2tp4\"

[sessions.same-id]
tunnel_name = \"alpha\"
session_id = 100
interface_name = \"l2tp3\"

[sessions.same-iface]
tunnel_name = \"alpha\"
session_id = 101
interface_name = \"l2tp0\"
";
            let (config, problems) = partial(toml).unwrap().into_config_lenient();
            // The unusable endpoint keeps its tunnel, and the session on it.
            assert_eq!(
                config.tunnels().keys().collect::<Vec<_>>(),
                vec!["alpha", "beta"]
            );
            assert_eq!(
                config.sessions().keys().collect::<Vec<_>>(),
                vec!["on-alpha", "on-beta"]
            );
            assert_eq!(
                config.tunnels()["beta"].remote_addr(),
                &IpHost::V6Addr(TunnelConfig::NO_PEER_ADDR)
            );
            assert_eq!(config.tunnels()["beta"].ip_version(), IpVersion::V6);
            let messages: Vec<String> = problems.iter().map(ToString::to_string).collect();
            assert_eq!(
                messages,
                [
                    "tunnel beta: remote_addr 192.0.2.1 is IPv4 but ip_version is IPv6",
                    "tunnel gamma: tunnel_id 10 is already used by tunnel alpha",
                    "session on-gamma: its tunnel gamma was rejected",
                    "session orphan: tunnel not defined: nope",
                    "session same-id: session_id 100 is already used by session on-alpha (L2TPv3 session identifiers are unique per host)",
                    "session same-iface: interface_name l2tp0 is already used by session on-alpha",
                ]
            );
            let effects: Vec<ProblemEffect> = problems.iter().map(|p| p.effect()).collect();
            assert_eq!(
                effects,
                [
                    ProblemEffect::NoPeer,
                    ProblemEffect::Rejected,
                    ProblemEffect::Rejected,
                    ProblemEffect::Rejected,
                    ProblemEffect::Rejected,
                    ProblemEffect::Rejected,
                ]
            );
            assert!(problems
                .iter()
                .all(|p| std::error::Error::source(p).is_some()));
            assert_eq!(problems[0].kind(), EntryKind::Tunnel);
            assert_eq!(problems[2].kind(), EntryKind::Session);

            // The strict conversion reports the first problem, whatever
            // its effect.
            let err = partial(toml).unwrap().into_config().unwrap_err();
            assert_eq!(
                err.to_string(),
                "invalid config: tunnel beta: remote_addr 192.0.2.1 is IPv4 but ip_version is IPv6"
            );
            assert!(toml::from_str::<Config>(toml).is_err());

            // Nothing wrong, no problems.
            let (config, problems) = partial(VALID).unwrap().into_config_lenient();
            assert_eq!(config, full(VALID).unwrap());
            assert!(problems.is_empty());

            // Nothing usable is still a valid, empty configuration.
            let (config, problems) =
                partial("[tunnels.hard]\ntunnel_id = 0\nremote_addr = \"::1\"\n")
                    .unwrap()
                    .into_config_lenient();
            assert_eq!(config, Config::new());
            assert_eq!(problems.len(), 1);
        }

        #[test]
        fn previous_values_replace_entries_that_would_be_rejected() {
            let previous = full(
                "\
[tunnels.a]
tunnel_id = 10
remote_addr = \"2001:db8::1\"

[tunnels.b]
tunnel_id = 11
remote_addr = \"2001:db8::2\"

[sessions.s-a]
tunnel_name = \"a\"
session_id = 100
interface_name = \"l2tp0\"

[sessions.s-b]
tunnel_name = \"b\"
session_id = 101
interface_name = \"l2tp1\"
",
            )
            .unwrap();
            // a changes validly; b and s-b break; c and s-c are new and broken.
            let reload = "\
[tunnels.a]
tunnel_id = 10
remote_addr = \"2001:db8::9\"

[tunnels.b]
tunnel_id = 0
remote_addr = \"2001:db8::2\"

[tunnels.c]
tunnel_id = 0
remote_addr = \"2001:db8::3\"

[sessions.s-a]
tunnel_name = \"a\"
session_id = 100
interface_name = \"l2tp0\"

[sessions.s-b]
tunnel_name = \"b\"
session_id = 101
interface_name = \"a/b\"

[sessions.s-c]
tunnel_name = \"c\"
session_id = 102
interface_name = \"l2tp2\"
";
            let (config, problems) = partial(reload)
                .unwrap()
                .into_config_with_previous(&previous);
            assert_eq!(
                config.tunnels()["a"].remote_addr(),
                &IpHost::V6Addr("2001:db8::9".parse().unwrap())
            );
            assert_eq!(config.tunnels()["b"], previous.tunnels()["b"]);
            assert!(!config.tunnels().contains_key("c"));
            assert_eq!(config.sessions()["s-a"], previous.sessions()["s-a"]);
            assert_eq!(config.sessions()["s-b"], previous.sessions()["s-b"]);
            assert!(!config.sessions().contains_key("s-c"));
            let effects: Vec<ProblemEffect> = problems.iter().map(|p| p.effect()).collect();
            assert_eq!(
                effects,
                [
                    ProblemEffect::KeptPrevious,
                    ProblemEffect::Rejected,
                    ProblemEffect::KeptPrevious,
                    ProblemEffect::Rejected,
                ]
            );
            assert_eq!(problems[0].to_string(), "tunnel b: tunnel_id is zero");
            assert_eq!(problems[1].to_string(), "tunnel c: tunnel_id is zero");
            assert!(
                problems[2]
                    .to_string()
                    .starts_with("session s-b: interface_name: "),
                "{}",
                problems[2]
            );
            assert_eq!(
                problems[3].to_string(),
                "session s-c: its tunnel c was rejected"
            );

            // Without a previous configuration every such entry is rejected.
            let (config, problems) = partial(reload).unwrap().into_config_lenient();
            assert_eq!(config.tunnels().keys().collect::<Vec<_>>(), vec!["a"]);
            assert_eq!(config.sessions().keys().collect::<Vec<_>>(), vec!["s-a"]);
            assert!(problems
                .iter()
                .all(|p| p.effect() == ProblemEffect::Rejected));

            // When a takes b's old identifier, b's previous values no longer
            // fit, and s-b has no tunnel to fall back on either.
            let conflict = reload.replace("tunnel_id = 10", "tunnel_id = 11");
            let (config, problems) = partial(&conflict)
                .unwrap()
                .into_config_with_previous(&previous);
            assert_eq!(config.tunnels().keys().collect::<Vec<_>>(), vec!["a"]);
            assert_eq!(config.tunnels()["a"].tunnel_id(), 11);
            assert_eq!(config.sessions().keys().collect::<Vec<_>>(), vec!["s-a"]);
            assert_eq!(problems[0].to_string(), "tunnel b: tunnel_id is zero");
            assert_eq!(problems[0].effect(), ProblemEffect::Rejected);
            // s-b is reported for its own mistake; its previous values do
            // not fit either, their tunnel being gone.
            assert!(
                problems[2]
                    .to_string()
                    .starts_with("session s-b: interface_name: "),
                "{}",
                problems[2]
            );
            assert_eq!(problems[2].effect(), ProblemEffect::Rejected);

            // Tolerated problems are unaffected by a previous configuration.
            let soft = reload
                .replace(
                    "tunnel_id = 0\nremote_addr = \"2001:db8::2\"",
                    "tunnel_id = 11\nremote_addr = \"::\"",
                )
                .replace(
                    "interface_name = \"a/b\"",
                    "interface_name = \"l2tp1\"\ninterface_hwaddr = \"nope\"",
                );
            let (config, problems) = partial(&soft).unwrap().into_config_with_previous(&previous);
            assert_eq!(
                config.tunnels()["b"].remote_addr(),
                &IpHost::V6Addr(TunnelConfig::NO_PEER_ADDR)
            );
            assert_eq!(config.sessions()["s-b"].interface_hwaddr(), None);
            assert_eq!(problems[0].effect(), ProblemEffect::NoPeer);
            assert_eq!(problems[2].effect(), ProblemEffect::KernelHwAddr);
        }

        #[test]
        fn unusable_endpoints_keep_the_tunnel_without_a_peer() {
            let cases: [(&str, &str, &str); 7] = [
                (
                    "remote_addr = \"2001:db8::1\"\n",
                    "",
                    "tunnel tun0: remote_addr is missing",
                ),
                (
                    "\"2001:db8::1\"",
                    "\"not a host!\"",
                    "tunnel tun0: remote_addr \"not a host!\": ",
                ),
                ("\"v6\"", "\"v5\"", "tunnel tun0: invalid ip_version \"v5\""),
                (
                    "ip_version = \"v6\"\nremote_addr = \"2001:db8::1\"\n",
                    "remote_addr = \"peer.example.org\"\n",
                    "tunnel tun0: ip_version is missing",
                ),
                (
                    "\"2001:db8::1\"",
                    "\"ff02::1\"",
                    "tunnel tun0: remote_addr ff02::1 is not a unicast address",
                ),
                (
                    "\"2001:db8::1\"",
                    "\"192.0.2.1\"",
                    "tunnel tun0: remote_addr 192.0.2.1 is IPv4 but ip_version is IPv6",
                ),
                (
                    "ip_version = \"v6\"\nremote_addr = \"2001:db8::1\"\n",
                    "ip_version = \"v4\"\nremote_addr = \"::\"\n",
                    "tunnel tun0: remote_addr :: is IPv6 but ip_version is IPv4",
                ),
            ];
            for (replace, with, expected) in cases {
                let toml = VALID.replace(replace, with);
                let (config, problems) = partial(&toml).unwrap().into_config_lenient();
                assert_eq!(problems.len(), 1, "{expected}: {problems:?}");
                assert_eq!(problems[0].kind(), EntryKind::Tunnel, "{expected}");
                assert_eq!(problems[0].effect(), ProblemEffect::NoPeer, "{expected}");
                assert!(
                    problems[0].to_string().starts_with(expected),
                    "{expected}: {}",
                    problems[0]
                );
                let tunnel = &config.tunnels()["tun0"];
                assert_eq!(
                    tunnel.remote_addr(),
                    &IpHost::V6Addr(TunnelConfig::NO_PEER_ADDR),
                    "{expected}"
                );
                assert_eq!(tunnel.ip_version(), IpVersion::V6);
                assert_eq!(tunnel.bind_interface(), Some(&ifname("vrf0")));
                assert_eq!(config.sessions()["sess0"].tunnel_name(), "tun0");
                // Strictly it is an error like any other.
                let err = partial(&toml).unwrap().into_config().unwrap_err();
                assert!(err.to_string().contains(expected), "{expected}: {err}");
                assert!(toml::from_str::<Config>(&toml).is_err(), "{expected}");
            }
        }

        #[test]
        fn ip_version_accepts_both_spellings_and_renders_upper_case() {
            for spelling in ["v4", "V4"] {
                let toml = VALID
                    .replace("\"v6\"", &format!("{spelling:?}"))
                    .replace("\"2001:db8::1\"", "\"192.0.2.1\"");
                let config = full(&toml).unwrap();
                assert_eq!(config.tunnels()["tun0"].ip_version(), IpVersion::V4);
                assert!(render(&config).contains("ip_version = \"V4\""));
            }
            assert_eq!("v6".parse::<IpVersion>().unwrap(), IpVersion::V6);
            assert_eq!("V6".parse::<IpVersion>().unwrap(), IpVersion::V6);
            for bad in ["v5", "ipv4", "4", ""] {
                let err = bad.parse::<IpVersion>().unwrap_err();
                assert!(
                    err.to_string().contains("invalid ip_version"),
                    "{bad}: {err}"
                );
            }
        }

        #[test]
        fn optional_fields_may_be_omitted() {
            let toml = VALID
                .replace("bind_interface = \"vrf0\"\n", "")
                .replace("interface_hwaddr = \"02:00:5E:00:53:01\"\n", "");
            let config = full(&toml).unwrap();
            assert_eq!(config.tunnels()["tun0"].bind_interface(), None);
            assert_eq!(config.sessions()["sess0"].interface_hwaddr(), None);
            assert_eq!(config.tunnels()["tun0"].peer_tunnel_id(), 10);
            assert_eq!(config.sessions()["sess0"].peer_session_id(), 100);
        }

        #[test]
        fn rejects_zero_ids_and_unknown_tunnels() {
            assert!(full(&VALID.replace("tunnel_id = 10", "tunnel_id = 0")).is_err());
            assert!(full(&VALID.replace("session_id = 100", "session_id = 0")).is_err());
            assert!(full(
                &VALID.replace("session_id = 100", "session_id = 100\npeer_session_id = 0")
            )
            .is_err());
            let err = full(&VALID.replace("tunnel_name = \"tun0\"", "tunnel_name = \"nope\""))
                .unwrap_err();
            assert!(err.to_string().contains("tunnel not defined"), "{err}");
        }

        #[test]
        fn rendering_round_trips() {
            let config = full(VALID).unwrap();
            let rendered = render(&config);
            assert!(rendered.contains("bind_interface = \"vrf0\""));
            assert!(rendered.contains("interface_name = \"l2tp0\""));
            assert!(rendered.contains("interface_hwaddr = \"02:00:5e:00:53:01\""));

            // Deserialising a Config directly runs the full validation.
            let reparsed: Config = toml::from_str(&rendered).expect("reparse rendered config");
            assert_eq!(reparsed, config);
            assert!(
                toml::from_str::<Config>(&VALID.replace("tunnel_id = 10", "tunnel_id = 0"))
                    .is_err()
            );

            let unbound = full(
                &VALID
                    .replace("bind_interface = \"vrf0\"\n", "")
                    .replace("interface_hwaddr = \"02:00:5E:00:53:01\"\n", ""),
            )
            .unwrap();
            let rendered = render(&unbound);
            assert!(!rendered.contains("bind_interface"));
            assert!(!rendered.contains("interface_hwaddr"));
        }

        #[test]
        fn merge_overrides_fields() {
            let mut base = partial(VALID).unwrap();
            let dropin = partial(
                "[sessions.sess0]\ninterface_name = \"l2tp9\"\ninterface_hwaddr = \"02:00:5e:00:53:02\"\n[tunnels.tun0]\nbind_interface = \"vrf1\"\n",
            )
            .unwrap();
            base.merge(dropin);
            let config = base.into_config().unwrap();
            assert_eq!(
                config.sessions()["sess0"].interface_name(),
                &ifname("l2tp9")
            );
            assert_eq!(
                config.sessions()["sess0"].interface_hwaddr(),
                Some(&hwaddr("02:00:5e:00:53:02"))
            );
            assert_eq!(
                config.tunnels()["tun0"].bind_interface(),
                Some(&ifname("vrf1"))
            );
        }

        #[test]
        fn empty_document_yields_empty_config() {
            assert_eq!(full("").unwrap(), Config::new());
            assert_eq!(full("[tunnels]\n[sessions]\n").unwrap(), Config::new());
        }

        #[test]
        fn cookies_are_optional_and_peer_cookie_defaults_to_cookie() {
            let config = full(VALID).unwrap();
            assert_eq!(config.sessions()["sess0"].cookie(), None);
            assert_eq!(config.sessions()["sess0"].peer_cookie(), None);
            assert!(!render(&config).contains("cookie"));

            let symmetric = full(&format!("{VALID}cookie = \"0011223344556677\"\n")).unwrap();
            let session = &symmetric.sessions()["sess0"];
            assert_eq!(session.cookie(), Some(&cookie("0011223344556677")));
            assert_eq!(session.peer_cookie(), Some(&cookie("0011223344556677")));

            let asymmetric = full(&format!(
                "{VALID}cookie = \"DEADBEEF\"\npeer_cookie = \"8899aabbccddeeff\"\n"
            ))
            .unwrap();
            let session = &asymmetric.sessions()["sess0"];
            assert_eq!(session.cookie(), Some(&cookie("deadbeef")));
            assert_eq!(session.peer_cookie(), Some(&cookie("8899aabbccddeeff")));

            let receive_only = full(&format!("{VALID}peer_cookie = \"deadbeef\"\n")).unwrap();
            let session = &receive_only.sessions()["sess0"];
            assert_eq!(session.cookie(), None);
            assert_eq!(session.peer_cookie(), Some(&cookie("deadbeef")));

            // Rendering keeps both values and round-trips.
            let rendered = render(&asymmetric);
            assert!(rendered.contains("cookie = \"deadbeef\""));
            assert!(rendered.contains("peer_cookie = \"8899aabbccddeeff\""));
            let reparsed: Config = toml::from_str(&rendered).unwrap();
            assert_eq!(reparsed, asymmetric);

            // A drop-in overrides one value and the other keeps its default.
            let mut merged = partial(&format!("{VALID}cookie = \"deadbeef\"\n")).unwrap();
            merged
                .merge(partial("[sessions.sess0]\npeer_cookie = \"0011223344556677\"\n").unwrap());
            let session = merged.into_config().unwrap();
            let session = &session.sessions()["sess0"];
            assert_eq!(session.cookie(), Some(&cookie("deadbeef")));
            assert_eq!(session.peer_cookie(), Some(&cookie("0011223344556677")));
        }

        #[test]
        fn rejects_invalid_cookies() {
            // A value of the wrong type fails the document; a wrong value
            // fails only its entry.
            for bad in ["1234", "[1, 2]"] {
                for key in ["cookie", "peer_cookie"] {
                    let toml = format!("{VALID}{key} = {bad}\n");
                    assert!(
                        matches!(partial(&toml), Err(Error::InvalidConfig(_))),
                        "{key} = {bad}"
                    );
                    assert!(toml::from_str::<Config>(&toml).is_err(), "{key} = {bad}");
                }
            }
            for bad in ["\"\"", "\"deadbee\"", "\"0x00112233\"", "\"+eadbeef\""] {
                for key in ["cookie", "peer_cookie"] {
                    let toml = format!("{VALID}{key} = {bad}\n");
                    let err = partial(&toml).unwrap().into_config().unwrap_err();
                    assert!(
                        err.to_string()
                            .contains(&format!("session sess0: {key}: invalid cookie")),
                        "{key} = {bad}: {err}"
                    );
                    assert!(toml::from_str::<Config>(&toml).is_err(), "{key} = {bad}");
                }
            }
        }

        #[test]
        fn ip_version_is_optional_for_literal_addresses_only() {
            let without = |addr: &str| {
                VALID
                    .replace("ip_version = \"v6\"\n", "")
                    .replace("\"2001:db8::1\"", &format!("{addr:?}"))
            };
            let config = full(&without("2001:db8::1")).unwrap();
            assert_eq!(config.tunnels()["tun0"].ip_version(), IpVersion::V6);
            let config = full(&without("192.0.2.1")).unwrap();
            assert_eq!(config.tunnels()["tun0"].ip_version(), IpVersion::V4);
            assert!(render(&config).contains("ip_version = \"V4\""));
            let config: Config = toml::from_str(&without("192.0.2.1")).unwrap();
            assert_eq!(config.tunnels()["tun0"].ip_version(), IpVersion::V4);

            let err = full(&without("peer.example.org")).unwrap_err();
            assert!(err.to_string().contains("ip_version is missing"), "{err}");
            assert!(toml::from_str::<Config>(&without("peer.example.org")).is_err());

            // A drop-in may supply the family, or the address that implies it.
            let mut merged = partial(&without("peer.example.org")).unwrap();
            merged.merge(partial("[tunnels.tun0]\nip_version = \"v4\"\n").unwrap());
            assert_eq!(
                merged.into_config().unwrap().tunnels()["tun0"].ip_version(),
                IpVersion::V4
            );
            let mut merged = partial(&without("peer.example.org")).unwrap();
            merged.merge(partial("[tunnels.tun0]\nremote_addr = \"192.0.2.1\"\n").unwrap());
            assert_eq!(
                merged.into_config().unwrap().tunnels()["tun0"].ip_version(),
                IpVersion::V4
            );
        }

        #[test]
        fn rejects_literal_remote_addrs_of_the_other_family() {
            for (version, addr) in [("v6", "192.0.2.1"), ("v4", "2001:db8::1")] {
                let toml = VALID
                    .replace("\"v6\"", &format!("{version:?}"))
                    .replace("\"2001:db8::1\"", &format!("{addr:?}"));
                let err = full(&toml).unwrap_err();
                assert!(
                    err.to_string().contains("but ip_version is"),
                    "{addr}: {err}"
                );
                assert!(toml::from_str::<Config>(&toml).is_err(), "{addr}");
            }
        }

        #[test]
        fn standalone_tunnel_and_session_documents_get_the_same_defaults() {
            let tunnel: super::super::TunnelConfig =
                toml::from_str("tunnel_id = 10\nremote_addr = \"192.0.2.1\"\n").unwrap();
            assert_eq!(tunnel.peer_tunnel_id(), 10);
            assert_eq!(tunnel.ip_version(), IpVersion::V4);
            assert_eq!(tunnel.bind_interface(), None);
            assert!(toml::from_str::<super::super::TunnelConfig>(
                "tunnel_id = 10\nremote_addr = \"peer.example.org\"\n"
            )
            .is_err());
            assert!(toml::from_str::<super::super::TunnelConfig>(
                "tunnel_id = 10\nip_version = \"v4\"\nremote_addr = \"2001:db8::1\"\n"
            )
            .is_err());

            let session: super::super::SessionConfig = toml::from_str(
                "tunnel_name = \"tun0\"\nsession_id = 100\ninterface_name = \"l2tp0\"\ncookie = \"deadbeef\"\n",
            )
            .unwrap();
            assert_eq!(session.peer_session_id(), 100);
            assert_eq!(session.peer_cookie(), Some(&cookie("deadbeef")));
            assert!(toml::from_str::<super::super::SessionConfig>(
                "tunnel_name = \"tun0\"\nsession_id = 100\ninterface_name = \"a/b\"\n"
            )
            .is_err());
        }

        #[test]
        fn rejects_non_unicast_literal_remote_addrs() {
            for (version, bad) in [("v6", "::"), ("v6", "ff02::1"), ("v4", "0.0.0.0")] {
                let toml = VALID
                    .replace("\"v6\"", &format!("{version:?}"))
                    .replace("\"2001:db8::1\"", &format!("{bad:?}"));
                let err = full(&toml).unwrap_err();
                assert!(
                    err.to_string().contains("not a unicast address"),
                    "{bad}: {err}"
                );
                assert!(toml::from_str::<Config>(&toml).is_err(), "{bad}");
            }
        }
    }
}
