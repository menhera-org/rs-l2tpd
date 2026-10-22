//! Desired configuration: tunnels and the sessions riding on them.
//!
//! A [`Config`] is validated as a whole: identifiers are non-zero, every
//! session names a tunnel that exists, interface names satisfy the kernel's
//! rules and hardware addresses are unicast. It is built in code with
//! [`Config::new`] and the `insert_*` methods or, with the `serde` feature,
//! deserialised from any format (deserialising runs the same validation).
//! This module does no I/O and assumes no serialisation format: the daemon
//! binary reads its TOML files and feeds the documents in as
//! [`PartialConfig`] values.
//!
//! The serialised shape is a `tunnels` map and a `sessions` map, each keyed
//! by a configuration name; see [`TunnelConfig`] and [`SessionConfig`] for
//! the fields. Several documents can be merged field by field with
//! [`PartialConfig::merge`], later ones overriding earlier ones, which is
//! how the daemon layers its drop-in directory over its main file.

use std::{collections::BTreeMap, fmt, str::FromStr};

use crate::error::{Error, Result};
use iphost::IpHost;
use l2tp::L2tpIfName;

/// Serde adapter for interface names: documents carry them as strings, and a
/// name the kernel would reject is refused while the document is parsed, so
/// the checked `L2tpIfName` is the only representation after that point.
#[cfg(feature = "serde")]
pub(crate) mod ifname_serde {
    use l2tp::{L2tpIfName, L2tpIfNameExt};
    use serde::{Deserialize, Deserializer, Serializer};

    fn text<E: serde::ser::Error>(name: &L2tpIfName) -> Result<&str, E> {
        name.to_str()
            .map_err(|_| E::custom(format!("interface name {name:?} is not UTF-8")))
    }

    pub(crate) fn serialize<S: Serializer>(name: &L2tpIfName, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(text(name)?)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<L2tpIfName, D::Error> {
        L2tpIfName::from_name(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }

    pub(crate) mod option {
        use super::*;

        pub(crate) fn serialize<S: Serializer>(
            name: &Option<L2tpIfName>,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            match name {
                None => s.serialize_none(),
                Some(name) => s.serialize_some(text(name)?),
            }
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Option<L2tpIfName>, D::Error> {
            Option::<String>::deserialize(d)?
                .map(|name| L2tpIfName::from_name(&name).map_err(serde::de::Error::custom))
                .transpose()
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

#[cfg(feature = "serde")]
fn merge_opt<T>(dst: &mut Option<T>, src: Option<T>) {
    if let Some(v) = src {
        *dst = Some(v);
    }
}

/// A configuration as deserialised from one document: every field is
/// optional so that several documents can be merged before the result is
/// validated. Interface names and hardware addresses are still checked
/// while deserialising, so an invalid value is reported with the document
/// it came from.
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

    /// Validates the merged result into a [`Config`].
    pub fn into_config(self) -> Result<Config> {
        Config::from_partial(self)
    }
}

#[cfg(feature = "serde")]
#[derive(Debug, Clone, serde::Deserialize, Default)]
struct PartialTunnelConfig {
    tunnel_id: Option<u32>,
    peer_tunnel_id: Option<u32>,
    ip_version: Option<IpVersion>,
    remote_addr: Option<IpHost>,
    #[serde(default, with = "ifname_serde::option")]
    bind_interface: Option<L2tpIfName>,
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

    fn into_full(self) -> Result<TunnelConfig> {
        let tunnel_id = self
            .tunnel_id
            .ok_or(Error::InvalidConfig("tunnel_id is missing".to_string()))?;
        let ip_version = self
            .ip_version
            .ok_or(Error::InvalidConfig("ip_version is missing".to_string()))?;
        let remote_addr = self
            .remote_addr
            .ok_or(Error::InvalidConfig("remote_addr is missing".to_string()))?;

        let config = TunnelConfig {
            tunnel_id,
            peer_tunnel_id: self.peer_tunnel_id.unwrap_or(tunnel_id),
            ip_version,
            remote_addr,
            // Interface names were validated when the document was parsed.
            bind_interface: self.bind_interface,
        };
        config.validate()?;
        Ok(config)
    }
}

#[cfg(feature = "serde")]
#[derive(Debug, Clone, serde::Deserialize, Default)]
struct PartialSessionConfig {
    tunnel_name: Option<String>,
    session_id: Option<u32>,
    peer_session_id: Option<u32>,
    #[serde(default, with = "ifname_serde::option")]
    interface_name: Option<L2tpIfName>,
    interface_hwaddr: Option<HwAddr>,
}

#[cfg(feature = "serde")]
impl PartialSessionConfig {
    fn merge(&mut self, latter: Self) {
        merge_opt(&mut self.tunnel_name, latter.tunnel_name);
        merge_opt(&mut self.session_id, latter.session_id);
        merge_opt(&mut self.peer_session_id, latter.peer_session_id);
        merge_opt(&mut self.interface_name, latter.interface_name);
        merge_opt(&mut self.interface_hwaddr, latter.interface_hwaddr);
    }

    fn into_full(self) -> Result<SessionConfig> {
        let tunnel_name = self
            .tunnel_name
            .ok_or(Error::InvalidConfig("tunnel_name is missing".to_string()))?;
        let session_id = self
            .session_id
            .ok_or(Error::InvalidConfig("session_id is missing".to_string()))?;
        // Interface names and hardware addresses were validated when the
        // document was parsed.
        let interface_name = self.interface_name.ok_or(Error::InvalidConfig(
            "interface_name is missing".to_string(),
        ))?;

        let config = SessionConfig {
            tunnel_name,
            session_id,
            peer_session_id: self.peer_session_id.unwrap_or(session_id),
            interface_name,
            interface_hwaddr: self.interface_hwaddr,
        };
        config.validate()?;
        Ok(config)
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

    /// Validates a merged [`PartialConfig`].
    #[cfg(feature = "serde")]
    pub fn from_partial(partial: PartialConfig) -> Result<Self> {
        let mut full = Config::default();
        for (k, v) in partial.tunnels {
            let tunnel = v
                .into_full()
                .map_err(|e| Error::InvalidConfig(format!("tunnel {k}: {e}")))?;
            full.insert_tunnel(k, tunnel)?;
        }
        for (k, v) in partial.sessions {
            let session = v
                .into_full()
                .map_err(|e| Error::InvalidConfig(format!("session {k}: {e}")))?;
            full.insert_session(k, session)?;
        }
        Ok(full)
    }

    /// Adds or replaces the tunnel called `name`.
    pub fn insert_tunnel(&mut self, name: impl Into<String>, tunnel: TunnelConfig) -> Result<()> {
        tunnel.validate()?;
        self.tunnels.insert(name.into(), tunnel);
        Ok(())
    }

    /// Adds or replaces the session called `name`, whose tunnel must already
    /// be present.
    pub fn insert_session(
        &mut self,
        name: impl Into<String>,
        session: SessionConfig,
    ) -> Result<()> {
        session.validate()?;
        if !self.tunnels.contains_key(&session.tunnel_name) {
            return Err(Error::InvalidConfig(format!(
                "tunnel not defined: {}",
                session.tunnel_name
            )));
        }
        self.sessions.insert(name.into(), session);
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
/// `tunnel_id` when deserialised through [`PartialConfig`]), `ip_version`,
/// `remote_addr` (an address or a host name) and the optional
/// `bind_interface`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TunnelConfig {
    tunnel_id: u32,
    peer_tunnel_id: u32,
    ip_version: IpVersion,
    remote_addr: IpHost,
    #[cfg_attr(feature = "serde", serde(default, with = "ifname_serde::option"))]
    bind_interface: Option<L2tpIfName>,
}

impl TunnelConfig {
    /// A tunnel whose peer uses the same identifier and whose socket is not
    /// bound to a device.
    pub fn new(tunnel_id: u32, ip_version: IpVersion, remote_addr: IpHost) -> Self {
        Self {
            tunnel_id,
            peer_tunnel_id: tunnel_id,
            ip_version,
            remote_addr,
            bind_interface: None,
        }
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
        Ok(())
    }
}

/// One Ethernet pseudowire session, which appears as an `l2tpeth` device.
///
/// Serialised fields: `tunnel_name` (a key of the `tunnels` map),
/// `session_id`, `peer_session_id` (defaults to `session_id` when
/// deserialised through [`PartialConfig`]), `interface_name` and the
/// optional `interface_hwaddr`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionConfig {
    tunnel_name: String,
    session_id: u32,
    peer_session_id: u32,
    #[cfg_attr(feature = "serde", serde(with = "ifname_serde"))]
    interface_name: L2tpIfName,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    interface_hwaddr: Option<HwAddr>,
}

impl SessionConfig {
    /// A session whose peer uses the same identifier and whose device keeps
    /// the hardware address the kernel assigns.
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
        }
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
    use super::{Config, HwAddr, IpVersion, SessionConfig, TunnelConfig};
    use crate::error::Error;
    use l2tp::{L2tpIfName, L2tpIfNameExt};

    fn hwaddr(s: &str) -> HwAddr {
        s.parse().unwrap()
    }

    fn ifname(s: &str) -> L2tpIfName {
        L2tpIfName::from_name(s).unwrap()
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
        use super::{hwaddr, ifname, Config, Error, IpVersion};
        use crate::config::PartialConfig;

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
        fn rejects_invalid_interface_name_at_parse_time() {
            for bad in [
                "this-interface-name-is-way-too-long",
                "",
                "with space",
                "a/b",
                "a:b",
                ".",
            ] {
                let toml = VALID.replace("\"l2tp0\"", &format!("{bad:?}"));
                let err = partial(&toml).expect_err(bad);
                assert!(matches!(err, Error::InvalidConfig(_)), "{bad}: {err}");

                let toml = VALID.replace("\"vrf0\"", &format!("{bad:?}"));
                let err = partial(&toml).expect_err(bad);
                assert!(matches!(err, Error::InvalidConfig(_)), "{bad}: {err}");
            }
        }

        #[test]
        fn rejects_invalid_hwaddr_at_parse_time() {
            let toml = VALID.replace("\"02:00:5E:00:53:01\"", "\"01:00:5e:00:53:01\"");
            assert!(matches!(partial(&toml), Err(Error::InvalidConfig(_))));
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
    }
}
