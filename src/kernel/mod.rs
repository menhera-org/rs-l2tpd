//! The one boundary to the host: the [`Kernel`] trait every reconciler
//! operation goes through, its real implementation and its fake
//! (`docs/architecture.md`, "The kernel boundary").
//!
//! Every method returns the kernel's errno in an [`io::Error`]; `ETIMEDOUT`
//! from a mutating request means its outcome is unknown (A14): the caller
//! keeps its reservations and verifies local state before retrying.

use std::io;
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::task::{Context, Poll};
use std::time::Instant;

pub use crate::config::{Cookie, Family, HwAddr, L2tpIfName};

#[cfg(any(test, feature = "fake-kernel"))]
pub mod fake;
pub mod linux;

/// A tunnel socket the kernel implementation holds for the reconciler.
/// The number is the implementation's own and is never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SocketId(pub(crate) u64);

impl SocketId {
    /// Constructs an implementation-local socket identifier.
    pub fn new(value: u64) -> Self {
        Self(value)
    }
    /// The implementation-local identifier.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// The peer a socket is connected to (T14, T27): an address, IPv4 for an
/// IPv4 peer whatever the socket family, and for a link-local IPv6 peer
/// the zone device's name, resolved by the kernel at the connect.
///
/// ```compile_fail,E0451
/// use rs_l2tpd::kernel::Peer;
/// let peer = Peer { addr: "192.0.2.1".parse().unwrap(), zone: None };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The peer's address.
    pub(crate) addr: IpAddr,
    /// The zone of a link-local address.
    pub(crate) zone: Option<L2tpIfName>,
}

/// A tunnel socket handed over by a previous instance (P14, S28).
#[derive(Clone, Copy, Debug)]
pub struct Adopted {
    /// The socket, now held by the implementation.
    pub(crate) socket: SocketId,
    /// The socket's family.
    pub(crate) family: Family,
    /// The tunnel registered on it.
    pub(crate) tunnel_id: u32,
    /// Its peer tunnel identifier, as the kernel reports it.
    pub(crate) peer_tunnel_id: u32,
}

/// The kernel's record of a tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelInfo {
    /// The tunnel identifier.
    pub(crate) tunnel_id: u32,
    /// The peer tunnel identifier.
    pub(crate) peer_tunnel_id: u32,
}

/// A session to create (S3): an Ethernet pseudowire with no sequence
/// numbers and no sublayer, under an explicit name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCreate {
    /// The tunnel.
    pub(crate) tunnel_id: u32,
    /// The session identifier.
    pub(crate) session_id: u32,
    /// The peer session identifier.
    pub(crate) peer_session_id: u32,
    /// Sent in every frame.
    pub(crate) cookie: Option<Cookie>,
    /// Required in every frame received.
    pub(crate) peer_cookie: Option<Cookie>,
    /// The creation name, a staging name (S4).
    pub(crate) ifname: L2tpIfName,
}

/// A cookie as the kernel reported it (K35): any length up to 8 bytes,
/// because a session created elsewhere may carry a length the
/// configuration cannot (C8). `Debug` gives the length only (O5).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ReportedCookie(l2tp::KernelCookie);

impl ReportedCookie {
    /// Fails above 8 bytes, which the kernel never reports.
    pub fn new(bytes: &[u8]) -> crate::Result<Self> {
        l2tp::KernelCookie::try_from(bytes)
            .map(Self)
            .map_err(|e| crate::Error::Other(e.to_string()))
    }

    /// As a configuration cookie: `Ok(None)` for no cookie, an error for a
    /// length C8 forbids, so that such a session matches no entry.
    pub fn configured(self) -> crate::Result<Option<Cookie>> {
        if self.0.is_empty() {
            return Ok(None);
        }
        Cookie::new(self.0.as_bytes()).map(Some)
    }
}

impl From<Option<Cookie>> for ReportedCookie {
    fn from(cookie: Option<Cookie>) -> Self {
        cookie.map_or_else(Self::default, |c| {
            Self::new(c.as_bytes()).expect("a configuration cookie is 4 or 8 bytes")
        })
    }
}

impl std::fmt::Debug for ReportedCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReportedCookie({} bytes)", self.0.len())
    }
}

/// The kernel's record of a session (K16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    /// The tunnel.
    pub(crate) tunnel_id: u32,
    /// The session identifier.
    pub(crate) session_id: u32,
    /// The peer session identifier.
    pub(crate) peer_session_id: u32,
    /// The cookie, empty when none.
    pub(crate) cookie: ReportedCookie,
    /// The peer cookie, empty when none.
    pub(crate) peer_cookie: ReportedCookie,
    /// The creation-time interface name, not the current one (K16).
    pub(crate) ifname: Option<L2tpIfName>,
}

impl SessionInfo {
    /// Both cookies as configuration cookies; an error when either has a
    /// length the configuration cannot hold, so the session is foreign.
    pub fn cookies(&self) -> crate::Result<(Option<Cookie>, Option<Cookie>)> {
        Ok((self.cookie.configured()?, self.peer_cookie.configured()?))
    }
}

/// A session device as its registration broadcast reported it (S8, M18).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Registration {
    /// The device's index.
    pub(crate) index: u32,
    /// The lifetime subscription's generation it was seen in.
    pub(crate) generation: u64,
    /// Distinct for every registration seen, even of a reused index.
    pub(crate) incarnation: u64,
}

/// What the lifetime subscription says about a registration (S9, S19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Proof {
    /// The index still refers to the device registered.
    Proved,
    /// The subscription saw the index leave the namespace.
    Removed,
    /// The registration's generation ended: nothing can be proved.
    Lost,
}

/// A device (A5): what the reconciler needs to match bind, zone and
/// session devices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    /// The index.
    pub(crate) index: u32,
    /// The current name.
    pub(crate) name: L2tpIfName,
    /// `IFF_UP`.
    pub(crate) up: bool,
    /// The device is a VRF.
    pub(crate) vrf: bool,
    /// The controller's index (`IFLA_MASTER`).
    pub(crate) master: Option<u32>,
}

/// An address on a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrInfo {
    /// The device's index.
    pub(crate) index: u32,
    /// The address.
    pub(crate) addr: IpAddr,
}

/// A notification of a subscription (E1–E7, E27), or the loss of some
/// (E20, E21).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Notice {
    /// `RTM_NEWLINK` of family `AF_UNSPEC` (E5).
    LinkNew(LinkInfo),
    /// `RTM_DELLINK` of family `AF_UNSPEC`.
    LinkDel(LinkInfo),
    /// `RTM_NEWADDR`.
    AddrNew(AddrInfo),
    /// `RTM_DELADDR`.
    AddrDel(AddrInfo),
    /// An announced tunnel deletion (K41).
    TunnelDeleted {
        /// The tunnel.
        tunnel_id: u32,
    },
    /// An announced session deletion (K41).
    SessionDeleted {
        /// The tunnel.
        tunnel_id: u32,
        /// The session.
        session_id: u32,
    },
    /// Notifications were lost; the subscription carries on.
    Loss,
}

/// A subscription read on the service runtime (A5–A7). Loss is an item,
/// so that a reader can turn it into its persistent flag (E20).
pub trait Subscription: Send {
    /// The next notice, or pending; registers the waker.
    fn poll_notice(&mut self, cx: &mut Context<'_>) -> Poll<Notice>;
}

/// Everything the reconciler does to the host. Synchronous: the reconciler
/// runs on a thread of its own and every request has a five-second total
/// deadline (A14).
pub trait Kernel: Send {
    /// The monotonic clock (M14).
    fn now(&self) -> Instant;
    /// Three bytes (six hexadecimal digits) from the kernel's random
    /// source, for staging names (S4).
    fn random(&mut self) -> io::Result<[u8; 3]>;

    /// A socket of `family`, bound to the unspecified address with
    /// `tunnel_id` as its connection identifier, unconnected, close-on-exec
    /// (T1, T6). `EAFNOSUPPORT`, `EPROTONOSUPPORT` (T4); `EADDRINUSE` (T7).
    fn create_socket(
        &mut self,
        family: Family,
        tunnel_id: u32,
        peer_tunnel_id: u32,
    ) -> io::Result<SocketId>;
    /// Whether an `AF_INET6` socket is IPv6-only (K23, T26).
    fn only_v6(&self, socket: SocketId) -> io::Result<bool>;
    /// The scratch check of E25: whether a new `AF_INET6` L2TP/IP socket
    /// would be IPv6-only.
    fn scratch_only_v6(&mut self) -> io::Result<bool>;
    /// `SO_BINDTOIFINDEX` (K22, T10).
    fn bind_index(&mut self, socket: SocketId, index: u32) -> io::Result<()>;
    /// Connects to `peer` (an IPv4 peer of an `AF_INET6` socket mapped)
    /// and returns the source the kernel selected (T16, T28, K24–K27, K34).
    fn connect(&mut self, socket: SocketId, peer: &Peer) -> io::Result<IpAddr>;
    /// `connect(AF_UNSPEC)`: clears the peer, the source and the binding
    /// (K22, K24, K25).
    fn disconnect(&mut self, socket: SocketId) -> io::Result<()>;
    /// Closes the socket; the kernel deletes the tunnel later (K17, T8).
    fn close(&mut self, socket: SocketId);
    /// A duplicate of the socket's descriptor, close-on-exec (P14, P26).
    fn clone_fd(&self, socket: SocketId) -> io::Result<OwnedFd>;
    /// Takes over a socket handed over by a previous instance (K37, P14).
    fn adopt(&mut self, fd: OwnedFd) -> io::Result<Adopted>;

    /// Registers the tunnel on its socket. `EEXIST` (K19).
    fn register_tunnel(
        &mut self,
        socket: SocketId,
        tunnel_id: u32,
        peer_tunnel_id: u32,
    ) -> io::Result<()>;
    /// The kernel's tunnel, if any.
    fn tunnel(&mut self, tunnel_id: u32) -> io::Result<Option<TunnelInfo>>;
    /// Creates a session and captures its device's registration (S3, S8).
    /// The name taken: `EEXIST` or `ENFILE`, nothing created (K20); an
    /// identifier taken: `EEXIST` (K19).
    fn create_session(&mut self, create: &SessionCreate) -> io::Result<Registration>;
    /// The kernel's session, if any.
    fn session(&mut self, tunnel_id: u32, session_id: u32) -> io::Result<Option<SessionInfo>>;
    /// Every session of the namespace, or of one tunnel, streamed from a
    /// complete dump (S4, S22, S28); an error means the dump proves nothing.
    fn scan_sessions(
        &mut self,
        tunnel_id: Option<u32>,
        visit: &mut dyn FnMut(&SessionInfo),
    ) -> io::Result<()>;
    /// Deletes by identifiers.
    fn delete_session(&mut self, tunnel_id: u32, session_id: u32) -> io::Result<()>;
    /// Deletes by stored creation name (K16); the caller has verified the
    /// name is unique and matches (S22).
    fn delete_session_by_name(&mut self, ifname: &L2tpIfName) -> io::Result<()>;

    /// The lifetime subscription's answer for `registration` (S9, A7).
    fn prove(&mut self, registration: &Registration) -> Proof;
    /// Stops tracking `registration`.
    fn release(&mut self, registration: &Registration);

    /// The device that bears `name` now.
    fn link_by_name(&mut self, name: &L2tpIfName) -> io::Result<Option<LinkInfo>>;
    /// The current device at an index (K9).
    fn link_by_index(&mut self, index: u32) -> io::Result<Option<LinkInfo>>;
    /// Renames a device; `EEXIST` when the name is taken.
    fn rename(&mut self, index: u32, name: &L2tpIfName) -> io::Result<()>;
    /// Sets a hardware address; `EBUSY` while the device is up (K31).
    fn set_hwaddr(&mut self, index: u32, addr: HwAddr) -> io::Result<()>;
    /// A device's Ethernet address, `None` for a device without one (V12).
    fn ether_addr(&mut self, index: u32) -> io::Result<Option<HwAddr>>;
    /// Every device (E20 resync).
    fn dump_links(&mut self) -> io::Result<Vec<LinkInfo>>;
    /// Every address (E20 resync).
    fn dump_addrs(&mut self) -> io::Result<Vec<AddrInfo>>;

    /// Opens the event monitor: links of family `AF_UNSPEC` and addresses
    /// (A5, E5).
    fn monitor(&mut self) -> io::Result<Box<dyn Subscription>>;
    /// Opens the `l2tp` group subscription (K41, E27).
    fn l2tp_events(&mut self) -> io::Result<Box<dyn Subscription>>;
}

/// The errno of `error`, 0 for none.
pub fn errno(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(0)
}

impl Peer {
    /// Constructs a host-boundary record from reported facts.
    pub fn new(addr: IpAddr, zone: Option<L2tpIfName>) -> Self {
        Self { addr, zone }
    }
    /// The reported `addr` field.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }
    /// The reported `zone` field.
    pub fn zone(&self) -> Option<L2tpIfName> {
        self.zone
    }
}

impl Adopted {
    /// Constructs a host-boundary record from reported facts.
    pub fn new(socket: SocketId, family: Family, tunnel_id: u32, peer_tunnel_id: u32) -> Self {
        Self {
            socket,
            family,
            tunnel_id,
            peer_tunnel_id,
        }
    }
    /// The reported `socket` field.
    pub fn socket(&self) -> SocketId {
        self.socket
    }
    /// The reported `family` field.
    pub fn family(&self) -> Family {
        self.family
    }
    /// The reported `tunnel_id` field.
    pub fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }
    /// The reported `peer_tunnel_id` field.
    pub fn peer_tunnel_id(&self) -> u32 {
        self.peer_tunnel_id
    }
}

impl TunnelInfo {
    /// Constructs a host-boundary record from reported facts.
    pub fn new(tunnel_id: u32, peer_tunnel_id: u32) -> Self {
        Self {
            tunnel_id,
            peer_tunnel_id,
        }
    }
    /// The reported `tunnel_id` field.
    pub fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }
    /// The reported `peer_tunnel_id` field.
    pub fn peer_tunnel_id(&self) -> u32 {
        self.peer_tunnel_id
    }
}

impl SessionCreate {
    /// Constructs a host-boundary record from reported facts.
    pub fn new(
        tunnel_id: u32,
        session_id: u32,
        peer_session_id: u32,
        cookie: Option<Cookie>,
        peer_cookie: Option<Cookie>,
        ifname: L2tpIfName,
    ) -> Self {
        Self {
            tunnel_id,
            session_id,
            peer_session_id,
            cookie,
            peer_cookie,
            ifname,
        }
    }
    /// The reported `tunnel_id` field.
    pub fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }
    /// The reported `session_id` field.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }
    /// The reported `peer_session_id` field.
    pub fn peer_session_id(&self) -> u32 {
        self.peer_session_id
    }
    /// The reported `cookie` field.
    pub fn cookie(&self) -> Option<Cookie> {
        self.cookie
    }
    /// The reported `peer_cookie` field.
    pub fn peer_cookie(&self) -> Option<Cookie> {
        self.peer_cookie
    }
    /// The reported `ifname` field.
    pub fn ifname(&self) -> L2tpIfName {
        self.ifname
    }
    /// Sets the requested `cookie`.
    pub fn with_cookie(mut self, value: Option<Cookie>) -> Self {
        self.cookie = value;
        self
    }
    /// Sets the requested `peer_cookie`.
    pub fn with_peer_cookie(mut self, value: Option<Cookie>) -> Self {
        self.peer_cookie = value;
        self
    }
}

impl SessionInfo {
    /// Constructs a host-boundary record from reported facts.
    pub fn new(
        tunnel_id: u32,
        session_id: u32,
        peer_session_id: u32,
        cookie: ReportedCookie,
        peer_cookie: ReportedCookie,
        ifname: Option<L2tpIfName>,
    ) -> Self {
        Self {
            tunnel_id,
            session_id,
            peer_session_id,
            cookie,
            peer_cookie,
            ifname,
        }
    }
    /// The reported `tunnel_id` field.
    pub fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }
    /// The reported `session_id` field.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }
    /// The reported `peer_session_id` field.
    pub fn peer_session_id(&self) -> u32 {
        self.peer_session_id
    }
    /// The reported `cookie` field.
    pub fn cookie(&self) -> ReportedCookie {
        self.cookie
    }
    /// The reported `peer_cookie` field.
    pub fn peer_cookie(&self) -> ReportedCookie {
        self.peer_cookie
    }
    /// The reported `ifname` field.
    pub fn ifname(&self) -> Option<L2tpIfName> {
        self.ifname
    }
    /// Replaces `tunnel_id` in this host record.
    pub fn with_tunnel_id(mut self, value: u32) -> Self {
        self.tunnel_id = value;
        self
    }
    /// Replaces `session_id` in this host record.
    pub fn with_session_id(mut self, value: u32) -> Self {
        self.session_id = value;
        self
    }
    /// Replaces `peer_session_id` in this host record.
    pub fn with_peer_session_id(mut self, value: u32) -> Self {
        self.peer_session_id = value;
        self
    }
}

impl Registration {
    /// Constructs a host-boundary record from reported facts.
    pub fn new(index: u32, generation: u64, incarnation: u64) -> Self {
        Self {
            index,
            generation,
            incarnation,
        }
    }
    /// The reported `index` field.
    pub fn index(&self) -> u32 {
        self.index
    }
    /// The reported `generation` field.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// The reported `incarnation` field.
    pub fn incarnation(&self) -> u64 {
        self.incarnation
    }
}

impl LinkInfo {
    /// Constructs a host-boundary record from reported facts.
    pub fn new(index: u32, name: L2tpIfName, up: bool, vrf: bool, master: Option<u32>) -> Self {
        Self {
            index,
            name,
            up,
            vrf,
            master,
        }
    }
    /// The reported `index` field.
    pub fn index(&self) -> u32 {
        self.index
    }
    /// The reported `name` field.
    pub fn name(&self) -> L2tpIfName {
        self.name
    }
    /// The reported `up` field.
    pub fn up(&self) -> bool {
        self.up
    }
    /// The reported `vrf` field.
    pub fn vrf(&self) -> bool {
        self.vrf
    }
    /// The reported `master` field.
    pub fn master(&self) -> Option<u32> {
        self.master
    }
}

impl AddrInfo {
    /// Constructs a host-boundary record from reported facts.
    pub fn new(index: u32, addr: IpAddr) -> Self {
        Self { index, addr }
    }
    /// The reported `index` field.
    pub fn index(&self) -> u32 {
        self.index
    }
    /// The reported `addr` field.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }
}
