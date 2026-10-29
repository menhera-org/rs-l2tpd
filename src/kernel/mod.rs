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
pub struct SocketId(pub u64);

/// The peer a socket is connected to (T14, T27): an address, IPv4 for an
/// IPv4 peer whatever the socket family, and for a link-local IPv6 peer
/// the zone device's name, resolved by the kernel at the connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The peer's address.
    pub addr: IpAddr,
    /// The zone of a link-local address.
    pub zone: Option<L2tpIfName>,
}

/// A tunnel socket handed over by a previous instance (P14, S28).
#[derive(Clone, Copy, Debug)]
pub struct Adopted {
    /// The socket, now held by the implementation.
    pub socket: SocketId,
    /// The socket's family.
    pub family: Family,
    /// The tunnel registered on it.
    pub tunnel_id: u32,
    /// Its peer tunnel identifier, as the kernel reports it.
    pub peer_tunnel_id: u32,
}

/// The kernel's record of a tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelInfo {
    /// The tunnel identifier.
    pub tunnel_id: u32,
    /// The peer tunnel identifier.
    pub peer_tunnel_id: u32,
}

/// A session to create (S3): an Ethernet pseudowire with no sequence
/// numbers and no sublayer, under an explicit name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCreate {
    /// The tunnel.
    pub tunnel_id: u32,
    /// The session identifier.
    pub session_id: u32,
    /// The peer session identifier.
    pub peer_session_id: u32,
    /// Sent in every frame.
    pub cookie: Option<Cookie>,
    /// Required in every frame received.
    pub peer_cookie: Option<Cookie>,
    /// The creation name, a staging name (S4).
    pub ifname: L2tpIfName,
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
    pub tunnel_id: u32,
    /// The session identifier.
    pub session_id: u32,
    /// The peer session identifier.
    pub peer_session_id: u32,
    /// The cookie, empty when none.
    pub cookie: ReportedCookie,
    /// The peer cookie, empty when none.
    pub peer_cookie: ReportedCookie,
    /// The creation-time interface name, not the current one (K16).
    pub ifname: Option<L2tpIfName>,
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
    pub index: u32,
    /// The lifetime subscription's generation it was seen in.
    pub generation: u64,
    /// Distinct for every registration seen, even of a reused index.
    pub incarnation: u64,
}

/// What the lifetime subscription says about a registration (S9, S19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub index: u32,
    /// The current name.
    pub name: L2tpIfName,
    /// `IFF_UP`.
    pub up: bool,
    /// The device is a VRF.
    pub vrf: bool,
    /// The controller's index (`IFLA_MASTER`).
    pub master: Option<u32>,
}

/// An address on a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrInfo {
    /// The device's index.
    pub index: u32,
    /// The address.
    pub addr: IpAddr,
}

/// A notification of a subscription (E1–E7, E27), or the loss of some
/// (E20, E21).
#[derive(Clone, Debug, PartialEq, Eq)]
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
    fn random(&mut self) -> [u8; 3];

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
