//! What the reconciler holds per tunnel and per session (A11, M19,
//! S19–S23). Records change only after the kernel confirmed (A12).

use std::net::IpAddr;
use std::time::Instant;

use crate::config::{
    HwAddr, L2tpIfName, SessionConfig, SessionIdentity, TunnelConfig, TunnelIdentity,
};
use crate::kernel::{Family, Peer, Registration, SocketId};

/// A tunnel the daemon owns through its socket.
pub(crate) struct TunnelRecord {
    /// The configuration name, for messages (O4).
    pub name: String,
    pub config: TunnelConfig,
    pub identity: TunnelIdentity,
    pub socket: SocketId,
    /// The socket's family, kept until re-creation (T4, T26).
    pub family: Family,
    /// The binding the daemon set and the kernel still holds (K22).
    pub bound: Option<u32>,
    /// The configured bind device and the zone device at the last
    /// reconnect (T10, T27).
    pub bind_index: Option<u32>,
    pub zone_index: Option<u32>,
    pub connection: Connection,
    /// Reconnect for a fresh source at the next converge (T19, E20).
    pub stale: bool,
    /// The next reconnect retry (T20, E13).
    pub retry_at: Option<Instant>,
}

/// Whether the socket is connected (T1, T16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Connection {
    /// No frame leaves; `pending` is a real peer not yet connected to.
    Disconnected { pending: Option<Peer> },
    /// Connected, with the source the socket reported (T28).
    Connected { peer: Peer, source: IpAddr },
}

impl Connection {
    pub fn is_connected(&self) -> bool {
        matches!(self, Connection::Connected { .. })
    }
}

/// How the daemon knows a session's device (S8, S19–S23, S28).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Identity {
    /// Created, not yet published under its configured name.
    Staged(Registration),
    /// Published; the lifetime subscription proves it.
    Proved(Registration),
    /// The subscription saw the device leave (S19).
    Removed,
    /// Notifications were lost; only the kernel's record decides (S22).
    Lost { staged: bool },
    /// Taken over from a previous instance: identifiers only (S28).
    Adopted,
}

impl Identity {
    pub fn registration(&self) -> Option<&Registration> {
        match self {
            Identity::Staged(r) | Identity::Proved(r) => Some(r),
            _ => None,
        }
    }
}

/// What the daemon is entitled to enforce of a field (M19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Enforce {
    /// To apply when the host allows.
    Pending,
    /// Waiting for the device to go down (S12).
    Deferred,
    Applied,
    /// Recorded as applied: the device is unmanageable (S20).
    Skipped,
    /// Another manager changed it afterwards (S10, S12).
    Overridden,
}

/// A session the daemon created or adopted.
pub(crate) struct SessionRecord {
    pub name: String,
    pub config: SessionConfig,
    pub identity: SessionIdentity,
    pub tunnel_id: u32,
    pub state: Identity,
    /// The creation name the kernel stored (K16).
    pub created_as: Option<L2tpIfName>,
    /// The device's name as far as known.
    pub current_name: Option<L2tpIfName>,
    pub name_state: Enforce,
    /// The address to enforce: the configured one, else the one the
    /// kernel assigned at creation (M19).
    pub hwaddr: Option<HwAddr>,
    pub hwaddr_state: Enforce,
    /// The address the kernel assigned at creation.
    pub kernel_hwaddr: Option<HwAddr>,
}

/// A conflict episode of one entry (T25).
pub(crate) struct Conflict {
    pub identity: ConflictIdentity,
    pub attempts: u8,
    pub left_out: bool,
    pub next: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConflictIdentity {
    Tunnel(TunnelIdentity),
    Session(SessionIdentity),
}
