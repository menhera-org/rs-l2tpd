//! The degradation ladder (M7, M8): the one place that decides which
//! state a tunnel's socket gets now. Promotion is the same function run
//! again at an event; no rung change re-creates anything (M17).

use std::io;

use crate::config::{Family, RemoteAddr};
use crate::kernel::{Kernel, Peer};

use super::Reconciler;

/// The state a tunnel's socket should be in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// Rung 1: connected to the real peer through the configured device
    /// and zone (T1, T27).
    Connect {
        peer: Peer,
        bind: Option<u32>,
        zone: Option<u32>,
    },
    /// Rungs 2–3: disconnected, bound to the configured device while it
    /// exists (T6, T13), with a real peer pending and why (T16).
    Disconnect {
        bind: Option<u32>,
        pending: Option<Peer>,
        why: Option<&'static str>,
    },
}

impl<K: Kernel> Reconciler<K> {
    /// The real peer of a tunnel (T14): the literal, or the selected answer
    /// of its resolver (V5); none otherwise.
    pub(crate) fn real_peer(&self, tunnel_id: u32) -> Option<Peer> {
        let record = &self.tunnels[&tunnel_id];
        match record.config.remote_addr()? {
            RemoteAddr::Ip { addr, zone } => Some(Peer {
                addr: *addr,
                zone: *zone,
            }),
            RemoteAddr::Host(_) => self
                .resolvers
                .selected(tunnel_id)
                .map(|addr| Peer { addr, zone: None }),
        }
    }

    /// The rung the host allows now (M7), resolving the configured bind
    /// and zone names to devices (T10, T27).
    pub(crate) fn target(&mut self, tunnel_id: u32) -> io::Result<Target> {
        let peer = self.real_peer(tunnel_id);
        let record = &self.tunnels[&tunnel_id];
        let (family, bind_name) = (record.family, record.config.bind_interface().copied());
        let bind = match bind_name {
            Some(name) => match self.k.link_by_name(&name)? {
                Some(link) => Some(link),
                None => {
                    return Ok(Target::Disconnect {
                        bind: None,
                        pending: peer,
                        why: Some("its bind device is absent"),
                    });
                }
            },
            None => None,
        };
        let disconnect = |why| Target::Disconnect {
            bind: bind.as_ref().map(|l| l.index),
            pending: peer.clone(),
            why: Some(why),
        };
        let Some(peer) = peer.clone() else {
            return Ok(disconnect("it has no peer").without_reason());
        };
        if family == Family::V4 && peer.addr.is_ipv6() {
            return Ok(disconnect(
                "an IPv6 peer cannot be reached on its AF_INET socket",
            ));
        }
        let mut zone = None;
        if let Some(zone_name) = peer
            .zone
            .filter(|_| matches!(peer.addr, std::net::IpAddr::V6(a) if a.is_unicast_link_local()))
        {
            let Some(link) = self.k.link_by_name(&zone_name)? else {
                return Ok(disconnect("the zone of its link-local peer is absent"));
            };
            if let Some(bind) = &bind
                && link.index != bind.index
                && link.master != Some(bind.index)
            {
                return Ok(disconnect(
                    "the zone of its peer is neither its bind device nor a member of it",
                ));
            }
            zone = Some(link.index);
        }
        Ok(Target::Connect {
            peer,
            bind: bind.map(|l| l.index),
            zone,
        })
    }
}

impl Target {
    /// A peerless tunnel waits for nothing: no reason to report.
    fn without_reason(self) -> Self {
        match self {
            Target::Disconnect { bind, pending, .. } => Target::Disconnect {
                bind,
                pending,
                why: None,
            },
            other => other,
        }
    }
}
