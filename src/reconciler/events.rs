//! The event handlers (E1–E27): each converges only the entries the event
//! concerns, found by lookup in the daemon's own records; an event that
//! concerns no entry costs a comparison (M5, M16).

use crate::config::{Family, L2tpIfName};
use crate::kernel::{AddrInfo, Kernel, LinkInfo, Notice};

use super::records::Identity;
use super::{Reconciler, report};

/// The subscription a notice came from: a loss means a different resync
/// for each (E20).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Source {
    /// The event monitor (links and addresses).
    Monitor,
    /// The `l2tp` group (K41).
    L2tp,
}

impl<K: Kernel> Reconciler<K> {
    /// Applies one notice of a subscription.
    pub fn handle(&mut self, source: Source, notice: Notice) {
        match notice {
            Notice::LinkNew(link) => self.link_new(link),
            Notice::LinkDel(link) => self.link_del(link),
            Notice::AddrNew(addr) => self.addr_changed(addr, false),
            Notice::AddrDel(addr) => self.addr_changed(addr, true),
            Notice::TunnelDeleted { tunnel_id } => self.tunnel_announced(tunnel_id),
            Notice::SessionDeleted {
                tunnel_id,
                session_id,
            } => {
                if self
                    .sessions
                    .get(&session_id)
                    .is_some_and(|s| s.tunnel_id == tunnel_id)
                {
                    self.sessions.get_mut(&session_id).unwrap().verify = true;
                    self.verify_session(session_id);
                }
            }
            Notice::Loss if source == Source::Monitor => self.monitor_resync(),
            Notice::Loss => {
                self.l2tp_pending = true;
                self.l2tp_resync();
            }
        }
    }

    fn owned_session(&self, index: u32) -> Option<u32> {
        self.sessions
            .iter()
            .find(|(_, s)| s.state.registration().is_some_and(|r| r.index == index))
            .map(|(sid, _)| *sid)
    }

    fn zone_name(&self, tunnel_id: u32) -> Option<L2tpIfName> {
        self.real_peer(tunnel_id)?.zone
    }

    /// A device appeared, was renamed or changed state (E1, E2, E4).
    fn link_new(&mut self, link: LinkInfo) {
        if link.vrf {
            self.vrfs.insert(link.index);
        } else {
            self.vrfs.remove(&link.index);
        }
        let previous = match link.master {
            Some(m) => self.masters.insert(link.index, m),
            None => self.masters.remove(&link.index),
        };
        let controller_changed = previous != link.master;
        if let Some(sid) = self.owned_session(link.index) {
            self.session_device_changed(sid, link.name, link.up);
        }
        let ids: Vec<u32> = self.tunnels.keys().copied().collect();
        for id in ids {
            let record = &self.tunnels[&id];
            let bind_name = record.config.bind_interface().copied();
            let zone_name = self.zone_name(id);
            let named = |n: Option<L2tpIfName>, index: Option<u32>| {
                (n == Some(link.name) && index != Some(link.index))
                    || (index == Some(link.index) && n != Some(link.name))
            };
            let follows =
                named(bind_name, record.bind_index) || named(zone_name, record.zone_index);
            // E4: the bound device's L3 domain changed, or the bound VRF's
            // set of members did.
            let domain = controller_changed
                && ((record.bind_index == Some(link.index)
                    && [previous, link.master]
                        .iter()
                        .flatten()
                        .any(|m| self.vrfs.contains(m)))
                    || record.bind_index.is_some_and(|b| {
                        self.vrfs.contains(&b) && (previous == Some(b) || link.master == Some(b))
                    }));
            if domain && record.connection.is_connected() {
                self.tunnels.get_mut(&id).unwrap().stale = true;
            }
            if follows || domain {
                self.converge_tunnel(id);
            }
        }
        self.resolver_device_changed(&link.name);
    }

    /// A device left the namespace (E3, S19, S27).
    fn link_del(&mut self, link: LinkInfo) {
        self.vrfs.remove(&link.index);
        let master = self.masters.remove(&link.index);
        if let Some(sid) = self.owned_session(link.index) {
            self.observed_removal(sid);
            if !self.sessions.contains_key(&sid) {
                self.create_wanted_sessions();
            }
        }
        let ids: Vec<u32> = self.tunnels.keys().copied().collect();
        for id in ids {
            let record = &self.tunnels[&id];
            let bound =
                record.bind_index == Some(link.index) || record.zone_index == Some(link.index);
            let member =
                master.is_some() && record.bind_index == master && record.connection.is_connected();
            if member {
                self.tunnels.get_mut(&id).unwrap().stale = true;
            }
            if bound || member {
                self.converge_tunnel(id);
            }
        }
        self.resolver_device_changed(&link.name);
    }

    /// E6, E7: connected tunnels of the address's family bound to its
    /// device or to that device's VRF reselect their source; an unbound
    /// tunnel does when the address it selected is removed.
    fn addr_changed(&mut self, addr: AddrInfo, removed: bool) {
        let family = if addr.addr.to_canonical().is_ipv4() {
            Family::V4
        } else {
            Family::V6
        };
        let vrf_of_device = self.masters.get(&addr.index).copied();
        let ids: Vec<u32> = self.tunnels.keys().copied().collect();
        for id in ids {
            let record = &self.tunnels[&id];
            let peer_family = match &record.connection {
                super::records::Connection::Connected { peer, .. } => {
                    if peer.addr.to_canonical().is_ipv4() {
                        Family::V4
                    } else {
                        Family::V6
                    }
                }
                _ => continue,
            };
            let effective = record.zone_index.or(record.bind_index);
            let concerns = match effective {
                Some(device) => {
                    peer_family == family
                        && (device == addr.index
                            || record.bind_index.is_some_and(|b| {
                                vrf_of_device == Some(b) && self.vrfs.contains(&b)
                            }))
                }
                None => removed && self.source_of(id) == Some(addr.addr.to_canonical()),
            };
            if concerns {
                self.tunnels.get_mut(&id).unwrap().stale = true;
                self.converge_tunnel(id);
            }
        }
    }

    /// A tunnel deletion was announced: an operator deleted an owned tunnel,
    /// which is unsupported (T9), or the announcement is foreign (K41).
    fn tunnel_announced(&mut self, tunnel_id: u32) {
        if !self.tunnels.contains_key(&tunnel_id) {
            return;
        }
        if let Ok(None) = self.k.tunnel(tunnel_id) {
            let label = self.tunnel_label(tunnel_id);
            self.report.begin_error(&label, "deleted", || {
                "was deleted in the kernel outside the daemon; this is unsupported (T9)".into()
            });
        }
    }

    /// E27: an announced deletion is verified locally; a session confirmed
    /// absent is created again (S27, S29), a present one is kept and
    /// verified again on the tick.
    pub(super) fn verify_session(&mut self, sid: u32) {
        let tid = self.sessions[&sid].tunnel_id;
        match self.k.session(tid, sid) {
            Ok(None) => {
                let label = self.session_label_of(sid);
                self.forget_session(sid);
                log::warn!("{label}: deleted outside the daemon; creating it again (S27)");
                self.create_wanted_sessions();
            }
            Ok(Some(_)) => {}
            Err(e) => log::debug!(
                "verification of session_id={sid} failed: {}",
                report::describe(&e)
            ),
        }
    }

    fn session_label_of(&self, sid: u32) -> String {
        let r = &self.sessions[&sid];
        report::session(&r.name, r.tunnel_id, sid)
    }

    /// E20, event monitor: every binding checked by name, every connected
    /// tunnel reconnected, deferred addresses re-checked, resolver devices
    /// validated again.
    fn monitor_resync(&mut self) {
        log::warn!("the event monitor lost notifications; resynchronising (E20)");
        if let Ok(links) = self.k.dump_links() {
            self.vrfs = links.iter().filter(|l| l.vrf).map(|l| l.index).collect();
            self.masters = links
                .iter()
                .filter_map(|l| Some((l.index, l.master?)))
                .collect();
        }
        let ids: Vec<u32> = self.tunnels.keys().copied().collect();
        for id in ids {
            let record = self.tunnels.get_mut(&id).unwrap();
            record.stale = record.connection.is_connected();
            self.converge_tunnel(id);
        }
        let sids: Vec<u32> = self.sessions.keys().copied().collect();
        for sid in sids {
            if let Identity::Proved(r) = self.sessions[&sid].state {
                self.apply_hwaddr(sid, r.index);
            }
        }
        let names: Vec<L2tpIfName> = self
            .accepted
            .resolvers()
            .values()
            .filter_map(|r| r.bind_interface().copied())
            .collect();
        for name in names {
            self.resolver_device_changed(&name);
        }
    }

    /// E20, `l2tp` group: every configured tunnel and session queried; the
    /// loss stays pending until a scan completes.
    pub(super) fn l2tp_resync(&mut self) {
        let mut complete = true;
        let tids: Vec<u32> = self.tunnels.keys().copied().collect();
        for tid in tids {
            match self.k.tunnel(tid) {
                Ok(None) => self.tunnel_announced(tid),
                Ok(Some(_)) => {}
                Err(_) => complete = false,
            }
        }
        let sids: Vec<u32> = self.sessions.keys().copied().collect();
        for sid in sids {
            if !self.sessions.contains_key(&sid) {
                continue;
            }
            let tid = self.sessions[&sid].tunnel_id;
            match self.k.session(tid, sid) {
                Ok(None) => self.verify_session(sid),
                Ok(Some(_)) => {}
                Err(_) => complete = false,
            }
        }
        if complete {
            self.l2tp_pending = false;
        }
    }
}
