//! The event handlers (E1–E27): each converges only the entries the event
//! concerns, found by lookup in the daemon's own records; an event that
//! concerns no entry costs a comparison (M5, M16).

use crate::config::{Family, L2tpIfName};
use crate::kernel::{AddrInfo, Kernel, LinkInfo, Notice};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use super::{Reconciler, report};

#[derive(Default)]
pub(super) struct Index {
    names: BTreeMap<L2tpIfName, BTreeSet<u32>>,
    devices: BTreeMap<u32, BTreeSet<u32>>,
    sources: BTreeMap<IpAddr, BTreeSet<u32>>,
    sessions: BTreeMap<u32, u32>,
    registrations: BTreeMap<u32, u32>,
}

pub(super) fn remove<T: Ord>(map: &mut BTreeMap<T, BTreeSet<u32>>, key: T, id: u32) {
    if let std::collections::btree_map::Entry::Occupied(mut entry) = map.entry(key) {
        entry.get_mut().remove(&id);
        if entry.get().is_empty() {
            entry.remove();
        }
    }
}

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
    pub(super) fn reindex(&mut self) {
        self.index = Index::default();
        for id in self.tunnels.keys().copied().collect::<Vec<_>>() {
            self.index_tunnel(id);
        }
        for (sid, record) in &self.sessions {
            if let Some(registration) = record.state.registration() {
                self.index.sessions.insert(registration.index, *sid);
                self.index.registrations.insert(*sid, registration.index);
            }
        }
        self.retain_devices();
    }

    pub(super) fn index_tunnel(&mut self, id: u32) {
        let record = &self.tunnels[&id];
        for name in [record.config.bind_interface().copied(), self.zone_name(id)]
            .into_iter()
            .flatten()
        {
            self.index.names.entry(name).or_default().insert(id);
        }
        for device in [record.bind_index, record.zone_index, record.bound]
            .into_iter()
            .flatten()
        {
            self.index.devices.entry(device).or_default().insert(id);
        }
        if let Some(source) = self.source_of(id) {
            self.index.sources.entry(source).or_default().insert(id);
        }
    }

    pub(super) fn unindex_tunnel(&mut self, id: u32) {
        let record = &self.tunnels[&id];
        for name in [record.config.bind_interface().copied(), self.zone_name(id)]
            .into_iter()
            .flatten()
        {
            remove(&mut self.index.names, name, id);
        }
        for device in [record.bind_index, record.zone_index, record.bound]
            .into_iter()
            .flatten()
        {
            remove(&mut self.index.devices, device, id);
        }
        if let Some(source) = self.source_of(id) {
            remove(&mut self.index.sources, source, id);
        }
    }

    pub(super) fn index_session(&mut self, sid: u32) {
        if let Some(registration) = self.sessions[&sid].state.registration() {
            self.index.sessions.insert(registration.index, sid);
            self.index.registrations.insert(sid, registration.index);
        }
    }

    pub(super) fn unindex_session(&mut self, sid: u32) {
        if let Some(index) = self.index.registrations.remove(&sid)
            && self.index.sessions.get(&index) == Some(&sid)
        {
            self.index.sessions.remove(&index);
        }
    }
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
                    self.verify_sessions.insert(session_id);
                    self.verify_session(session_id);
                }
            }
            Notice::Loss if source == Source::Monitor => self.monitor_resync(),
            Notice::Loss => {
                self.l2tp_pending = true;
                self.l2tp_resync();
            }
        }
        self.arm_tick();
    }

    fn owned_session(&self, index: u32) -> Option<u32> {
        self.index.sessions.get(&index).copied().filter(|sid| {
            self.sessions
                .get(sid)
                .is_some_and(|s| s.state.registration().is_some_and(|r| r.index == index))
        })
    }

    fn zone_name(&self, tunnel_id: u32) -> Option<L2tpIfName> {
        self.real_peer(tunnel_id)?.zone
    }

    /// A device appeared, was renamed or changed state (E1, E2, E4).
    fn link_new(&mut self, link: LinkInfo) {
        let previous = self.masters.get(&link.index).copied();
        let relevant = self.index.devices.contains_key(&link.index)
            || self.index.names.contains_key(&link.name)
            || self.vrfs.contains(&link.index);
        if relevant {
            if self.remember_device(&link).is_err() {
                self.monitor_pending = true;
            }
            if !link.vrf {
                self.vrfs.remove(&link.index);
            }
        }
        if relevant
            || link
                .master
                .is_some_and(|master| self.vrfs.contains(&master))
        {
            match link.master {
                Some(master) => {
                    self.masters.insert(link.index, master);
                }
                None => {
                    self.masters.remove(&link.index);
                }
            }
        } else {
            self.masters.remove(&link.index);
        }
        let controller_changed = previous != link.master;
        if let Some(sid) = self.owned_session(link.index) {
            self.session_device_changed(sid, link.name, link.up);
        }
        let ids: BTreeSet<_> = self
            .index
            .names
            .get(&link.name)
            .into_iter()
            .flatten()
            .chain(self.index.devices.get(&link.index).into_iter().flatten())
            .chain(
                previous
                    .into_iter()
                    .chain(link.master)
                    .flat_map(|m| self.index.devices.get(&m).into_iter().flatten()),
            )
            .copied()
            .collect();
        let tracked = !ids.is_empty() || relevant || previous.is_some();
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
        if tracked {
            self.retain_devices();
        }
        self.resolver_device_changed(&link.name, Some(link.index));
    }

    /// A device left the namespace (E3, S19, S27).
    fn link_del(&mut self, link: LinkInfo) {
        self.vrfs.remove(&link.index);
        let master = self.masters.remove(&link.index);
        if let Some(sid) = self.owned_session(link.index) {
            self.observed_removal(sid);
            if !self.sessions.contains_key(&sid) {
                self.recreate_session(sid);
            }
        }
        let ids: BTreeSet<_> = self
            .index
            .devices
            .get(&link.index)
            .into_iter()
            .flatten()
            .chain(
                master
                    .into_iter()
                    .flat_map(|m| self.index.devices.get(&m).into_iter().flatten()),
            )
            .copied()
            .collect();
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
        self.resolver_device_changed(&link.name, Some(link.index));
    }

    /// E6, E7: connected tunnels of the address's family bound to its
    /// device or to that device's VRF reselect their source; an unbound
    /// tunnel does when the address it selected is removed.
    fn addr_changed(&mut self, addr: AddrInfo, removed: bool) {
        let key = (addr.index, addr.addr.to_canonical());
        if self.address_devices.contains(&addr.index) {
            if removed {
                self.addresses.remove(&key);
            } else if !self.addresses.insert(key) {
                return;
            }
        } else if !removed {
            return;
        }
        let family = if addr.addr.to_canonical().is_ipv4() {
            Family::V4
        } else {
            Family::V6
        };
        let vrf_of_device = self.masters.get(&addr.index).copied();
        let ids: BTreeSet<_> = self
            .index
            .devices
            .get(&addr.index)
            .into_iter()
            .flatten()
            .chain(
                vrf_of_device
                    .into_iter()
                    .flat_map(|m| self.index.devices.get(&m).into_iter().flatten()),
            )
            .chain(
                removed
                    .then(|| self.index.sources.get(&addr.addr.to_canonical()))
                    .flatten()
                    .into_iter()
                    .flatten(),
            )
            .copied()
            .collect();
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
    pub(super) fn tunnel_announced(&mut self, tunnel_id: u32) {
        if !self.tunnels.contains_key(&tunnel_id) {
            return;
        }
        self.verify_tunnels.insert(tunnel_id);
        if let Ok(None) = self.k.tunnel(tunnel_id) {
            self.verify_tunnels.remove(&tunnel_id);
            let label = self.tunnel_label(tunnel_id);
            self.report.begin_error(&label, "deleted", || {
                "was deleted in the kernel outside the daemon; this is unsupported (T9)".into()
            });
        }
    }

    /// E27: an announced deletion is verified locally; a session confirmed
    /// absent is created again (S27, S29), a present one is kept and
    /// verified again on the tick.
    pub(super) fn verify_session(&mut self, sid: u32) -> bool {
        let tid = self.sessions[&sid].tunnel_id;
        match self.k.session(tid, sid) {
            Ok(None) => {
                let label = self.session_label_of(sid);
                self.forget_session(sid);
                log::warn!("{label}: deleted outside the daemon; creating it again (S27)");
                self.recreate_session(sid);
                true
            }
            Ok(Some(_)) => self.sessions[&sid]
                .state
                .registration()
                .is_some_and(|registration| {
                    self.k.prove(registration) == crate::kernel::Proof::Proved
                }),
            Err(e) => {
                log::debug!(
                    "verification of session_id={sid} failed: {}",
                    report::describe(&e)
                );
                false
            }
        }
    }

    fn recreate_session(&mut self, sid: u32) {
        self.create_wanted_sessions();
        if self.sessions.contains_key(&sid) && !self.converge_session(sid) {
            self.incomplete = true;
            self.reconcile_at.get_or_insert(self.k.now() + super::RETRY);
        }
    }

    fn session_label_of(&self, sid: u32) -> String {
        let r = &self.sessions[&sid];
        report::session(&r.name, r.tunnel_id, sid)
    }

    /// E20, event monitor: every binding checked by name, every connected
    /// tunnel reconnected, deferred addresses re-checked, resolver devices
    /// validated again.
    pub(super) fn monitor_resync(&mut self) {
        self.monitor_pending = true;
        self.report.begin("event monitor", "loss", || {
            "lost notifications; resynchronising (E20)".into()
        });
        let Ok(links) = self.k.dump_links() else {
            return;
        };
        self.vrfs = links
            .iter()
            .filter(|link| link.vrf && self.index.devices.contains_key(&link.index))
            .map(|link| link.index)
            .collect();
        self.masters = links
            .iter()
            .filter(|link| {
                self.index.devices.contains_key(&link.index)
                    || link
                        .master
                        .is_some_and(|master| self.vrfs.contains(&master))
            })
            .filter_map(|link| Some((link.index, link.master?)))
            .collect();
        for link in &links {
            if self.masters.values().any(|master| *master == link.index) && link.vrf {
                self.vrfs.insert(link.index);
            }
        }
        self.address_devices.clear();
        self.monitor_pending = false;
        for link in &links {
            if let Some(sid) = self.owned_session(link.index) {
                self.session_device_changed(sid, link.name, link.up);
            }
        }
        self.retain_devices();
        if self.monitor_pending {
            return;
        }
        self.report
            .end("event monitor", "loss", || "resynchronised (E20)".into());
        let ids: Vec<u32> = self.tunnels.keys().copied().collect();
        for id in ids {
            let record = self.tunnels.get_mut(&id).unwrap();
            record.stale = record.connection.is_connected();
            self.converge_tunnel(id);
        }
        let sids: Vec<u32> = self.sessions.keys().copied().collect();
        for sid in sids {
            if !self.converge_session(sid) {
                self.incomplete = true;
                self.reconcile_at.get_or_insert(self.k.now() + super::RETRY);
            }
        }
        let names: Vec<L2tpIfName> = self
            .accepted
            .resolvers()
            .values()
            .flat_map(|r| {
                r.bind_interface()
                    .into_iter()
                    .chain(r.addresses().iter().filter_map(|s| s.zone()))
                    .copied()
            })
            .collect();
        for name in names {
            self.resolver_device_changed(&name, None);
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
                Ok(None) => {
                    self.verify_session(sid);
                }
                Ok(Some(_)) => {}
                Err(_) => complete = false,
            }
        }
        if complete {
            self.l2tp_pending = false;
        }
    }
}

impl<K: Kernel> Reconciler<K> {
    pub(super) fn remember_device(&mut self, link: &LinkInfo) -> std::io::Result<()> {
        if link.vrf && !self.vrfs.contains(&link.index) {
            let members = self.k.dump_links()?;
            self.vrfs.insert(link.index);
            for member in members {
                if member.master == Some(link.index) {
                    self.masters.entry(member.index).or_insert(link.index);
                }
            }
        }
        if let Some(master) = link.master {
            self.masters.entry(link.index).or_insert(master);
            if self
                .k
                .link_by_index(master)?
                .is_some_and(|parent| parent.vrf)
            {
                self.vrfs.insert(master);
            }
        }
        Ok(())
    }

    pub(super) fn retain_devices(&mut self) {
        self.masters.retain(|index, master| {
            self.index.devices.contains_key(index) || self.index.devices.contains_key(master)
        });
        self.vrfs.retain(|index| {
            self.index.devices.contains_key(index)
                || self.masters.values().any(|master| master == index)
        });
        let watched: BTreeSet<_> = self
            .index
            .devices
            .keys()
            .chain(self.masters.keys())
            .copied()
            .collect();
        self.addresses.retain(|(index, _)| watched.contains(index));
        if !watched.is_subset(&self.address_devices) {
            match self.k.dump_addrs() {
                Ok(addresses) => {
                    for address in addresses {
                        if watched.contains(&address.index)
                            && !self.address_devices.contains(&address.index)
                        {
                            self.addresses
                                .insert((address.index, address.addr.to_canonical()));
                        }
                    }
                }
                Err(_) => {
                    self.monitor_pending = true;
                    return;
                }
            }
        }
        self.address_devices = watched;
    }
}
