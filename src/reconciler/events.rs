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
        self.changed_devices
            .extend(self.index.devices.keys().copied());
        self.changed_bindings
            .extend(self.index.devices.keys().copied());
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
            self.changed_devices.insert(device);
            self.changed_bindings.insert(device);
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
            self.changed_devices.insert(device);
            self.changed_bindings.insert(device);
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
                    && self.session_wanted(session_id).is_some()
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
            || self.vrfs.contains_key(&link.index);
        if relevant {
            let inventory = self.index.devices.contains_key(&link.index)
                || self.index.names.contains_key(&link.name);
            if self.remember_device(&link, inventory).is_err() {
                self.monitor_pending = true;
            }
            if !link.vrf {
                self.vrfs.remove(&link.index);
            }
        }
        if relevant
            || link.master.is_some_and(|master| {
                self.vrfs.contains_key(&master) && self.index.devices.contains_key(&master)
            })
        {
            self.set_master(link.index, link.master);
        } else {
            self.set_master(link.index, None);
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
                        .any(|m| self.vrfs.contains_key(m)))
                    || record.bind_index.is_some_and(|b| {
                        self.vrfs.contains_key(&b)
                            && (previous == Some(b) || link.master == Some(b))
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
        let master = self.masters.get(&link.index).copied();
        self.set_master(link.index, None);
        if let Some(sid) = self.owned_session(link.index) {
            let record = &self.sessions[&sid];
            let creation = record.created_as.map(|name| (name, record.tunnel_id));
            self.observed_removal(sid);
            if !self.sessions.contains_key(&sid) {
                self.recreate_session(sid, creation);
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
        let address = addr.addr.to_canonical();
        if self.address_devices.contains(&addr.index) {
            if removed {
                if let Some(addresses) = self.addresses.get_mut(&addr.index) {
                    addresses.remove(&address);
                    if addresses.is_empty() {
                        self.addresses.remove(&addr.index);
                    }
                }
            } else if !self
                .addresses
                .entry(addr.index)
                .or_default()
                .insert(address)
            {
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
                                vrf_of_device == Some(b) && self.vrfs.contains_key(&b)
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
                let creation = self.sessions[&sid].created_as.map(|name| (name, tid));
                self.forget_session(sid);
                log::warn!("{label}: deleted outside the daemon; creating it again (S27)");
                self.recreate_session(sid, creation);
                true
            }
            Ok(Some(_)) => false,
            Err(e) => {
                log::debug!(
                    "verification of session_id={sid} failed: {}",
                    report::describe(&e)
                );
                false
            }
        }
    }

    fn recreate_session(&mut self, sid: u32, creation: Option<(L2tpIfName, u32)>) {
        // Both callers confirmed this session absent; other reservations stay (S4).
        if let Some((name, tid)) = creation
            && self.reserved.get(&name) == Some(&(tid, sid))
        {
            self.reserved.remove(&name);
        }
        if let Some(name) = self.wanted_sessions.get(&sid) {
            self.create_wanted_session(name.clone(), self.accepted.sessions()[name].clone());
        }
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
        let mut links = BTreeMap::new();
        if self
            .k
            .scan_links(0, &mut |link| {
                if self.index.devices.contains_key(&link.index)
                    || self.index.sessions.contains_key(&link.index)
                {
                    links.insert(link.index, link.clone());
                }
            })
            .is_err()
        {
            return;
        }
        let watched_vrfs: BTreeSet<_> = links
            .values()
            .filter(|link| link.vrf && self.index.devices.contains_key(&link.index))
            .map(|link| link.index)
            .collect();
        let parents: BTreeSet<_> = links
            .values()
            .filter(|link| self.index.devices.contains_key(&link.index))
            .filter_map(|link| link.master)
            .collect();
        // Members can precede their VRF, so discover dependencies before streaming them.
        if (!watched_vrfs.is_empty() || !parents.is_empty())
            && self
                .k
                .scan_links(0, &mut |link| {
                    if parents.contains(&link.index)
                        || link
                            .master
                            .is_some_and(|master| watched_vrfs.contains(&master))
                    {
                        links.insert(link.index, link.clone());
                    }
                })
                .is_err()
        {
            return;
        }
        self.changed_devices
            .extend(self.address_devices.iter().copied());
        self.vrfs = links
            .values()
            .filter(|link| link.vrf && self.index.devices.contains_key(&link.index))
            .map(|link| (link.index, true))
            .collect();
        self.masters = links
            .values()
            .filter(|link| {
                self.index.devices.contains_key(&link.index)
                    || link.master.is_some_and(|master| {
                        self.vrfs.contains_key(&master) && self.index.devices.contains_key(&master)
                    })
            })
            .filter_map(|link| Some((link.index, link.master?)))
            .collect();
        self.members.clear();
        for (member, master) in &self.masters {
            self.members.entry(*master).or_default().insert(*member);
        }
        for link in links.values() {
            if self.members.contains_key(&link.index) && link.vrf {
                self.vrfs
                    .insert(link.index, self.index.devices.contains_key(&link.index));
            }
        }
        self.addresses.clear();
        self.address_devices.clear();
        self.changed_devices.extend(
            self.index
                .devices
                .keys()
                .chain(self.masters.keys())
                .copied(),
        );
        self.monitor_pending = false;
        for link in links.values() {
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
    pub(super) fn remember_device(
        &mut self,
        link: &LinkInfo,
        inventory: bool,
    ) -> std::io::Result<()> {
        if link.vrf && inventory && self.vrfs.get(&link.index) != Some(&true) {
            let mut members = Vec::new();
            self.k.scan_links(link.index, &mut |member| {
                // Preserve the prior master until its ordered link event arrives.
                if !self.masters.contains_key(&member.index) {
                    members.push(member.index);
                }
            })?;
            self.vrfs.insert(link.index, true);
            self.changed_devices.insert(link.index);
            for member in members {
                self.set_master(member, Some(link.index));
            }
        }
        if let Some(master) = link.master
            && self.masters.get(&link.index) != Some(&master)
        {
            let parent = self.k.link_by_index(master)?;
            self.set_master(link.index, Some(master));
            if parent.is_some_and(|parent| parent.vrf) {
                self.vrfs.entry(master).or_insert(false);
            }
        }
        Ok(())
    }

    fn set_master(&mut self, index: u32, master: Option<u32>) {
        if self.masters.get(&index).copied() == master {
            return;
        }
        if let Some(previous) = self.masters.remove(&index) {
            remove(&mut self.members, previous, index);
            self.changed_devices.insert(previous);
        }
        if let Some(master) = master {
            self.masters.insert(index, master);
            self.members.entry(master).or_default().insert(index);
            self.changed_devices.insert(master);
        }
        self.changed_devices.insert(index);
    }

    pub(super) fn retain_devices(&mut self) {
        let mut seed = BTreeSet::new();
        while let Some(index) = self.changed_devices.pop_first() {
            let binding_changed = self.changed_bindings.remove(&index);
            if binding_changed && !self.index.devices.contains_key(&index) {
                if let Some(complete) = self.vrfs.get_mut(&index) {
                    *complete = false;
                }
                let children: Vec<_> = self
                    .members
                    .get(&index)
                    .into_iter()
                    .flatten()
                    .copied()
                    .collect();
                for child in children {
                    if !self.index.devices.contains_key(&child) {
                        self.set_master(child, None);
                    }
                }
            }
            if let Some(master) = self.masters.get(&index).copied()
                && !self.index.devices.contains_key(&index)
                && !self.index.devices.contains_key(&master)
            {
                self.set_master(index, None);
            }
            if !self.index.devices.contains_key(&index) && !self.members.contains_key(&index) {
                self.vrfs.remove(&index);
            }
            let watched =
                self.index.devices.contains_key(&index) || self.masters.contains_key(&index);
            if !watched {
                self.addresses.remove(&index);
                self.address_devices.remove(&index);
                seed.remove(&index);
            } else if !self.address_devices.contains(&index) {
                seed.insert(index);
            }
        }
        if seed.is_empty() {
            return;
        }
        let mut addresses: BTreeMap<u32, BTreeSet<IpAddr>> = BTreeMap::new();
        let scanned = seed.iter().try_for_each(|&index| {
            self.k.scan_addrs(index, &mut |address| {
                addresses
                    .entry(address.index)
                    .or_default()
                    .insert(address.addr.to_canonical());
            })
        });
        match scanned {
            Ok(()) => {
                for (index, values) in addresses {
                    self.addresses.entry(index).or_default().extend(values);
                }
                self.address_devices.extend(seed);
            }
            Err(_) => {
                self.monitor_pending = true;
            }
        }
    }
}

#[cfg(all(test, feature = "fake-kernel", feature = "serde"))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod resource_tests {
    use super::*;
    use crate::kernel::fake::FakeKernel;
    use crate::reconciler::{Lookup, Resolve};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Watches(Arc<Mutex<BTreeSet<u64>>>);
    impl Resolve for Watches {
        fn watch(&mut self, lookup: Lookup) -> std::io::Result<()> {
            assert!(self.0.lock().unwrap().insert(lookup.id()));
            Ok(())
        }
        fn unwatch(&mut self, id: u64) {
            self.0.lock().unwrap().remove(&id);
        }
        fn poll(&mut self) -> Vec<(u64, Vec<IpAddr>)> {
            Vec::new()
        }
    }

    fn drain(r: &mut Reconciler<FakeKernel>) {
        loop {
            let monitor = r.k.take_monitor();
            let l2tp = r.k.take_l2tp();
            if monitor.is_empty() && l2tp.is_empty() {
                break;
            }
            for notice in monitor {
                r.handle(Source::Monitor, notice);
            }
            for notice in l2tp {
                r.handle(Source::L2tp, notice);
            }
        }
        assert!(r.take_requests().is_empty());
    }

    fn sizes(r: &Reconciler<FakeKernel>) -> [usize; 32] {
        [
            r.wanted_tunnels.len(),
            r.wanted_sessions.len(),
            r.tunnels.len(),
            r.sessions.len(),
            r.reserved.len(),
            r.departing.len(),
            r.deleting_sessions.len(),
            r.unmatched_sessions.len(),
            r.verify_sessions.len(),
            r.verify_tunnels.len(),
            r.conflicts.len(),
            r.conflict_times.len(),
            r.retries.len(),
            r.requests.len(),
            r.request_names.len(),
            r.vrfs.len(),
            r.masters.len(),
            r.members.len(),
            r.members.values().map(BTreeSet::len).sum(),
            r.changed_devices.len(),
            r.changed_bindings.len(),
            r.address_devices.len(),
            r.addresses.len(),
            r.addresses.values().map(BTreeSet::len).sum(),
            r.index.names.len(),
            r.index.names.values().map(BTreeSet::len).sum(),
            r.index.devices.len(),
            r.index.devices.values().map(BTreeSet::len).sum(),
            r.index.sources.len(),
            r.index.sources.values().map(BTreeSet::len).sum(),
            r.index.sessions.len(),
            r.index.registrations.len(),
        ]
    }

    /// spec: S4, S27, G4, G23
    #[test]
    fn confirmed_absence_releases_only_the_matching_creation_reservation() {
        let mut r = Reconciler::new(FakeKernel::new(42), Box::new(Watches::default()));
        let own = L2tpIfName::new(b"own").unwrap();
        let other_tunnel = L2tpIfName::new(b"other-tunnel").unwrap();
        let other_session = L2tpIfName::new(b"other-session").unwrap();
        r.reserved.insert(own, (10, 100));
        r.reserved.insert(other_tunnel, (11, 100));
        r.reserved.insert(other_session, (10, 101));
        r.recreate_session(100, Some((other_tunnel, 10)));
        r.recreate_session(100, Some((other_session, 10)));
        r.recreate_session(100, None);
        assert_eq!(r.reserved.len(), 3);
        r.recreate_session(100, Some((own, 10)));
        assert_eq!(r.reserved.len(), 2);
        assert_eq!(r.reserved[&other_tunnel], (11, 100));
        assert_eq!(r.reserved[&other_session], (10, 101));
        assert!(r.k.ops().is_empty());
    }

    /// spec: G23, M16, V7, S25, T8
    #[test]
    fn completed_configuration_history_releases_records_indexes_and_watches() {
        let _socket_workload = crate::reconciler::tests::socket_workload();
        let watches = Watches::default();
        let mut kernel = FakeKernel::new(42);
        let base = kernel.add_link("base0", false);
        kernel.add_addr(base, "192.0.2.1".parse().unwrap());
        let base_text = "[host]\nfix_bindv6only=false\n[tunnels.base]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='base0'\n[sessions.base]\ntunnel_name='base'\nsession_id=100\ninterface_name='survivor'\n";
        let baseline: crate::config::Config = toml::from_str(base_text).unwrap();
        let mut r = Reconciler::new(kernel, Box::new(watches.clone()));
        assert!(r.reconcile(baseline.clone()));
        drain(&mut r);
        let survivor = r.k.session_index(10, 100).unwrap();
        let expected = sizes(&r);
        for (epoch, count) in [1, 100, 300, 300, 100, 1, 300, 1].into_iter().enumerate() {
            let mut text = base_text.to_owned();
            let mut devices = Vec::new();
            for n in 0..count {
                let id = 1000 + epoch * 1000 + n;
                let name = format!("wan{epoch}_{n}");
                let device = r.k.add_link(&name, false);
                r.k.add_addr(device, "192.0.2.1".parse().unwrap());
                devices.push(device);
                text += &format!(
                    "[tunnels.t{id}]\ntunnel_id={id}\nip_version='V4'\nremote_addr='history.example'\nbind_interface='{name}'\n[sessions.s{id}]\ntunnel_name='t{id}'\nsession_id={}\ninterface_name='s{id}'\n",
                    id + 100_000
                );
            }
            assert!(r.reconcile(toml::from_str(&text).unwrap()));
            drain(&mut r);
            assert_eq!(r.tunnels.len(), count + 1);
            assert_eq!(r.sessions.len(), count + 1);
            assert_eq!(watches.0.lock().unwrap().len(), count);
            r.reconcile(baseline.clone());
            for _ in 0..3 {
                r.k.advance(std::time::Duration::from_secs(1));
                r.k.tick();
                drain(&mut r);
                r.tick();
            }
            for device in devices {
                r.k.remove_link(device);
            }
            drain(&mut r);
            assert_eq!(sizes(&r), expected, "retained state after epoch {epoch}");
            assert_eq!(r.accepted(), &baseline);
            assert!(watches.0.lock().unwrap().is_empty());
            assert!(!r.resolvers.any());
            assert_eq!(r.next_deadline(), None);
            assert_eq!(r.k.session_index(10, 100), Some(survivor));
            assert!(r.ready());
            r.k.clear_ops();
            println!(
                "RESOURCE_HISTORY epoch={epoch} removed={count} survivors=1 sizes={expected:?}"
            );
        }
    }
    /// spec: G23, M16, E4, E20
    #[test]
    fn current_dependency_inventories_stream_and_release_their_final_reference() {
        for count in [1, 100, 10_000] {
            for vrf in [false, true] {
                let mut kernel = FakeKernel::new(42);
                let members: Vec<_> = (0..count)
                    .map(|n| kernel.add_link(&format!("member{n}"), false))
                    .collect();
                let wanted = kernel.add_link("wanted", vrf);
                let unrelated = kernel.add_link("unrelated", true);
                for (n, member) in members.iter().copied().enumerate() {
                    let addr = IpAddr::from([10, 0, (n >> 8) as u8, n as u8]);
                    if vrf {
                        kernel.set_master(member, Some(wanted));
                        kernel.add_addr(member, addr);
                    } else {
                        kernel.add_addr(wanted, addr);
                    }
                    let noise = kernel.add_link(&format!("noise{n}"), false);
                    kernel.set_master(noise, Some(unrelated));
                    kernel.add_addr(noise, IpAddr::from([198, 19, (n >> 8) as u8, n as u8]));
                }
                kernel.take_monitor();
                let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
                let config = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='wanted'\n";
                assert!(r.reconcile(toml::from_str(config).unwrap()));
                assert_eq!(r.tunnels.len(), 1);
                assert_eq!(r.masters.len(), if vrf { count } else { 0 });
                assert_eq!(
                    r.addresses.values().map(BTreeSet::len).sum::<usize>(),
                    count
                );
                assert!(!r.vrfs.contains_key(&unrelated));
                let expected = sizes(&r);
                r.handle(Source::Monitor, Notice::Loss);
                assert!(!r.monitor_pending);
                assert_eq!(sizes(&r), expected);
                assert!(!r.addresses.contains_key(&unrelated));
                assert!(r.reconcile(toml::from_str("[host]\nfix_bindv6only=false\n").unwrap()));
                for _ in 0..3 {
                    r.k.advance(std::time::Duration::from_secs(1));
                    r.k.tick();
                    r.tick();
                }
                assert_eq!(sizes(&r), [0; 32], "count={count}, vrf={vrf}");
                assert_eq!(r.next_deadline(), None);
            }
        }
    }

    /// spec: G23, M16, E4, E20, T10
    #[test]
    fn bound_member_resync_retains_its_parent_without_sibling_state() {
        for count in [1, 100, 10_000] {
            for vrf in [false, true] {
                let mut kernel = FakeKernel::new(42);
                let member = kernel.add_link("wanted", false);
                let parent = kernel.add_link("parent", vrf);
                kernel.set_master(member, Some(parent));
                let address = "192.0.2.1".parse().unwrap();
                kernel.add_addr(member, address);
                for n in 0..count {
                    let sibling = kernel.add_link(&format!("sibling{n}"), false);
                    kernel.set_master(sibling, Some(parent));
                    kernel.add_addr(sibling, IpAddr::from([198, 19, (n >> 8) as u8, n as u8]));
                }
                kernel.take_monitor();
                let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
                let config = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='wanted'\n";
                assert!(r.reconcile(toml::from_str(config).unwrap()));
                let socket = r.tunnels[&10].socket;
                for resync in [false, true] {
                    if resync {
                        r.handle(Source::Monitor, Notice::Loss);
                    }
                    assert!(!r.monitor_pending);
                    assert_eq!(r.masters, BTreeMap::from([(member, parent)]));
                    assert_eq!(
                        r.members,
                        BTreeMap::from([(parent, BTreeSet::from([member]))])
                    );
                    assert_eq!(
                        r.vrfs,
                        if vrf {
                            BTreeMap::from([(parent, false)])
                        } else {
                            BTreeMap::new()
                        }
                    );
                    assert_eq!(r.address_devices, BTreeSet::from([member]));
                    assert_eq!(
                        r.addresses,
                        BTreeMap::from([(member, BTreeSet::from([address]))])
                    );
                    assert_eq!(r.tunnels[&10].socket, socket);
                    assert_eq!(
                        r.k.connection(socket).map(|(_, source)| source),
                        Some(address)
                    );
                    assert_eq!(r.tunnels[&10].bound, Some(member));
                }
                assert!(r.reconcile(toml::from_str("[host]\nfix_bindv6only=false\n").unwrap()));
                for _ in 0..3 {
                    r.k.advance(std::time::Duration::from_secs(1));
                    r.k.tick();
                    r.tick();
                }
                assert_eq!(sizes(&r), [0; 32], "siblings={count}, vrf={vrf}");
                assert_eq!(r.next_deadline(), None);
            }
        }
    }

    /// spec: G23, M3, E20, E22
    #[test]
    fn failed_inventory_completion_never_commits_visited_partial_state() {
        for completed in [0, 1, 2, 3, 4] {
            let mut kernel = FakeKernel::new(42);
            let member = kernel.add_link("member", false);
            let wanted = kernel.add_link("wanted", true);
            kernel.set_master(member, Some(wanted));
            kernel.add_addr(member, "192.0.2.1".parse().unwrap());
            let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
            let config = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='wanted'\n";
            if completed == 0 {
                r.k.fail_after("dump-end", 1, nix::errno::Errno::EIO);
                assert!(!r.reconcile(toml::from_str(config).unwrap()));
                assert!(r.masters.is_empty());
                assert!(r.vrfs.is_empty());
                assert!(r.addresses.is_empty());
                r.k.advance(std::time::Duration::from_secs(1));
                r.tick();
            }
            assert!(r.reconcile(toml::from_str(config).unwrap()));
            r.k.take_monitor();
            let old = (
                r.masters.clone(),
                r.members.clone(),
                r.vrfs.clone(),
                r.addresses.clone(),
                r.address_devices.clone(),
            );
            let added = r.k.add_link("added", false);
            r.k.set_master(added, Some(wanted));
            let address = "192.0.2.2".parse().unwrap();
            r.k.add_addr(added, address);
            r.k.fail_after("dump-end", completed, nix::errno::Errno::EIO);
            r.handle(Source::Monitor, Notice::Loss);
            assert!(r.monitor_pending);
            if completed < 2 {
                assert_eq!(
                    (
                        r.masters.clone(),
                        r.members.clone(),
                        r.vrfs.clone(),
                        r.addresses.clone(),
                        r.address_devices.clone()
                    ),
                    old,
                    "failed link pass {completed}",
                );
            } else {
                assert_eq!(r.masters.get(&added), Some(&wanted));
                assert!(r.addresses.is_empty());
                assert!(r.address_devices.is_empty());
            }
            r.k.advance(std::time::Duration::from_secs(1));
            r.tick();
            assert!(!r.monitor_pending);
            assert_eq!(r.masters.get(&added), Some(&wanted));
            assert!(r.addresses[&added].contains(&address));
            assert_eq!(r.addresses.values().map(BTreeSet::len).sum::<usize>(), 2);
            assert_eq!(r.next_deadline(), None);
        }
    }

    /// spec: E4, M16, G23, T21
    #[test]
    fn a_new_vrf_inventory_preserves_the_previous_master_until_its_ordered_change() {
        let mut kernel = FakeKernel::new(42);
        let blue = kernel.add_link("blue", true);
        let member = kernel.add_link("member", false);
        kernel.set_up(blue, true);
        kernel.set_up(member, true);
        kernel.set_master(member, Some(blue));
        let source = "2001:db8:1::1".parse().unwrap();
        kernel.add_addr(member, source);
        let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
        let config = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='2001:db8:1::2'\nbind_interface='blue'\n[tunnels.b]\ntunnel_id=20\nremote_addr='2001:db8:1::2'\nbind_interface='red'\n";
        r.reconcile(toml::from_str(config).unwrap());
        r.k.take_monitor();
        assert_eq!(r.masters.get(&member), Some(&blue));
        let red = r.k.add_link("red", true);
        r.k.set_up(red, true);
        r.k.set_master(member, Some(red));
        let link = r.k.link_by_index(red).unwrap().unwrap();
        assert!(!r.vrfs.contains_key(&red));
        r.handle(Source::Monitor, Notice::LinkNew(link));
        assert_eq!(r.masters.get(&member), Some(&blue));
        let member_event = r.k.link_by_index(member).unwrap().unwrap();
        r.handle(Source::Monitor, Notice::LinkNew(member_event));
        assert_eq!(r.masters.get(&member), Some(&red));
        assert!(!r.members.contains_key(&blue));
        assert_eq!(r.members.get(&red), Some(&BTreeSet::from([member])));
        assert!(r.addresses[&member].contains(&source));
        assert!(r.k.connection(r.tunnels[&10].socket).is_none());
        assert_eq!(
            r.k.connection(r.tunnels[&20].socket)
                .map(|(_, source)| source),
            Some(source)
        );
    }

    /// spec: E4, M16, G23, T21
    #[test]
    fn binding_a_known_parent_vrf_inventories_its_previously_unwatched_members() {
        let mut kernel = FakeKernel::new(42);
        let vrf = kernel.add_link("blue", true);
        let first = kernel.add_link("member", false);
        let sibling = kernel.add_link("sibling", false);
        for index in [vrf, first, sibling] {
            kernel.set_up(index, true);
        }
        kernel.set_master(first, Some(vrf));
        kernel.set_master(sibling, Some(vrf));
        kernel.add_addr(first, "2001:db8:1::1".parse().unwrap());
        let address = "2001:db8:1::3".parse().unwrap();
        kernel.add_addr(sibling, address);
        let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
        let one = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='2001:db8:1::2'\nbind_interface='member'\n";
        r.reconcile(toml::from_str(one).unwrap());
        assert!(r.vrfs.contains_key(&vrf));
        assert_eq!(r.members.get(&vrf), Some(&BTreeSet::from([first])));
        let both = format!(
            "{one}[tunnels.b]\ntunnel_id=20\nremote_addr='2001:db8:1::2'\nbind_interface='blue'\n"
        );
        r.reconcile(toml::from_str(&both).unwrap());
        assert_eq!(r.members.get(&vrf), Some(&BTreeSet::from([first, sibling])));
        assert!(r.addresses[&sibling].contains(&address));
        assert_eq!(r.vrfs.get(&vrf), Some(&true));
        assert!(r.reconcile(toml::from_str(one).unwrap()));
        assert_eq!(r.vrfs.get(&vrf), Some(&false));
        assert_eq!(r.members.get(&vrf), Some(&BTreeSet::from([first])));
        assert!(!r.addresses.contains_key(&sibling));
        r.k.fail_next("dump", nix::errno::Errno::EIO);
        let parent_event = r.k.link_by_index(vrf).unwrap().unwrap();
        r.handle(Source::Monitor, Notice::LinkNew(parent_event));
        assert!(
            !r.monitor_pending,
            "an unbound parent must not inventory siblings"
        );
        let parent = r.k.link_by_index(vrf).unwrap().unwrap();
        assert_eq!(
            r.remember_device(&parent, true).unwrap_err().raw_os_error(),
            Some(nix::libc::EIO)
        );
        assert_eq!(r.vrfs.get(&vrf), Some(&false));
        assert_eq!(r.members.get(&vrf), Some(&BTreeSet::from([first])));
        let rebound = both.replace("tunnel_id=20", "tunnel_id=30");
        assert!(r.reconcile(toml::from_str(&rebound).unwrap()));
        assert_eq!(r.vrfs.get(&vrf), Some(&true));
        assert_eq!(r.members.get(&vrf), Some(&BTreeSet::from([first, sibling])));
        assert!(r.addresses[&sibling].contains(&address));
        assert!(r.k.connection(r.tunnels[&30].socket).is_some());
        r.k.take_monitor();
        r.k.clear_ops();
        r.k.add_addr(sibling, "2001:db8:1::4".parse().unwrap());
        let notices = r.k.take_monitor();
        assert_eq!(notices.len(), 1);
        for notice in notices {
            r.handle(Source::Monitor, notice);
        }
        assert_eq!(
            r.k.ops()
                .iter()
                .filter(|op| op.starts_with("disconnect "))
                .count(),
            1
        );
        assert_eq!(
            r.k.ops()
                .iter()
                .filter(|op| op.starts_with("connect "))
                .count(),
            1
        );
    }
}
