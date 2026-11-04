//! The event handlers (E1–E27): each converges only the entries the event
//! concerns, found by lookup in the daemon's own records; an event that
//! concerns no entry costs a comparison (M5, M16).

use crate::config::L2tpIfName;
use crate::kernel::{AddrInfo, Kernel, LinkInfo, Notice};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use super::{Reconciler, report};

mod device;
mod inventory;
mod recovery;

#[derive(Default)]
pub(super) struct Index {
    names: BTreeMap<L2tpIfName, BTreeSet<u32>>,
    devices: BTreeMap<u32, BTreeSet<u32>>,
    sources: BTreeMap<IpAddr, BTreeSet<u32>>,
    sessions: BTreeMap<u32, u32>,
    registrations: BTreeMap<u32, u32>,
}

pub(super) fn remove<T: Ord, V: Ord>(map: &mut BTreeMap<T, BTreeSet<V>>, key: T, id: V) {
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
}

#[cfg(all(test, feature = "fake-kernel", feature = "serde"))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod resource_tests;
