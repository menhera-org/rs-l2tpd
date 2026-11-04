//! Ordered link and address notices and their affected tunnel dependencies.
use super::*;

impl<K: Kernel> Reconciler<K> {
    /// A device appeared, was renamed or changed state (E1, E2, E4).
    pub(super) fn link_new(&mut self, link: LinkInfo) {
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
            self.tunnel_link_changed(id, &link, previous);
        }
        if tracked {
            self.retain_devices();
        }
        self.resolver_device_changed(&link.name, Some(link.index));
    }

    fn tunnel_link_changed(&mut self, id: u32, link: &LinkInfo, previous: Option<u32>) {
        let controller_changed = previous != link.master;
        let record = &self.tunnels[&id];
        let bind_name = record.config.bind_interface().copied();
        let zone_name = self.zone_name(id);
        let named = |n: Option<L2tpIfName>, index: Option<u32>| {
            (n == Some(link.name) && index != Some(link.index))
                || (index == Some(link.index) && n != Some(link.name))
        };
        let follows = named(bind_name, record.bind_index) || named(zone_name, record.zone_index);
        // E4: the bound device's L3 domain changed, or the bound VRF's
        // set of members did.
        let domain = controller_changed
            && record
                .bind_index
                .is_some_and(|bind| self.bind_domain_changed(bind, link, previous));
        if domain && record.connection.is_connected() {
            self.tunnels.get_mut(&id).unwrap().stale = true;
        }
        if follows || domain {
            self.converge_tunnel(id);
        }
    }

    fn bind_domain_changed(&self, bind: u32, link: &LinkInfo, previous: Option<u32>) -> bool {
        let masters = [previous, link.master];
        if bind == link.index && masters.iter().flatten().any(|m| self.vrfs.contains_key(m)) {
            return true;
        }
        self.vrfs.contains_key(&bind) && masters.contains(&Some(bind))
    }

    /// A device left the namespace (E3, S19, S27).
    pub(super) fn link_del(&mut self, link: LinkInfo) {
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
    pub(super) fn addr_changed(&mut self, addr: AddrInfo, removed: bool) {
        let address = addr.addr.to_canonical();
        if self.address_devices.contains(&addr.index) {
            if removed {
                remove(&mut self.addresses, addr.index, address);
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
        let ipv4 = address.is_ipv4();
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
                    .then(|| self.index.sources.get(&address))
                    .flatten()
                    .into_iter()
                    .flatten(),
            )
            .copied()
            .collect();
        for id in ids {
            let record = &self.tunnels[&id];
            let crate::reconciler::records::Connection::Connected { peer, .. } = &record.connection
            else {
                continue;
            };
            let effective = record.zone_index.or(record.bind_index);
            let concerns = match effective {
                Some(device) => {
                    peer.addr.to_canonical().is_ipv4() == ipv4
                        && (device == addr.index
                            || record.bind_index.is_some_and(|b| {
                                vrf_of_device == Some(b) && self.vrfs.contains_key(&b)
                            }))
                }
                None => removed && self.source_of(id) == Some(address),
            };
            if concerns {
                self.tunnels.get_mut(&id).unwrap().stale = true;
                self.converge_tunnel(id);
            }
        }
    }
}
