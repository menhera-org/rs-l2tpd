//! Retained device, VRF membership and address inventories.
use super::*;

impl<K: Kernel> Reconciler<K> {
    pub(in crate::reconciler) fn remember_device(
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

    pub(super) fn set_master(&mut self, index: u32, master: Option<u32>) {
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

    fn retain_device_bindings(&mut self, index: u32) {
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
    }

    pub(in crate::reconciler) fn retain_devices(&mut self) {
        let mut seed = BTreeSet::new();
        while let Some(index) = self.changed_devices.pop_first() {
            self.retain_device_bindings(index);
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
