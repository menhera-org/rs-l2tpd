//! Local ownership verification and recovery after notification loss.
use super::*;

impl<K: Kernel> Reconciler<K> {
    /// A tunnel deletion was announced: an operator deleted an owned tunnel,
    /// which is unsupported (T9), or the announcement is foreign (K41).
    pub(in crate::reconciler) fn tunnel_announced(&mut self, tunnel_id: u32) {
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
    pub(in crate::reconciler) fn verify_session(&mut self, sid: u32) -> bool {
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

    pub(super) fn recreate_session(&mut self, sid: u32, creation: Option<(L2tpIfName, u32)>) {
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
            self.reconcile_at
                .get_or_insert(self.k.now() + crate::reconciler::RETRY);
        }
    }

    fn session_label_of(&self, sid: u32) -> String {
        let r = &self.sessions[&sid];
        report::session(&r.name, r.tunnel_id, sid)
    }

    fn monitor_links(&mut self) -> std::io::Result<BTreeMap<u32, LinkInfo>> {
        let mut links = BTreeMap::new();
        self.k.scan_links(0, &mut |link| {
            if self.index.devices.contains_key(&link.index)
                || self.index.sessions.contains_key(&link.index)
            {
                links.insert(link.index, link.clone());
            }
        })?;
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
        if !watched_vrfs.is_empty() || !parents.is_empty() {
            self.k.scan_links(0, &mut |link| {
                if parents.contains(&link.index)
                    || link
                        .master
                        .is_some_and(|master| watched_vrfs.contains(&master))
                {
                    links.insert(link.index, link.clone());
                }
            })?;
        }
        Ok(links)
    }

    /// E20, event monitor: every binding checked by name, every connected
    /// tunnel reconnected, deferred addresses re-checked, resolver devices
    /// validated again.
    pub(in crate::reconciler) fn monitor_resync(&mut self) {
        self.monitor_pending = true;
        self.report.begin("event monitor", "loss", || {
            "lost notifications; resynchronising (E20)".into()
        });
        let Ok(links) = self.monitor_links() else {
            return;
        };
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
                    || link
                        .master
                        .is_some_and(|master| self.vrfs.contains_key(&master))
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
                self.reconcile_at
                    .get_or_insert(self.k.now() + crate::reconciler::RETRY);
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
    pub(in crate::reconciler) fn l2tp_resync(&mut self) {
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
            // Verification can replace only this session's record.
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
