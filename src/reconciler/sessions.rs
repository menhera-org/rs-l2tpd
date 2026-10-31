//! Session operations (S1–S28): staging under a random name, publication,
//! renames (with temporary names for swaps), deferred hardware addresses,
//! and removal with the proof of S9 or S22.

use std::io;

use nix::errno::Errno;

use crate::config::{L2tpIfName, SessionConfig, SessionIdentity};
use crate::kernel::{Kernel, Proof, SessionCreate, SessionInfo, errno};

use super::records::{ConflictIdentity, Enforce, Identity, SessionRecord};
use super::{Reconciler, report};

/// Draws of a staging name in one attempt (S7).
const DRAWS: usize = 8;

#[cfg(all(test, feature = "fake-kernel", feature = "serde"))]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "wanted_tests.rs"]
mod wanted_tests;

impl<K: Kernel> Reconciler<K> {
    fn session_label(&self, sid: u32) -> String {
        let r = &self.sessions[&sid];
        report::session(&r.name, r.tunnel_id, sid)
    }

    /// The accepted entry of the same kernel identity as the record.
    fn session_wanted(&self, sid: u32) -> Option<(String, SessionConfig)> {
        let record = self.sessions.get(&sid)?;
        let name = self.wanted_sessions.get(&sid)?;
        (self.accepted.session_identity(name) == Some(record.identity))
            .then(|| (name.clone(), self.accepted.sessions()[name].clone()))
    }

    /// A name `prefix` followed by six hexadecimal digits from the
    /// kernel's random source (S4, S11).
    fn random_name(&mut self, prefix: &str) -> io::Result<L2tpIfName> {
        let [a, b, c] = self.k.random()?;
        Ok(L2tpIfName::new(format!("{prefix}{a:02x}{b:02x}{c:02x}").as_bytes()).unwrap())
    }

    /// Free as a creation name: no device bears it, no session stored it,
    /// the daemon has not reserved it (S4).
    fn creation_name_free(&mut self, name: &L2tpIfName) -> io::Result<bool> {
        if self.reserved.contains_key(name) || self.k.link_by_name(name)?.is_some() {
            return Ok(false);
        }
        let mut stored = false;
        self.k
            .scan_sessions(None, &mut |s| stored |= s.ifname.as_ref() == Some(name))?;
        Ok(!stored)
    }

    /// Deletes the sessions the configuration no longer has (S25), before
    /// any tunnel goes (S26).
    pub(super) fn remove_unwanted_sessions(&mut self) {
        let unwanted: Vec<u32> = self
            .sessions
            .keys()
            .copied()
            .filter(|sid| self.session_wanted(*sid).is_none())
            .collect();
        for sid in unwanted {
            let label = self.session_label(sid);
            if self.delete_session(sid) {
                self.forget_session(sid);
                log::info!("{label}: removed");
            } else {
                self.incomplete = true;
            }
        }
    }

    /// Forgets a session record; its creation name stays reserved until
    /// the session is confirmed gone (S4).
    pub(super) fn forget_session(&mut self, sid: u32) {
        self.unindex_session(sid);
        self.verify_sessions.remove(&sid);
        let label = self.session_label(sid);
        let record = self.sessions.remove(&sid).unwrap();
        if let Some(registration) = record.state.registration() {
            self.k.release(registration);
        }
        self.report.forget(&label);
    }

    /// Deletes a session with its proof: by identifiers when the device is
    /// proved or the session adopted (S9, S28); nothing after an observed
    /// removal (S21); by stored name after a verified dump after a loss
    /// (S22). Returns whether the session is gone or forgettable.
    fn delete_session(&mut self, sid: u32) -> bool {
        let record = &self.sessions[&sid];
        let tid = record.tunnel_id;
        let proof = match record.state {
            Identity::Staged(r) | Identity::Proved(r) => self.k.prove(&r),
            Identity::Removed => Proof::Removed,
            Identity::Lost { .. } => Proof::Lost,
            Identity::Adopted => Proof::Proved,
        };
        match proof {
            Proof::Proved => match self.k.delete_session(tid, sid) {
                Ok(()) => {
                    self.deleting_sessions
                        .insert((tid, sid), self.k.now() + super::DELETION_WAIT);
                    true
                }
                Err(e) if errno(&e) == Errno::ENODEV as i32 => true,
                Err(e) => {
                    let label = self.session_label(sid);
                    log::debug!("{label}: deletion failed: {}", report::describe(&e));
                    false
                }
            },
            Proof::Removed => true,
            Proof::Lost => self.delete_verified(sid),
        }
    }

    /// S22: a complete fresh dump must hold exactly one session with the
    /// stored name, matching every identifier and cookie; only then is it
    /// deleted by that name. A refusal leaves the object alone, reported.
    fn delete_verified(&mut self, sid: u32) -> bool {
        let label = self.session_label(sid);
        let record = &self.sessions[&sid];
        let Some(name) = record.created_as else {
            return true;
        };
        let want = (record.tunnel_id, sid, record.config.peer_session_id());
        let identity = record.identity;
        let (mut count, mut matched) = (0, false);
        let tunnel = self.tunnels.get(&want.0).map(|t| t.identity);
        let scan = self.k.scan_sessions(None, &mut |s: &SessionInfo| {
            if s.ifname == Some(name) {
                count += 1;
                // A foreign cookie length (K35) matches no entry.
                matched = (s.tunnel_id, s.session_id, s.peer_session_id) == want
                    && tunnel.zip(s.cookies().ok()).is_some_and(|(t, (c, p))| {
                        SessionIdentity::new(t, s.session_id, s.peer_session_id, c, p) == identity
                    });
            }
        });
        match scan {
            Ok(()) if count == 1 && matched => match self.k.delete_session_by_name(&name) {
                Ok(()) => {
                    self.deleting_sessions
                        .insert((want.0, want.1), self.k.now() + super::DELETION_WAIT);
                    true
                }
                Err(e) if errno(&e) == Errno::ENODEV as i32 => true,
                Err(_) => false,
            },
            Ok(()) if count == 0 => true,
            Ok(()) => {
                self.report.begin(&label, "ambiguous", || {
                    "cannot be deleted safely: its stored name is ambiguous or does not match; left alone (S22)".into()
                });
                false
            }
            Err(e) => {
                log::debug!("{label}: session dump failed: {}", report::describe(&e));
                false
            }
        }
    }

    /// Creates the sessions the configuration has and the kernel lacks,
    /// in tunnels that exist (S3, S4).
    pub(super) fn create_wanted_sessions(&mut self) {
        let wanted: Vec<(String, SessionConfig)> = self
            .accepted
            .sessions()
            .iter()
            .filter(|(_, s)| !self.sessions.contains_key(&s.session_id()))
            .map(|(n, s)| (n.clone(), s.clone()))
            .collect();
        for (name, config) in wanted {
            let tid = self.accepted.tunnels()[config.tunnel_name()].tunnel_id();
            let identity = self.accepted.session_identity(&name).unwrap();
            if self
                .tunnels
                .get(&tid)
                .is_none_or(|t| t.identity != identity.tunnel())
            {
                continue;
            }
            let sid = config.session_id();
            if self.deleting_sessions.contains_key(&(tid, sid)) {
                self.incomplete = true;
                continue;
            }
            let conflict = ConflictIdentity::Session(identity);
            if !self.may_try(true, sid, conflict) {
                continue;
            }
            let label = report::session(&name, tid, sid);
            match self.stage(&name, &config, identity, tid) {
                Ok(()) => {
                    self.conflict_over(true, sid, &label);
                    self.report.end(&label, "create", || "created".into());
                    self.report.forget_condition(&label, "random");
                }
                Err(e) if errno(&e) == Errno::EEXIST as i32 => {
                    self.conflict(true, sid, conflict, &label, &e)
                }
                Err(e) => {
                    self.incomplete = true;
                    self.report.cannot_create(&label, "create", &e);
                }
            }
        }
        if self.incomplete {
            self.reconcile_at.get_or_insert(self.k.now() + super::RETRY);
        }
    }

    /// Creates a session under a fresh staging name (S4, S7, S8).
    fn stage(
        &mut self,
        name: &str,
        config: &SessionConfig,
        identity: SessionIdentity,
        tid: u32,
    ) -> io::Result<()> {
        let mut direct = config.interface_hwaddr().is_none()
            && self.creation_name_free(config.interface_name())?;
        for _ in 0..DRAWS + usize::from(direct) {
            let temp = if direct {
                *config.interface_name()
            } else {
                self.random_name("rsl2tp-t")?
            };
            if !self.creation_name_free(&temp)? {
                direct = false;
                continue;
            }
            let create = SessionCreate {
                tunnel_id: tid,
                session_id: config.session_id(),
                peer_session_id: config.peer_session_id(),
                cookie: config.cookie(),
                peer_cookie: config.peer_cookie(),
                ifname: temp,
            };
            let state = match self.k.create_session(&create) {
                Ok(registration) if direct => Identity::Proved(registration),
                Ok(registration) => Identity::Staged(registration),
                // The outcome is unknown: the kernel's record decides (S23).
                Err(e) if errno(&e) == Errno::ETIMEDOUT as i32 => Identity::Lost { staged: true },
                // A name taken since the check (K20), or the identifier (K19).
                Err(e)
                    if errno(&e) == Errno::EEXIST as i32 || errno(&e) == Errno::ENFILE as i32 =>
                {
                    if self.k.link_by_name(&temp)?.is_some() {
                        direct = false;
                        continue;
                    }
                    return Err(e);
                }
                Err(e) => return Err(e),
            };
            let kernel_hwaddr = match state {
                Identity::Staged(r) | Identity::Proved(r) => {
                    self.k.ether_addr(r.index).ok().flatten()
                }
                _ => None,
            };
            self.reserved.insert(temp, (tid, config.session_id()));
            self.sessions.insert(
                config.session_id(),
                SessionRecord {
                    name: name.to_owned(),
                    config: config.clone(),
                    identity,
                    tunnel_id: tid,
                    state,
                    created_as: Some(temp),
                    current_name: Some(temp),
                    name_state: if direct {
                        Enforce::Applied
                    } else {
                        Enforce::Pending
                    },
                    hwaddr: config.interface_hwaddr().or(kernel_hwaddr),
                    hwaddr_state: if config.interface_hwaddr().is_some() {
                        Enforce::Pending
                    } else {
                        Enforce::Applied
                    },
                    kernel_hwaddr,
                },
            );
            self.index_session(config.session_id());
            log::info!(
                "{}: created as {}",
                report::session(name, tid, config.session_id()),
                temp.to_string_lossy()
            );
            return Ok(());
        }
        Err(io::Error::other(
            "eight staging names in a row are taken by foreign devices (S7)",
        ))
    }

    /// Takes a configuration change that applies in place (S17, M19): a
    /// changed field clears its override and skip.
    pub(super) fn update_sessions_in_place(&mut self) {
        let sids: Vec<u32> = self.sessions.keys().copied().collect();
        for sid in sids {
            let Some((name, config)) = self.session_wanted(sid) else {
                continue;
            };
            let record = self.sessions.get_mut(&sid).unwrap();
            if record.name != name || record.config != config {
                self.report
                    .forget(&report::session(&record.name, record.tunnel_id, sid));
            }
            if record.config.interface_name() != config.interface_name() {
                record.name_state = Enforce::Pending;
            }
            if record.config.interface_hwaddr() != config.interface_hwaddr() {
                record.hwaddr = config.interface_hwaddr().or(record.kernel_hwaddr);
                record.hwaddr_state = Enforce::Pending;
            }
            record.name = name;
            record.config = config;
        }
    }

    /// Renames to temporary names the published devices whose name another
    /// owned device is about to take, so that no rename collides (S11, M6).
    pub(super) fn clear_swaps(&mut self) {
        // Drain acyclic rename dependencies first; only cycles need a
        // temporary name (S11).
        loop {
            let movable =
                self.sessions
                    .iter()
                    .find(|(_, r)| {
                        r.name_state == Enforce::Pending
                            && matches!(r.state, Identity::Proved(_))
                            && r.current_name != Some(*r.config.interface_name())
                            && !self.sessions.values().any(|holder| {
                                holder.current_name == Some(*r.config.interface_name())
                            })
                    })
                    .map(|(sid, _)| *sid);
            let Some(sid) = movable else { break };
            let before = self.sessions[&sid].current_name;
            self.converge_session(sid);
            if self
                .sessions
                .get(&sid)
                .is_some_and(|r| r.current_name == before)
            {
                break;
            }
        }
        let targets: Vec<(u32, L2tpIfName)> = self
            .sessions
            .iter()
            .filter(|(_, r)| {
                r.name_state == Enforce::Pending && matches!(r.state, Identity::Proved(_))
            })
            .map(|(sid, r)| (*sid, *r.config.interface_name()))
            .collect();
        for (sid, target) in &targets {
            let holder = self
                .sessions
                .iter()
                .find(|(other, r)| {
                    other != &sid
                        && r.current_name == Some(*target)
                        && matches!(r.state, Identity::Proved(_))
                })
                .map(|(other, _)| *other);
            let Some(holder) = holder else { continue };
            // Only a holder that is itself moving away gives the name up.
            if !targets
                .iter()
                .any(|(s, t)| *s == holder && Some(*t) != self.sessions[&holder].current_name)
            {
                continue;
            }
            let Identity::Proved(registration) = self.sessions[&holder].state else {
                continue;
            };
            if self.k.prove(&registration) != Proof::Proved {
                continue;
            }
            for _ in 0..DRAWS {
                let temp = match self.random_name("rsl2tp-r") {
                    Ok(name) => name,
                    Err(error) => {
                        let label = self.session_label(holder);
                        self.report.begin(&label, "random", || {
                            format!("temporary name unavailable: {error}")
                        });
                        self.incomplete = true;
                        break;
                    }
                };
                match self.k.rename(registration.index, &temp) {
                    Ok(()) => {
                        self.sessions.get_mut(&holder).unwrap().current_name = Some(temp);
                        break;
                    }
                    Err(e) if errno(&e) == Errno::EEXIST as i32 => continue,
                    Err(_) => break,
                }
            }
        }
    }

    /// Converges one session in place: staging finished, name and hardware
    /// address enforced as M19 says, unmanageable devices left alone
    /// (S5–S7, S10, S12, S20). Returns false when something is to retry.
    pub(super) fn converge_session(&mut self, sid: u32) -> bool {
        let label = self.session_label(sid);
        let record = &self.sessions[&sid];
        let registration = match record.state {
            Identity::Staged(r) | Identity::Proved(r) => r,
            Identity::Lost { staged: true } => return self.restage(sid),
            _ => {
                self.skip_unmanageable(sid);
                return true;
            }
        };
        match self.k.prove(&registration) {
            Proof::Proved => {}
            Proof::Removed => return self.observed_removal(sid),
            Proof::Lost => {
                let staged = matches!(record.state, Identity::Staged(_));
                self.sessions.get_mut(&sid).unwrap().state = Identity::Lost { staged };
                return if staged {
                    self.restage(sid)
                } else {
                    self.skip_unmanageable_then(sid)
                };
            }
        }
        let mut done = self.apply_hwaddr(sid, registration.index);
        if !done {
            return false;
        }
        let record = &self.sessions[&sid];
        if record.name_state == Enforce::Pending {
            let target = *record.config.interface_name();
            let staged = matches!(record.state, Identity::Staged(_));
            if record.current_name == Some(target) {
                let record = self.sessions.get_mut(&sid).unwrap();
                record.name_state = Enforce::Applied;
                record.state = Identity::Proved(registration);
            } else {
                match self.k.prove(&registration) {
                    Proof::Proved => {}
                    Proof::Removed => return self.observed_removal(sid),
                    Proof::Lost => {
                        self.sessions.get_mut(&sid).unwrap().state = Identity::Lost { staged };
                        return if staged {
                            self.restage(sid)
                        } else {
                            self.skip_unmanageable_then(sid)
                        };
                    }
                }
                match self.k.rename(registration.index, &target) {
                    Ok(()) => {
                        let record = self.sessions.get_mut(&sid).unwrap();
                        record.current_name = Some(target);
                        record.name_state = Enforce::Applied;
                        record.state = Identity::Proved(registration);
                        self.report.forget_condition(&label, "name");
                        let verb = if staged { "published" } else { "renamed" };
                        log::info!("{label}: {verb} as {}", target.to_string_lossy());
                    }
                    Err(e) => {
                        self.report.begin(&label, "name", || {
                            format!(
                                "cannot take the name {}: {}",
                                target.to_string_lossy(),
                                report::describe(&e)
                            )
                        });
                        done = false;
                    }
                }
            }
        }
        done
    }

    /// Applies the hardware address to enforce while the device is down,
    /// defers it while up (S12, K31). Returns false on a failure to retry.
    pub(super) fn apply_hwaddr(&mut self, sid: u32, index: u32) -> bool {
        let label = self.session_label(sid);
        let record = &self.sessions[&sid];
        let Some(addr) = record
            .hwaddr
            .filter(|_| matches!(record.hwaddr_state, Enforce::Pending | Enforce::Deferred))
        else {
            return true;
        };
        let deferred = record.hwaddr_state == Enforce::Deferred;
        match self.k.set_hwaddr(index, addr) {
            Ok(()) => {
                self.sessions.get_mut(&sid).unwrap().hwaddr_state = Enforce::Applied;
                if deferred {
                    log::info!("{label}: hardware address {addr} applied");
                }
                true
            }
            Err(e) if errno(&e) == Errno::EBUSY as i32 => {
                self.sessions.get_mut(&sid).unwrap().hwaddr_state = Enforce::Deferred;
                // Reported at every reconcile that carries it (S12, O3).
                log::warn!("{label}: hardware address {addr} deferred until the device is down");
                true
            }
            Err(e) => {
                log::debug!("{label}: hardware address failed: {}", report::describe(&e));
                false
            }
        }
    }

    /// The device left: re-created when the kernel no longer has the
    /// session (S27), unmanageable when it moved away (S19, S20).
    pub(super) fn observed_removal(&mut self, sid: u32) -> bool {
        let tid = self.sessions[&sid].tunnel_id;
        match self.k.session(tid, sid) {
            Ok(None) => {
                let label = self.session_label(sid);
                self.forget_session(sid);
                log::warn!("{label}: deleted outside the daemon; creating it again (S27)");
                self.incomplete = true;
                false
            }
            Ok(Some(_)) => {
                self.sessions.get_mut(&sid).unwrap().state = Identity::Removed;
                self.skip_unmanageable_then(sid)
            }
            Err(error) => {
                log::debug!("session_id={sid}: removal verification failed: {error}");
                self.incomplete = true;
                self.reconcile_at.get_or_insert(self.k.now() + super::RETRY);
                false
            }
        }
    }

    /// A staged session whose identity was lost: removed through the
    /// kernel's record and created again (S23).
    fn restage(&mut self, sid: u32) -> bool {
        let tid = self.sessions[&sid].tunnel_id;
        if self.delete_verified(sid) && matches!(self.k.session(tid, sid), Ok(None)) {
            self.forget_session(sid);
        }
        self.incomplete = true;
        false
    }

    fn skip_unmanageable_then(&mut self, sid: u32) -> bool {
        self.skip_unmanageable(sid);
        true
    }

    /// S20: requested changes to an unmanageable device are skipped,
    /// recorded as applied, and reported once.
    fn skip_unmanageable(&mut self, sid: u32) {
        let label = self.session_label(sid);
        let record = self.sessions.get_mut(&sid).unwrap();
        let mut skipped = Vec::new();
        if matches!(record.name_state, Enforce::Pending)
            && record.current_name != Some(*record.config.interface_name())
        {
            record.name_state = Enforce::Skipped;
            skipped.push("its name");
        }
        if matches!(record.hwaddr_state, Enforce::Pending | Enforce::Deferred)
            && record.hwaddr.is_some()
        {
            record.hwaddr_state = Enforce::Skipped;
            skipped.push("its hardware address");
        }
        if !skipped.is_empty() {
            let why = match record.state {
                Identity::Adopted => "it was adopted from a previous instance",
                Identity::Removed => "its device left the namespace",
                _ => "notifications about its device were lost",
            };
            self.report.begin(&label, "unmanageable", || {
                format!(
                    "unmanageable because {why}; not changing {}; a change of session_id, peer_session_id or a cookie, or a restart, re-creates it (S20)",
                    skipped.join(" or ")
                )
            });
        }
    }

    /// A link notice about an owned device: its name, and a deferred
    /// hardware address once it is down (E2, E4, S10, S12).
    pub(super) fn session_device_changed(&mut self, sid: u32, name: L2tpIfName, up: bool) {
        let label = self.session_label(sid);
        let record = &self.sessions[&sid];
        if record.current_name != Some(name)
            && let Some(registration) = record.state.registration()
        {
            match self.k.link_by_index(registration.index) {
                Ok(Some(current)) if current.name == name => {}
                Err(_) => {
                    self.monitor_pending = true;
                    return;
                }
                _ => return,
            }
        }
        let record = &self.sessions[&sid];
        if record.hwaddr_state == Enforce::Applied
            && let Some(registration) = record.state.registration()
            && self.k.prove(registration) == Proof::Proved
            && let Ok(Some(address)) = self.k.ether_addr(registration.index)
            && record.hwaddr != Some(address)
        {
            self.sessions.get_mut(&sid).unwrap().hwaddr_state = Enforce::Overridden;
        }
        let record = self.sessions.get_mut(&sid).unwrap();
        if record.current_name != Some(name) {
            if record.name_state == Enforce::Applied && matches!(record.state, Identity::Proved(_))
            {
                record.name_state = Enforce::Overridden;
                log::info!(
                    "{label}: renamed to {} by another manager; kept (S10)",
                    name.to_string_lossy()
                );
            }
            record.current_name = Some(name);
        }
        if !up
            && record.hwaddr_state == Enforce::Deferred
            && let Identity::Proved(r) | Identity::Staged(r) = record.state
            && self.k.prove(&r) == Proof::Proved
        {
            self.apply_hwaddr(sid, r.index);
        }
    }
}
