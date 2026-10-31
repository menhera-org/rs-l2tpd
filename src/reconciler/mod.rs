//! The reconciler: the accepted configuration, the records, the
//! operations in the order of M6, the degradation ladder, events, timers
//! and reporting (spec M1–M19, T, S, V, E, O2–O6).
//!
//! It runs on the thread that owns the [`Kernel`]; the runtime hands it
//! configurations, notices and ticks, and carries its [`Request`]s to the
//! program (L12, L13).

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use crate::config::{Config, L2tpIfName};
use crate::kernel::Kernel;

mod deadlines;
mod events;
mod ladder;
mod records;
mod report;
mod resolvers;
mod sessions;
mod store;
mod timers;
mod tunnels;
mod workers;

pub use events::Source;
pub use resolvers::{ClientId, IphostResolve, Lookup, Resolve, ResolverSpec};

use deadlines::Deadlines;
use records::{Conflict, ConflictIdentity, SessionRecord, TunnelRecord};
use report::Report;

/// The intervals of M14.
const RETRY: Duration = Duration::from_secs(1);
const LEFT_OUT_RETRY: Duration = Duration::from_secs(30);
const CONFLICT_ATTEMPTS: u8 = 10;
const DELETION_WAIT: Duration = Duration::from_secs(2);

/// What the reconciler asks of the program, which owns the process (L12,
/// L13). The runtime turns these into control events.
#[derive(Debug)]
#[non_exhaustive]
pub enum Request {
    /// Set `net.ipv6.bindv6only` to 0 (P25), then report through
    /// [`Reconciler::tunable_written`].
    WriteBindv6only {
        /// The request incarnation, returned with the answer.
        id: u64,
        /// The absolute deadline; answers at or after it are ignored.
        deadline: Instant,
    },
    /// Store a tunnel's socket where a descriptor store exists (P14).
    StoreSocket {
        /// The reserved store name.
        name: String,
        /// The tunnel.
        tunnel_id: u32,
        /// A duplicate of its socket.
        fd: OwnedFd,
    },
    /// Withdraw a stored socket before it is closed (P14).
    ForgetSocket {
        /// The exact inherited or submitted store name.
        name: String,
        /// The request incarnation.
        id: u64,
        /// The withdrawal deadline.
        deadline: Instant,
    },
}

/// The reconciler over a kernel `K`.
pub struct Reconciler<K: Kernel> {
    k: K,
    accepted: Config,
    wanted_tunnels: BTreeMap<u32, String>,
    wanted_sessions: BTreeMap<u32, String>,
    tunnels: BTreeMap<u32, TunnelRecord>,
    sessions: BTreeMap<u32, SessionRecord>,
    /// Tunnel identifiers whose socket was closed, until the kernel lets
    /// them go or the wait ends (T8).
    departing: Deadlines<u32>,
    /// Creation names reserved until their session is confirmed gone (S4).
    reserved: BTreeMap<L2tpIfName, (u32, u32)>,
    deleting_sessions: Deadlines<(u32, u32)>,
    unmatched_sessions: BTreeSet<(u32, u32)>,
    verify_sessions: BTreeSet<u32>,
    verify_tunnels: BTreeSet<u32>,
    conflicts: BTreeMap<(bool, u32), Conflict>,
    conflict_times: Deadlines<(bool, u32)>,
    retries: Deadlines<u32>,
    resolvers: resolvers::Resolvers,
    report: Report,
    requests: Vec<Request>,
    /// Whether the program wrote the tunable (P25): `None` until asked.
    tunable: Option<bool>,
    tunable_pending: Option<(u64, Instant)>,
    next_request: u64,
    store: store::Store,
    /// An earlier reconcile left something unapplied (E12).
    incomplete: bool,
    /// AF_INET6 L2TP/IP sockets refused at the last creation (T4).
    inet6_refused: bool,
    /// When the incomplete reconcile is retried (E12).
    reconcile_at: Option<Instant>,
    tick_at: Option<Instant>,
    /// The `l2tp` subscription lost notifications and the scan of E20 has
    /// not completed.
    l2tp_pending: bool,
    monitor_pending: bool,
    /// The devices seen as VRFs and the controllers of enslaved devices,
    /// from link notices (E4, E6).
    vrfs: BTreeSet<u32>,
    masters: BTreeMap<u32, u32>,
    members: BTreeMap<u32, BTreeSet<u32>>,
    changed_devices: BTreeSet<u32>,
    changed_bindings: BTreeSet<u32>,
    address_devices: BTreeSet<u32>,
    addresses: BTreeMap<u32, BTreeSet<std::net::IpAddr>>,
    index: events::Index,
}

impl<K: Kernel> Reconciler<K> {
    /// A reconciler with nothing applied, resolving through `resolve`.
    pub fn new(kernel: K, resolve: Box<dyn Resolve>) -> Self {
        Reconciler {
            k: kernel,
            accepted: Config::new(),
            wanted_tunnels: BTreeMap::new(),
            wanted_sessions: BTreeMap::new(),
            tunnels: BTreeMap::new(),
            sessions: BTreeMap::new(),
            departing: Deadlines::default(),
            reserved: BTreeMap::new(),
            deleting_sessions: Deadlines::default(),
            unmatched_sessions: BTreeSet::new(),
            verify_sessions: BTreeSet::new(),
            verify_tunnels: BTreeSet::new(),
            conflicts: BTreeMap::new(),
            conflict_times: Deadlines::default(),
            retries: Deadlines::default(),
            resolvers: resolvers::Resolvers::new(resolve),
            report: Report::default(),
            requests: Vec::new(),
            tunable: None,
            tunable_pending: None,
            next_request: 0,
            store: store::Store::default(),
            incomplete: false,
            inet6_refused: false,
            reconcile_at: None,
            tick_at: None,
            l2tp_pending: false,
            monitor_pending: false,
            vrfs: BTreeSet::new(),
            masters: BTreeMap::new(),
            members: BTreeMap::new(),
            changed_devices: BTreeSet::new(),
            changed_bindings: BTreeSet::new(),
            address_devices: BTreeSet::new(),
            addresses: BTreeMap::new(),
            index: events::Index::default(),
        }
    }

    /// The kernel.
    pub fn kernel(&self) -> &K {
        &self.k
    }

    /// The kernel, mutably: for tests and for the runtime's subscriptions.
    pub fn kernel_mut(&mut self) -> &mut K {
        &mut self.k
    }

    /// The accepted configuration (C13).
    pub fn accepted(&self) -> &Config {
        &self.accepted
    }

    pub(crate) fn applied(&self) -> bool {
        !self.incomplete
    }

    /// Duplicates the owned tunnel sockets for an in-process restart.
    /// A partial failure drops every duplicate already obtained.
    pub fn restart_sockets(&self) -> std::io::Result<Vec<(String, OwnedFd)>> {
        self.tunnels
            .iter()
            .map(|(id, record)| Ok((format!("t{id}"), self.k.clone_fd(record.socket)?)))
            .collect()
    }

    /// Takes what the program must do (L12, L13).
    pub fn take_requests(&mut self) -> Vec<Request> {
        std::mem::take(&mut self.requests)
    }

    /// The program's answer to [`Request::WriteBindv6only`] (L12).
    pub fn tunable_written(&mut self, id: u64, ok: bool) {
        let Some((pending, deadline)) = self.tunable_pending else {
            return;
        };
        if pending != id || self.k.now() >= deadline {
            return;
        }
        self.tunable_pending = None;
        self.tunable = Some(ok);
        if !ok {
            log::warn!("bindv6only write failed; using the socket family fallback (T26)");
        }
        self.reconcile_current(self.accepted.clone());
    }

    /// Applies `config` (M1): removals, then creations, then changes in
    /// place, every entry independently (M3, M4, M6). Returns whether
    /// everything is applied; otherwise the tick retries (E12).
    pub fn reconcile(&mut self, config: Config) -> bool {
        let now = self.k.now();
        for (key, conflict) in &mut self.conflicts {
            conflict.next = now;
            if conflict.left_out {
                self.conflict_times.insert(*key, now);
            }
        }
        if self.tunable_pending.is_none() {
            self.tunable = None;
        }
        self.reconcile_current(config)
    }

    fn reconcile_current(&mut self, config: Config) -> bool {
        if config != self.accepted {
            self.wanted_tunnels = config
                .tunnels()
                .iter()
                .map(|(name, tunnel)| (tunnel.tunnel_id(), name.clone()))
                .collect();
            self.wanted_sessions = config
                .sessions()
                .iter()
                .map(|(name, session)| (session.session_id(), name.clone()))
                .collect();
            let wanted: BTreeMap<_, _> = config
                .tunnels()
                .values()
                .map(|t| {
                    (
                        (false, t.tunnel_id()),
                        ConflictIdentity::Tunnel(t.identity()),
                    )
                })
                .chain(config.sessions().iter().filter_map(|(name, s)| {
                    Some((
                        (true, s.session_id()),
                        ConflictIdentity::Session(config.session_identity(name)?),
                    ))
                }))
                .collect();
            let obsolete: Vec<_> = self
                .conflicts
                .iter()
                .filter(|(key, c)| wanted.get(key) != Some(&c.identity))
                .map(|(key, _)| *key)
                .collect();
            for key in obsolete {
                self.conflicts.remove(&key);
                self.conflict_times.remove(&key);
            }
            for id in self.resolvers.reload(&config, &self.wanted_tunnels) {
                if let Some(record) = self.tunnels.get(&id) {
                    self.report.forget(&report::tunnel(&record.name, id));
                }
            }
        }
        self.accepted = config;
        self.incomplete = false;
        self.check_tunable();
        self.verify_inherited();
        self.retry_unmatched_sessions();
        self.retire_sockets();
        self.remove_unwanted_sessions();
        self.remove_unwanted_tunnels();
        self.retire_sockets();
        self.release_departed();
        self.create_wanted_tunnels();
        self.create_wanted_sessions();
        self.converge_all();
        self.reconcile_at = self.incomplete.then(|| self.k.now() + RETRY);
        self.arm_tick();
        !self.incomplete
    }

    /// Changes in place, after every removal and creation (M6): tunnels'
    /// peers and bindings, then renames (swaps first), then addresses.
    fn converge_all(&mut self) {
        self.update_tunnels_in_place();
        self.update_sessions_in_place();
        self.reindex();
        let ids: Vec<u32> = self.tunnels.keys().copied().collect();
        for id in ids {
            self.ensure_lookup(id);
            // A pending peer has its own retry (E13), not the reconcile's.
            self.converge_tunnel(id);
        }
        self.clear_swaps();
        let sids: Vec<u32> = self.sessions.keys().copied().collect();
        for sid in sids {
            if self.sessions.contains_key(&sid) && !self.converge_session(sid) {
                self.incomplete = true;
            }
        }
    }

    /// Removes everything owned, in the order of M6 (P16). Returns
    /// whether every step succeeded.
    pub fn shutdown(&mut self) -> bool {
        self.tunable_pending = None;
        self.requests
            .retain(|r| !matches!(r, Request::WriteBindv6only { .. }));
        self.accepted = Config::new();
        self.wanted_tunnels.clear();
        self.wanted_sessions.clear();
        self.conflicts.clear();
        self.conflict_times = Deadlines::default();
        self.store
            .shutdown
            .get_or_insert(self.k.now() + DELETION_WAIT);
        self.verify_inherited();
        self.incomplete = false;
        self.remove_unwanted_sessions();
        self.remove_unwanted_tunnels();
        self.reindex();
        self.retire_sockets();
        self.resolvers.reload(&self.accepted, &self.wanted_tunnels);
        !self.incomplete && self.tunnels.is_empty() && self.store.retiring.is_empty()
    }

    pub(crate) fn shutdown_deletions(&mut self) -> crate::Result<bool> {
        let now = self.k.now();
        let mut failure = None;
        for (id, deadline) in self
            .departing
            .iter()
            .map(|(id, at)| (*id, *at))
            .collect::<Vec<_>>()
        {
            match self.k.tunnel(id) {
                Ok(None) => {
                    self.departing.remove(&id);
                }
                result if now >= deadline => {
                    log::error!("tunnel_id={id}: deletion not confirmed before deadline");
                    failure = Some(match result {
                        Err(error) => error.into(),
                        _ => crate::Error::Other(format!("tunnel_id={id}: deletion not confirmed")),
                    });
                }
                _ => {}
            }
        }
        failure.map_or(Ok(self.departing.is_empty()), Err)
    }

    pub(crate) fn shutdown_deadline(&self) -> Option<Instant> {
        self.store
            .next_deadline(self.k.now())
            .into_iter()
            .chain(self.departing.first_deadline())
            .min()
    }

    /// Every eligible entry exists in the kernel (P6): all but the entries
    /// left out for a conflict and the sessions of a left-out tunnel.
    pub fn ready(&self) -> bool {
        let tunnels = self.accepted.tunnels().values().all(|t| {
            self.tunnels
                .get(&t.tunnel_id())
                .is_some_and(|r| r.identity == t.identity())
                || self.left_out_key(false, t.tunnel_id())
        });
        let sessions = self.accepted.sessions().iter().all(|(name, s)| {
            let tunnel = &self.accepted.tunnels()[s.tunnel_name()];
            self.sessions
                .get(&s.session_id())
                .is_some_and(|r| Some(r.identity) == self.accepted.session_identity(name))
                || self.left_out_key(true, s.session_id())
                || self.left_out_key(false, tunnel.tunnel_id())
        });
        tunnels && sessions
    }

    /// The configuration names of the entries left out for a conflict
    /// (L5, T25).
    pub fn left_out(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for (name, t) in self.accepted.tunnels() {
            if self.left_out_key(false, t.tunnel_id()) {
                names.push(name.clone());
            }
        }
        for (name, s) in self.accepted.sessions() {
            if self.left_out_key(true, s.session_id()) {
                names.push(name.clone());
            }
        }
        names
    }

    fn left_out_key(&self, session: bool, id: u32) -> bool {
        self.conflicts
            .get(&(session, id))
            .is_some_and(|c| c.left_out)
    }

    /// The bindv6only scratch check of E25, at every reconcile (P25).
    fn check_tunable(&mut self) {
        if !self.accepted.host().fix_bindv6only()
            || self.tunable.is_some()
            || self.tunable_pending.is_some()
        {
            return;
        }
        // An error is a host without AF_INET6 sockets: irrelevant (E25).
        if let Ok(true) = self.k.scratch_only_v6() {
            self.request_tunable();
        }
    }

    fn request_tunable(&mut self) {
        if self.tunable.is_none() && self.tunable_pending.is_none() {
            log::warn!("net.ipv6.bindv6only is set; asking for it to be set back to 0 (T26, P25)");
            self.next_request += 1;
            let deadline = self.k.now() + Duration::from_secs(5);
            self.tunable_pending = Some((self.next_request, deadline));
            self.requests.push(Request::WriteBindv6only {
                id: self.next_request,
                deadline,
            });
        }
    }

    /// Whether an entry may try to claim its identifiers now (T25): not
    /// while it is left out and its slow retry is not due. A changed
    /// identity restarts the counter.
    fn may_try(&mut self, session: bool, id: u32, identity: ConflictIdentity) -> bool {
        let now = self.k.now();
        match self.conflicts.get(&(session, id)) {
            Some(c) if c.identity != identity => {
                self.conflicts.remove(&(session, id));
                self.conflict_times.remove(&(session, id));
                true
            }
            Some(c) => c.next <= now,
            None => true,
        }
    }

    /// Records a refusal of the entry's identifiers (T25).
    fn conflict(
        &mut self,
        session: bool,
        id: u32,
        identity: ConflictIdentity,
        entry: &str,
        error: &std::io::Error,
    ) {
        let now = self.k.now();
        let c = self.conflicts.entry((session, id)).or_insert(Conflict {
            identity,
            attempts: 0,
            left_out: false,
            next: now,
        });
        c.attempts = c.attempts.saturating_add(1);
        if c.attempts >= CONFLICT_ATTEMPTS {
            c.next = now + LEFT_OUT_RETRY;
            if !c.left_out {
                c.left_out = true;
                log::warn!(
                    "{entry}: left out after {} refusals: {}",
                    c.attempts,
                    report::describe(error)
                );
            }
        } else {
            c.next = now + RETRY;
            self.incomplete = true;
            log::debug!("{entry}: identifiers refused: {}", report::describe(error));
        }
        if c.left_out {
            self.conflict_times.insert((session, id), c.next);
        }
    }

    /// The entry got its identifiers (T25).
    fn conflict_over(&mut self, session: bool, id: u32, entry: &str) {
        self.conflict_times.remove(&(session, id));
        if let Some(c) = self.conflicts.remove(&(session, id))
            && c.left_out
        {
            log::info!("{entry}: identifiers free, created");
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests;
