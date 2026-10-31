//! The timers of M14 as one deadline: the runtime sleeps until
//! [`Reconciler::next_deadline`] and calls [`Reconciler::tick`]. Every
//! timer is fixed-delay and bounded in number (M15).

use std::time::Instant;

use crate::kernel::Kernel;

use super::{RETRY, Reconciler};

impl<K: Kernel> Reconciler<K> {
    /// When the next timer is due, `None` while nothing waits (M15).
    pub fn next_deadline(&self) -> Option<Instant> {
        let now = self.k.now();
        [
            self.reconcile_at,
            self.tunable_pending.map(|(_, deadline)| deadline),
            self.store.next_deadline(now),
            self.tick_at,
            self.resolvers.next_deadline(),
            self.retries.first_deadline(),
            self.conflict_times.first_deadline(),
            self.departing.first_deadline(),
            self.deleting_sessions.first_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Runs the timers that are due: the reconcile retry (E12), the
    /// left-out retry (E14), the reconnect and pending-peer retries (E8,
    /// E13), the resolver polling and device retries (V4, V9), and the
    /// verifications of E20 and E27.
    pub fn tick(&mut self) {
        let now = self.k.now();
        if self.tick_at.is_some_and(|deadline| now >= deadline) {
            self.tick_at = None;
        }
        self.retire_sockets();
        if self
            .tunable_pending
            .is_some_and(|(_, deadline)| now >= deadline)
        {
            self.tunable_pending = None;
            self.tunable = Some(false);
            log::warn!("bindv6only write timed out; using the socket family fallback (T26)");
            self.reconcile_at = Some(now);
        }
        self.poll_answers();
        self.retry_resolvers();
        let left_out_due = self
            .conflict_times
            .first_deadline()
            .is_some_and(|at| at <= now);
        let departed_due = self.departing.first_deadline().is_some_and(|at| at <= now)
            || self
                .deleting_sessions
                .first_deadline()
                .is_some_and(|at| at <= now);
        if self.reconcile_at.is_some_and(|t| t <= now) || left_out_due || departed_due {
            self.reconcile_at = None;
            let config = self.accepted.clone();
            self.reconcile_current(config);
        }
        let due: Vec<u32> = self.retries.due(now).copied().collect();
        for id in due {
            self.retries.remove(&id);
            self.converge_tunnel(id);
        }
        let verify: Vec<_> = self.verify_sessions.iter().copied().collect();
        for sid in verify {
            if self.verify_session(sid) {
                self.verify_sessions.remove(&sid);
            }
        }
        if self.l2tp_pending {
            self.l2tp_resync();
        }
        if self.monitor_pending {
            self.monitor_resync();
        }
        let verify: Vec<_> = self.verify_tunnels.iter().copied().collect();
        for id in verify {
            self.tunnel_announced(id);
        }
        self.arm_tick();
    }

    pub(super) fn arm_tick(&mut self) {
        if self.resolvers.any()
            || self.l2tp_pending
            || self.monitor_pending
            || !self.verify_sessions.is_empty()
            || !self.verify_tunnels.is_empty()
        {
            self.tick_at.get_or_insert(self.k.now() + RETRY);
        } else {
            self.tick_at = None;
        }
    }
}
