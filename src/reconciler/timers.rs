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
        let every_second =
            (self.resolvers.any() || self.l2tp_pending || self.sessions.values().any(|s| s.verify))
                .then_some(now + RETRY);
        [
            self.reconcile_at,
            every_second,
            self.resolvers.next_deadline(),
            self.tunnels.values().filter_map(|t| t.retry_at).min(),
            self.conflicts
                .values()
                .filter(|c| c.left_out)
                .map(|c| c.next)
                .min(),
            self.departing.values().min().copied(),
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
        self.poll_answers();
        self.retry_resolvers();
        let left_out_due = self.conflicts.values().any(|c| c.left_out && c.next <= now);
        let departed_due = self.departing.values().any(|d| *d <= now);
        if self.reconcile_at.is_some_and(|t| t <= now) || left_out_due || departed_due {
            self.reconcile_at = None;
            let config = self.accepted.clone();
            self.reconcile(config);
        }
        let due: Vec<u32> = self
            .tunnels
            .iter()
            .filter(|(_, t)| t.retry_at.is_some_and(|r| r <= now))
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            self.tunnels.get_mut(&id).unwrap().retry_at = None;
            self.converge_tunnel(id);
        }
        let verify: Vec<u32> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.verify)
            .map(|(sid, _)| *sid)
            .collect();
        for sid in verify {
            self.verify_session(sid);
        }
        if self.l2tp_pending {
            self.l2tp_resync();
        }
    }
}
