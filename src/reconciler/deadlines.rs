//! Cancellable deadlines, indexed by owner and time (M14–M16, G23).
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::time::Instant;

#[derive(Default)]
pub(super) struct Deadlines<K> {
    owners: BTreeMap<K, Instant>,
    times: BTreeSet<(Instant, K)>,
}
impl<K: Ord + Clone> Deadlines<K> {
    pub fn insert(&mut self, key: K, at: Instant) -> Option<Instant> {
        let previous = self.owners.insert(key.clone(), at);
        if let Some(previous) = previous {
            self.times.remove(&(previous, key.clone()));
        }
        self.times.insert((at, key));
        previous
    }
    pub fn remove(&mut self, key: &K) -> Option<Instant> {
        let (key, at) = self.owners.remove_entry(key)?;
        self.times.remove(&(at, key));
        Some(at)
    }
    pub fn first_deadline(&self) -> Option<Instant> {
        self.times.first().map(|(at, _)| *at)
    }
    pub fn due(&self, now: Instant) -> impl Iterator<Item = &K> {
        self.times
            .iter()
            .take_while(move |(at, _)| *at <= now)
            .map(|(_, key)| key)
    }
}
impl<K> Deref for Deadlines<K> {
    type Target = BTreeMap<K, Instant>;
    fn deref(&self) -> &Self::Target {
        &self.owners
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::time::Duration;

    /// spec: M14, M15, M16, G23
    #[test]
    fn replacement_cancellation_and_ties_keep_one_deadline_per_owner() {
        let mut timers = Deadlines::default();
        let now = Instant::now();
        assert_eq!(timers.first_deadline(), None);
        assert_eq!(timers.remove(&1), None);
        for n in 0..10_000 {
            let at = now + Duration::from_secs(n);
            timers.insert(1, at);
            assert_eq!(timers.times.len(), 1);
            assert_eq!(timers.first_deadline(), Some(at));
        }
        timers.insert(1, now);
        timers.insert(2, now);
        timers.insert(3, now + Duration::from_secs(1));
        assert_eq!(timers.due(now).copied().collect::<Vec<_>>(), [1, 2]);
        assert_eq!(timers.remove(&1), Some(now));
        assert_eq!(timers.first_deadline(), Some(now));
        timers.remove(&2);
        assert_eq!(timers.first_deadline(), Some(now + Duration::from_secs(1)));
        assert_eq!(timers.due(now).count(), 0);
        timers.remove(&3);
        assert!(timers.owners.is_empty() && timers.times.is_empty());
        let mut model = BTreeMap::new();
        let mut seed = 42u64;
        for n in 0..10_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let key = (seed % 64) as u32;
            if seed & 64 == 0 {
                assert_eq!(timers.remove(&key), model.remove(&key));
            } else {
                let at = now + Duration::from_millis(seed % 100);
                assert_eq!(timers.insert(key, at), model.insert(key, at));
            }
            assert_eq!(timers.first_deadline(), model.values().min().copied());
            assert_eq!(timers.times.len(), model.len());
            assert_eq!(timers.owners, model);
            let at = now + Duration::from_millis(n % 100);
            let mut expected: Vec<_> = model
                .iter()
                .filter(|(_, due)| **due <= at)
                .map(|(key, _)| *key)
                .collect();
            let mut actual: Vec<_> = timers.due(at).copied().collect();
            actual.sort();
            expected.sort();
            assert_eq!(actual, expected);
        }
    }
}
