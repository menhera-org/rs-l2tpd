//! Process-wide lookup admission (V3, V4, V15). Obsolete calls keep their
//! slot until return; only current jobs and their latest result are held.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

const LIMIT: usize = 8;
const REFRESH: Duration = Duration::from_secs(30);
type Call = Arc<dyn Fn() -> Vec<IpAddr> + Send + Sync>;

struct Job {
    owner: u64,
    call: Call,
    configured: bool,
    due: Option<Instant>,
    result: Option<Vec<IpAddr>>,
}

#[derive(Default)]
struct State {
    next: u64,
    jobs: BTreeMap<u64, Job>,
    order: VecDeque<u64>,
    active: [usize; 2],
    owners: BTreeSet<u64>,
}

impl State {
    fn admit(&mut self, owner: u64, now: Instant) -> Option<(u64, bool, Call)> {
        let mut earlier = [false; 2];
        for _ in 0..self.order.len() {
            let id = self.order.pop_front().unwrap();
            self.order.push_back(id);
            let job = self.jobs.get_mut(&id).unwrap();
            let class = usize::from(job.configured);
            if !earlier[class]
                && self.active[class] < LIMIT
                && job.due.is_some_and(|due| due <= now)
            {
                earlier[class] = true;
                if job.owner != owner {
                    continue;
                }
                self.active[class] += 1;
                job.due = None;
                return Some((id, job.configured, job.call.clone()));
            }
        }
        None
    }

    fn complete(&mut self, id: u64, configured: bool, result: Vec<IpAddr>, now: Instant) {
        self.active[usize::from(configured)] -= 1;
        if let Some(job) = self.jobs.get_mut(&id) {
            job.result = Some(result);
            job.due = Some(now + REFRESH);
        }
    }
}

#[derive(Default)]
pub(super) struct Workers {
    state: Mutex<State>,
    changed: Condvar,
}

pub(super) struct Owner {
    shared: Arc<Workers>,
    id: u64,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Owner {
    pub fn new() -> io::Result<Self> {
        let shared = Workers::global();
        let id = {
            let mut state = shared.state.lock().unwrap();
            state.next += 1;
            let id = state.next;
            state.owners.insert(id);
            id
        };
        let dispatcher = shared.clone();
        // Spawn here: the caller's network namespace owns this instance.
        let thread = match std::thread::Builder::new()
            .name("rs-l2tpd-dns".into())
            .spawn(move || dispatcher.run(id))
        {
            Ok(thread) => thread,
            Err(error) => {
                shared.state.lock().unwrap().owners.remove(&id);
                return Err(error);
            }
        };
        Ok(Self {
            shared,
            id,
            thread: Some(thread),
        })
    }

    pub fn watch(&self, configured: bool, call: Call) -> u64 {
        self.shared.watch(self.id, configured, call)
    }
    pub fn unwatch(&self, id: u64) {
        self.shared.unwatch(id);
    }
    pub fn poll(&self, id: u64) -> Option<Vec<IpAddr>> {
        self.shared.poll(id)
    }
    pub fn waiting(&self, id: u64) -> bool {
        self.shared.waiting(id, Instant::now())
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock().unwrap();
        state.owners.remove(&self.id);
        state.jobs.retain(|_, job| job.owner != self.id);
        let keys: BTreeSet<_> = state.jobs.keys().copied().collect();
        state.order.retain(|id| keys.contains(id));
        self.shared.changed.notify_all();
        drop(state);
        // Only the dispatcher joins: it never runs a blocking lookup.
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Workers {
    fn global() -> Arc<Self> {
        static WORKERS: OnceLock<Arc<Workers>> = OnceLock::new();
        WORKERS.get_or_init(|| Arc::new(Self::default())).clone()
    }

    fn watch(&self, owner: u64, configured: bool, call: Call) -> u64 {
        let mut state = self.state.lock().unwrap();
        state.next += 1;
        let id = state.next;
        state.jobs.insert(
            id,
            Job {
                owner,
                call,
                configured,
                due: Some(Instant::now()),
                result: None,
            },
        );
        state.order.push_back(id);
        self.changed.notify_all();
        id
    }

    pub fn unwatch(&self, id: u64) {
        let mut state = self.state.lock().unwrap();
        state.jobs.remove(&id);
        state.order.retain(|key| *key != id);
        self.changed.notify_all();
    }

    pub fn poll(&self, id: u64) -> Option<Vec<IpAddr>> {
        self.state.lock().unwrap().jobs.get_mut(&id)?.result.take()
    }

    fn waiting(&self, id: u64, now: Instant) -> bool {
        let state = self.state.lock().unwrap();
        state.jobs.get(&id).is_some_and(|job| {
            job.due.is_some_and(|due| due <= now)
                && state.active[usize::from(job.configured)] >= LIMIT
        })
    }

    fn run(self: Arc<Self>, owner: u64) {
        let mut state = self.state.lock().unwrap();
        loop {
            if !state.owners.contains(&owner) {
                return;
            }
            if let Some((id, configured, call)) = state.admit(owner, Instant::now()) {
                self.changed.notify_all();
                let workers = self.clone();
                // Spawn only after admission, with no references to the service.
                if let Err(error) = std::thread::Builder::new()
                    .name("rs-l2tpd-lookup".into())
                    .spawn(move || {
                        // A panic must not strand a process-wide permit.
                        let result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call()))
                                .unwrap_or_default();
                        workers.state.lock().unwrap().complete(
                            id,
                            configured,
                            result,
                            Instant::now(),
                        );
                        workers.changed.notify_all();
                    })
                {
                    log::warn!("cannot start resolver worker: {error}");
                    state.complete(id, configured, Vec::new(), Instant::now());
                }
                continue;
            }
            let next = state
                .jobs
                .values()
                .filter(|job| {
                    job.owner == owner && state.active[usize::from(job.configured)] < LIMIT
                })
                .filter_map(|job| job.due)
                .min();
            // Another namespace's earlier eligible job owns admission;
            // its dispatcher or a completion will notify us.
            let next = next.filter(|due| *due > Instant::now());
            state = match next {
                Some(next) => {
                    self.changed
                        .wait_timeout(state, next.saturating_duration_since(Instant::now()))
                        .unwrap()
                        .0
                }
                None => self.changed.wait(state).unwrap(),
            };
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// spec: V3, V4, V15, G23, A9
    #[test]
    fn obsolete_calls_keep_separate_budgets_and_latest_results() {
        let workers = Workers::default();
        let call: Call = Arc::new(Vec::new);
        let now = Instant::now();
        let mut running = Vec::new();
        for _ in 0..8 {
            workers.watch(0, false, call.clone());
        }
        for _ in 0..8 {
            let (id, _, _) = workers
                .state
                .lock()
                .unwrap()
                .admit(0, now + REFRESH)
                .unwrap();
            running.push(id);
            workers.unwatch(id);
        }
        let waiting = workers.watch(0, false, call.clone());
        assert!(workers.waiting(waiting, now + REFRESH));
        for _ in 0..100 {
            let obsolete = workers.watch(0, false, call.clone());
            workers.unwatch(obsolete);
        }
        assert!(
            workers
                .state
                .lock()
                .unwrap()
                .admit(0, now + REFRESH)
                .is_none()
        );
        let configured = workers.watch(0, true, call);
        assert_eq!(
            workers
                .state
                .lock()
                .unwrap()
                .admit(0, now + REFRESH)
                .unwrap()
                .0,
            configured
        );
        let mut state = workers.state.lock().unwrap();
        assert_eq!(state.jobs.len(), 2);
        state.complete(running[0], false, Vec::new(), now);
        assert!(!state.jobs.contains_key(&running[0]));
        assert_eq!(state.admit(0, now + REFRESH).unwrap().0, waiting);
        state.complete(waiting, false, vec!["192.0.2.1".parse().unwrap()], now);
        assert!(
            state
                .admit(0, now + REFRESH - Duration::from_nanos(1))
                .is_none()
        );
        assert_eq!(state.admit(0, now + REFRESH).unwrap().0, waiting);
        state.complete(
            waiting,
            false,
            vec!["192.0.2.2".parse().unwrap()],
            now + REFRESH,
        );
        drop(state);
        assert_eq!(
            workers.poll(waiting).unwrap(),
            vec!["192.0.2.2".parse::<IpAddr>().unwrap()]
        );
        assert!(workers.poll(waiting).is_none());
    }

    /// spec: V3, V15, G23, A9
    #[test]
    fn eight_blocked_calls_survive_cancellation_without_a_ninth_worker() {
        let workers = Owner::new().unwrap();
        assert!(Arc::ptr_eq(&workers.shared, &Workers::global()));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (started, starts) = std::sync::mpsc::channel();
        let mut obsolete = Vec::new();
        for _ in 0..8 {
            let gate = gate.clone();
            let started = started.clone();
            obsolete.push(workers.watch(
                false,
                Arc::new(move || {
                    started.send("system").unwrap();
                    let (lock, changed) = &*gate;
                    let mut released = lock.lock().unwrap();
                    while !*released {
                        released = changed.wait(released).unwrap();
                    }
                    Vec::new()
                }),
            ));
        }
        // Always release actual workers, including on assertion failure.
        struct Release(Arc<(Mutex<bool>, Condvar)>);
        impl Drop for Release {
            fn drop(&mut self) {
                *self.0.0.lock().unwrap() = true;
                self.0.1.notify_all();
            }
        }
        let release = Release(gate);
        for _ in 0..8 {
            assert_eq!(
                starts.recv_timeout(Duration::from_secs(5)).unwrap(),
                "system"
            );
        }
        for id in obsolete {
            workers.unwatch(id);
        }
        for _ in 0..100 {
            let replacement = Owner::new().unwrap();
            replacement.watch(false, Arc::new(Vec::new));
            drop(replacement);
        }
        let waiting = {
            let started = started.clone();
            workers.watch(
                false,
                Arc::new(move || {
                    started.send("latest").unwrap();
                    Vec::new()
                }),
            )
        };
        let configured = workers.watch(
            true,
            Arc::new(move || {
                started.send("configured").unwrap();
                Vec::new()
            }),
        );
        assert_eq!(
            starts.recv_timeout(Duration::from_secs(5)).unwrap(),
            "configured"
        );
        assert_eq!(workers.shared.state.lock().unwrap().active[0], 8);
        assert_eq!(workers.shared.state.lock().unwrap().jobs.len(), 2);
        let count = std::fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                std::fs::read_to_string(entry.path().join("comm"))
                    .ok()
                    .is_some_and(|name| name.trim() == "rs-l2tpd-lookup")
            })
            .count();
        assert!(count <= 9, "actual lookup thread count: {count}");
        drop(release);
        assert_eq!(
            starts.recv_timeout(Duration::from_secs(5)).unwrap(),
            "latest"
        );
        workers.unwatch(waiting);
        workers.unwatch(configured);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut state = workers.shared.state.lock().unwrap();
        while state.active != [0, 0] {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero());
            state = workers.shared.changed.wait_timeout(state, left).unwrap().0;
        }
        assert!(state.jobs.is_empty());
    }

    /// spec: V3, V15
    #[test]
    #[ignore = "permission to create an isolated network namespace"]
    fn dispatchers_preserve_each_owners_network_namespace() {
        use std::os::unix::fs::MetadataExt;
        let _first = Owner::new().unwrap();
        let original = std::fs::metadata("/proc/thread-self/ns/net").unwrap().ino();
        std::thread::spawn(move || {
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
            let expected = std::fs::metadata("/proc/thread-self/ns/net").unwrap().ino();
            assert_ne!(expected, original);
            let owner = Owner::new().unwrap();
            let (send, received) = std::sync::mpsc::channel();
            owner.watch(
                false,
                Arc::new(move || {
                    send.send(std::fs::metadata("/proc/thread-self/ns/net").unwrap().ino())
                        .unwrap();
                    Vec::new()
                }),
            );
            assert_eq!(
                received.recv_timeout(Duration::from_secs(5)).unwrap(),
                expected
            );
        })
        .join()
        .unwrap();
    }
}
