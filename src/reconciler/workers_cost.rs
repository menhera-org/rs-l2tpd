use super::*;

/// spec: G23, M16, V15
#[test]
fn cancellation_cost_with_unrelated_jobs() {
    for count in [1, 300, 20_000] {
        for drop_owner in [false, true] {
            let shared = Arc::new(Workers::default());
            let call: Call = Arc::new(Vec::new);
            for _ in 0..count {
                shared.watch(0, false, call.clone());
            }
            let started = Instant::now();
            for _ in 0..500 {
                let id = shared.watch(1, false, call.clone());
                if drop_owner {
                    drop(Owner {
                        shared: shared.clone(),
                        id: 1,
                        thread: None,
                    });
                } else {
                    shared.unwatch(id);
                }
            }
            let elapsed = started.elapsed().as_nanos();
            let state = shared.state.lock().unwrap();
            assert_eq!(state.jobs.len(), count);
            assert_eq!(state.order.len(), count);
            assert!(state.jobs.values().all(|job| job.owner == 0));
            eprintln!(
                "CANCEL_COST jobs={count} cancellations=500 drop_owner={drop_owner} elapsed_ns={elapsed}"
            );
        }
    }
}
