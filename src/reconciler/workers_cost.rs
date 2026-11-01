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

/// spec: V7, V15, G23, M16
#[test]
#[ignore = "serial isolated runner; child exec must not inherit concurrent fake socket references"]
fn dropping_an_adapter_cancels_only_its_jobs_and_preserves_other_answers() {
    use crate::reconciler::{IphostResolve, Lookup, Resolve, ResolverSpec};
    const CHILD: &str = "RS_L2TPD_ADAPTER_DROP_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "reconciler::workers::cost_tests::dropping_an_adapter_cancels_only_its_jobs_and_preserves_other_answers",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("adapter cleanup subprocess exceeded its deadline");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("LLVM Profile Error"));
        return;
    }
    let shared = Workers::global();
    {
        let state = shared.state.lock().unwrap();
        assert!(state.owners.is_empty() && state.jobs.is_empty() && state.order.is_empty());
    }
    let mut first = IphostResolve::default();
    for (id, host) in [(1, "192.0.2.1"), (2, "192.0.2.2")] {
        first
            .watch(Lookup::new(id, host.into(), ResolverSpec::System))
            .unwrap();
    }
    let mut other = IphostResolve::default();
    other
        .watch(Lookup::new(3, "192.0.2.3".into(), ResolverSpec::System))
        .unwrap();
    let (owner, survivor) = {
        let state = shared.state.lock().unwrap();
        assert_eq!(state.owners.len(), 2);
        assert_eq!(state.jobs.len(), 3);
        assert_eq!(state.order.len(), 3);
        let mut owners = state.owners.iter();
        let (&owner, jobs) = owners.next().unwrap();
        assert_eq!(jobs.len(), 2);
        let (&survivor, jobs) = owners.next().unwrap();
        assert_eq!(jobs.len(), 1);
        (owner, survivor)
    };
    drop(first);
    {
        let state = shared.state.lock().unwrap();
        assert!(!state.owners.contains_key(&owner));
        assert_eq!(state.owners[&survivor].len(), 1);
        assert_eq!(state.jobs.len(), 1);
        assert_eq!(state.order.len(), 1);
        assert!(state.jobs.values().all(|job| job.owner == survivor));
        assert!(
            state
                .order
                .iter()
                .all(|(_, id)| state.jobs.contains_key(id))
        );
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let answers = other.poll();
        if !answers.is_empty() {
            assert_eq!(answers, [(3, vec!["192.0.2.3".parse::<IpAddr>().unwrap()])]);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "surviving adapter lost its answer"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(other);
    loop {
        let state = shared.state.lock().unwrap();
        assert!(state.owners.is_empty() && state.jobs.is_empty() && state.order.is_empty());
        if state.active == [0, 0] {
            break;
        }
        drop(state);
        assert!(
            Instant::now() < deadline,
            "obsolete worker kept its permit after returning"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
