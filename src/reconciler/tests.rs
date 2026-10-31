//! Unit tests of the reconciler's pure parts; the behavioural rules are
//! tested against the fake kernel in `tests/rules/`.

#[cfg(feature = "fake-kernel")]
mod completion {
    use super::super::*;
    use crate::kernel::fake::FakeKernel;
    use crate::kernel::{LinkInfo, Notice};
    use nix::errno::Errno;

    const CONFIG: &str = "[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'";

    fn reconciler() -> Reconciler<FakeKernel> {
        let mut kernel = FakeKernel::new(42);
        let device = kernel.add_link("eth", false);
        kernel.add_addr(device, "192.0.2.1".parse().unwrap());
        Reconciler::new(kernel, Box::new(IphostResolve::default()))
    }

    /// spec: E3, E12, S27, E27, G23
    #[test]
    fn removal_query_retries_and_old_deletion_does_not_poll_a_new_incarnation() {
        let mut r = reconciler();
        assert!(r.reconcile(toml::from_str(CONFIG).unwrap()));
        let old = r.k.session_index(10, 100).unwrap();
        r.k.operator_delete_session(10, 100);
        r.k.tick();
        r.k.fail_next("session", Errno::EIO);
        r.handle(
            Source::Monitor,
            Notice::LinkDel(LinkInfo::new(
                old,
                L2tpIfName::new(b"l2tp0").unwrap(),
                false,
                false,
                None,
            )),
        );
        assert!(r.next_deadline().is_some());
        r.k.advance(RETRY);
        r.tick();
        r.k.advance(RETRY);
        r.tick();
        assert!(r.k.session_index(10, 100).is_some());
        assert_ne!(r.k.session_index(10, 100), Some(old));
        r.handle(
            Source::L2tp,
            Notice::SessionDeleted {
                tunnel_id: 10,
                session_id: 100,
            },
        );
        assert!(!r.verify_sessions.is_empty());
        r.k.advance(RETRY);
        r.tick();
        assert!(r.verify_sessions.is_empty());
        assert_eq!(r.next_deadline(), None);
    }

    /// spec: S10, S8, O3, G13
    #[test]
    fn obsolete_creation_names_are_not_recorded_as_overrides_and_create_episode_ends() {
        let mut r = reconciler();
        let text = CONFIG.to_owned() + "\ninterface_hwaddr='02:00:5e:00:53:01'";
        r.k.fail_next("create", Errno::EPERM);
        r.reconcile(toml::from_str(&text).unwrap());
        let label = report::session("s", 10, 100);
        assert!(r.report.is_open(&label, "create"));
        r.k.advance(RETRY);
        r.tick();
        assert!(!r.report.is_open(&label, "create"));
        for notice in r.k.take_monitor() {
            r.handle(Source::Monitor, notice);
        }
        assert_eq!(r.sessions[&100].name_state, records::Enforce::Applied);
        assert!(!r.report.is_open(&label, "name-override"));
        let index = r.k.session_index(10, 100).unwrap();
        r.k.rename_link(index, "manager");
        r.k.fail_next("link", Errno::EIO);
        r.session_device_changed(100, L2tpIfName::new(b"manager").unwrap(), false);
        assert!(r.monitor_pending);
        r.k.advance(RETRY);
        r.tick();
        assert!(!r.monitor_pending);
        assert_eq!(r.sessions[&100].name_state, records::Enforce::Overridden);
    }

    /// spec: G23, M5, M16
    #[test]
    fn unrelated_interfaces_do_not_accumulate_in_the_device_caches() {
        let mut r = reconciler();
        r.reconcile(toml::from_str(CONFIG).unwrap());
        for index in 1000..11000 {
            r.handle(
                Source::Monitor,
                Notice::LinkNew(LinkInfo::new(
                    index,
                    L2tpIfName::new(b"foreign").unwrap(),
                    false,
                    index % 2 == 0,
                    Some(999),
                )),
            );
        }
        assert!(r.vrfs.is_empty());
        assert!(r.masters.is_empty());
        assert!(r.addresses.is_empty());
        assert!(r.address_devices.is_empty());
        assert_eq!(r.next_deadline(), None);
    }
}

#[cfg(feature = "fake-kernel")]
mod deadline_cost {
    use super::super::*;
    use crate::kernel::fake::FakeKernel;

    /// spec: G23, M15, T25
    #[test]
    fn removing_a_left_out_entry_cancels_its_conflict_and_retry() {
        for shutdown in [false, true] {
            let mut kernel = FakeKernel::new(42);
            let foreign = kernel.operator_replace_tunnel(10, 20);
            let mut r = Reconciler::new(kernel, Box::new(IphostResolve::default()));
            let config = toml::from_str(
                "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'",
            )
            .unwrap();
            r.reconcile(config);
            for _ in 0..10 {
                r.k.advance(RETRY);
                r.tick();
            }
            assert_eq!(r.left_out(), ["a"]);
            assert!(r.conflict_times.first_deadline().is_some());
            if shutdown {
                assert!(r.shutdown());
                r.k.advance(DELETION_WAIT);
            } else {
                r.reconcile(Config::new());
            }
            assert!(
                r.conflicts.is_empty(),
                "removed configuration retains conflict history"
            );
            assert!(
                r.conflict_times.is_empty(),
                "removed configuration retains slow retry"
            );
            assert_eq!(r.next_deadline(), None);
            assert_eq!(r.k.tunnel_socket(10), Some(foreign));
        }
    }

    /// spec: M14, M15, E8, E13, G23
    #[test]
    fn reconnect_deadlines_keep_their_time_and_cancel_on_success_and_removal() {
        let mut kernel = FakeKernel::new(42);
        let device = kernel.add_link("eth", false);
        kernel.add_addr(device, "192.0.2.1".parse().unwrap());
        let mut r = Reconciler::new(kernel, Box::new(IphostResolve::default()));
        let text =
            "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'";
        r.k.fail_next("connect", nix::errno::Errno::ENETUNREACH);
        r.reconcile(toml::from_str(text).unwrap());
        let at = r.k.now() + RETRY;
        assert_eq!(r.next_deadline(), Some(at));
        r.k.advance(Duration::from_millis(250));
        r.handle(
            Source::Monitor,
            crate::kernel::Notice::LinkNew(crate::kernel::LinkInfo::new(
                999,
                L2tpIfName::new(b"foreign").unwrap(),
                true,
                false,
                None,
            )),
        );
        assert_eq!(
            r.next_deadline(),
            Some(at),
            "unrelated traffic postponed retry"
        );
        r.k.advance(Duration::from_millis(750));
        r.tick();
        assert!(r.retries.is_empty());
        assert_eq!(r.next_deadline(), None);
        r.k.fail_next("connect", nix::errno::Errno::ENETUNREACH);
        r.reconcile(toml::from_str(&text.replace("192.0.2.2", "192.0.2.3")).unwrap());
        assert_eq!(r.next_deadline(), Some(r.k.now() + RETRY));
        r.reconcile(Config::new());
        assert!(
            r.retries.is_empty(),
            "removed tunnel retained a reconnect timer"
        );
        r.k.advance(DELETION_WAIT);
        r.tick();
        assert_eq!(r.next_deadline(), None);
        assert_eq!(r.k.open_sockets(), 0);
    }

    /// spec: G12, M14, M15, M16
    #[test]
    fn deadline_selection_preserves_the_earliest_deletion_under_large_workloads() {
        for count in [1, 300, 20_000] {
            let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
            let now = r.k.now();
            for id in 0..count {
                r.departing
                    .insert(id, now + Duration::from_secs(u64::from(id % 31) + 1));
            }
            let expected = Some(now + Duration::from_secs(1));
            let started = Instant::now();
            for _ in 0..20_000 {
                assert_eq!(std::hint::black_box(&r).next_deadline(), expected);
            }
            println!(
                "DEADLINE_COST records={count} queries=20000 elapsed_ns={}",
                started.elapsed().as_nanos()
            );
            assert_eq!(r.departing.len(), count as usize);
        }
    }
}
