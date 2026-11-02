//! Unit tests of the reconciler's pure parts; the behavioural rules are
//! tested against the fake kernel in `tests/rules/`.

pub(crate) fn socket_workload() -> std::sync::MutexGuard<'static, ()> {
    // Bound combined descriptor demand from the large fake namespaces.
    static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

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

    /// spec: L12, E25, T26, M14
    #[test]
    fn tunable_completions_reject_wrong_expired_and_finished_requests() {
        let mut r = reconciler();
        r.k.set_bindv6only(true);
        assert!(!r.reconcile(toml::from_str(CONFIG).unwrap()));
        let pending = r.tunable_pending.unwrap();
        r.take_requests();
        assert!(!r.reconcile(toml::from_str(CONFIG).unwrap()));
        assert_eq!(r.tunable_pending, Some(pending));
        assert!(
            r.take_requests().is_empty(),
            "reload duplicated an outstanding write"
        );
        r.tunable_written(pending.0 + 1, true);
        assert_eq!(r.tunable_pending, Some(pending));
        assert!(!r.ready());
        r.k.advance(Duration::from_secs(5));
        r.tunable_written(pending.0, true);
        assert_eq!(r.tunable_pending, Some(pending));
        assert!(!r.ready());
        r.tick();
        assert_eq!(r.tunable, Some(false));
        assert!(r.ready());
        r.tunable_written(pending.0, true);
        assert_eq!(r.tunable, Some(false));
        assert!(r.take_requests().is_empty());
    }

    /// spec: E25, T26, L12
    #[test]
    fn redundant_tunable_requests_preserve_the_original_outcome_and_deadline() {
        let mut r = reconciler();
        r.tunable = Some(true);
        r.request_tunable();
        assert!(r.take_requests().is_empty());
        assert!(r.tunable_pending.is_none());
        r.tunable = None;
        r.request_tunable();
        let pending = r.tunable_pending.unwrap();
        assert_eq!(r.take_requests().len(), 1);
        r.k.advance(Duration::from_secs(1));
        r.request_tunable();
        assert_eq!(r.tunable_pending, Some(pending));
        assert!(r.take_requests().is_empty());
    }

    /// spec: V6, V7, E10, E11, G2, G23
    #[test]
    fn resolver_answers_and_reload_tolerate_a_missing_local_record() {
        let answers = crate::rule_tests::Answers::default();
        let mut r = Reconciler::new(FakeKernel::new(42), Box::new(answers.clone()));
        let text = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nip_version='V4'\nremote_addr='peer.example'\n";
        assert!(r.reconcile(toml::from_str(text).unwrap()));
        let record = r.tunnels.remove(&10).unwrap();
        let socket = record.socket;
        r.k.clear_ops();
        answers.answer("peer.example", &["192.0.2.2"]);
        r.poll_answers();
        assert_eq!(r.resolvers.selected(10), Some("192.0.2.2".parse().unwrap()));
        assert!(
            r.k.ops().is_empty(),
            "an answer without a local owner issued a kernel operation"
        );
        let changed: Config =
            toml::from_str(&text.replace("peer.example", "other.example")).unwrap();
        r.k.fail_next("register", Errno::EIO);
        assert!(!r.reconcile(changed.clone()));
        assert!(r.tunnels.is_empty());
        assert!(answers.watching().is_empty());
        r.tunnels.insert(10, record);
        assert!(r.reconcile(changed));
        assert_eq!(r.tunnels[&10].socket, socket);
        assert_eq!(answers.watching()[0].host(), "other.example");
        assert_eq!(r.k.open_sockets(), 1);
    }

    /// spec: C14, T25, E14
    #[test]
    fn a_changed_conflict_identity_discards_its_counter_and_slow_deadline() {
        let mut r = reconciler();
        let config: Config = toml::from_str(CONFIG).unwrap();
        let old = ConflictIdentity::Tunnel(config.tunnels()["a"].identity());
        let changed: Config =
            toml::from_str(&CONFIG.replace("tunnel_id=10", "tunnel_id=10\npeer_tunnel_id=11"))
                .unwrap();
        let new = ConflictIdentity::Tunnel(changed.tunnels()["a"].identity());
        let error = std::io::Error::from_raw_os_error(Errno::EEXIST as i32);
        for _ in 0..10 {
            r.conflict(false, 10, old, "a", &error);
        }
        assert!(r.conflicts[&(false, 10)].left_out);
        assert!(r.conflict_times.first_deadline().is_some());
        assert!(r.may_try(false, 10, new));
        assert!(!r.conflicts.contains_key(&(false, 10)));
        assert!(r.conflict_times.first_deadline().is_none());
        r.conflict(false, 10, new, "a", &error);
        assert_eq!(r.conflicts[&(false, 10)].attempts, 1);
        assert!(!r.conflicts[&(false, 10)].left_out);
    }

    /// spec: T25, E12, E14, C14
    #[test]
    fn explicit_reload_retries_an_active_conflict_without_leaving_it_out() {
        let mut r = reconciler();
        r.k.fail_next("register", Errno::EEXIST);
        let config: Config = toml::from_str(CONFIG).unwrap();
        assert!(!r.reconcile(config.clone()));
        assert!(!r.conflicts[&(false, 10)].left_out);
        assert!(r.left_out().is_empty());
        assert!(r.reconcile(config));
        assert!(r.conflicts.is_empty());
        assert!(r.conflict_times.is_empty());
        assert!(r.ready());
    }

    /// spec: S28, E12, G20, G23
    #[test]
    fn an_already_absent_unmatched_session_cancels_its_retry() {
        let mut r = reconciler();
        r.unmatched_sessions.insert((10, 100));
        r.k.clear_ops();
        r.retry_unmatched_sessions();
        assert!(r.unmatched_sessions.is_empty());
        assert!(r.deleting_sessions.is_empty());
        assert!(r.k.ops().is_empty());
        assert!(!r.incomplete);
    }

    /// spec: E3, E12, S27, E27, G23
    #[test]
    fn removal_queries_retry_and_late_announcements_stay_bounded_until_absence() {
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
        let current = r.k.session_index(10, 100).unwrap();
        r.k.clear_ops();
        for _ in 0..3 {
            for _ in 0..100 {
                r.handle(
                    Source::L2tp,
                    Notice::SessionDeleted {
                        tunnel_id: 10,
                        session_id: 100,
                    },
                );
            }
            r.k.advance(RETRY);
            r.tick();
            assert_eq!(r.verify_sessions.len(), 1);
            assert_eq!(r.next_deadline(), Some(r.k.now() + RETRY));
            assert_eq!(r.k.session_index(10, 100), Some(current));
            assert!(r.k.ops().is_empty());
        }
        r.k.operator_delete_session(10, 100);
        r.k.tick();
        r.k.advance(RETRY);
        r.tick();
        assert!(r.verify_sessions.is_empty());
        assert_ne!(r.k.session_index(10, 100), Some(current));
        assert!(r.k.session_index(10, 100).is_some());
        assert_eq!(r.next_deadline(), None);
    }

    /// spec: E27, E18, C14, G23, M6
    #[test]
    fn verification_tasks_follow_configured_identity_even_when_cleanup_fails() {
        for change in ["remove", "session"] {
            let mut r = reconciler();
            assert!(r.reconcile(toml::from_str(CONFIG).unwrap()));
            r.handle(
                Source::L2tp,
                Notice::SessionDeleted {
                    tunnel_id: 10,
                    session_id: 100,
                },
            );
            r.handle(Source::L2tp, Notice::TunnelDeleted { tunnel_id: 10 });
            assert_eq!(r.verify_sessions.len(), 1);
            assert_eq!(r.verify_tunnels.len(), 1);
            let renamed = CONFIG.replace("[sessions.s]", "[sessions.renamed]");
            assert!(r.reconcile(toml::from_str(&renamed).unwrap()));
            assert_eq!(r.verify_sessions.len(), 1);
            assert_eq!(r.verify_tunnels.len(), 1);
            let next = match change {
                "remove" => toml::from_str(CONFIG.split("[sessions.s]").next().unwrap()).unwrap(),
                "session" => toml::from_str(&format!("{CONFIG}\npeer_session_id=101\n")).unwrap(),
                _ => unreachable!(),
            };
            r.k.fail_next("delete", Errno::EIO);
            assert!(!r.reconcile(next));
            assert!(r.sessions.contains_key(&100));
            assert!(r.tunnels.contains_key(&10));
            assert!(
                r.verify_sessions.is_empty(),
                "{change}: obsolete session task"
            );
            assert_eq!(r.verify_tunnels.len(), 1);

            r.k.fail_next("session", Errno::EIO);
            r.handle(
                Source::L2tp,
                Notice::SessionDeleted {
                    tunnel_id: 10,
                    session_id: 100,
                },
            );
            assert!(r.verify_sessions.is_empty());
            assert_eq!(
                r.k.session(10, 100).unwrap_err().raw_os_error(),
                Some(nix::libc::EIO)
            );
        }
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
            assert!(r.wanted_tunnels.is_empty());
            assert!(r.wanted_sessions.is_empty());
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

#[cfg(feature = "fake-kernel")]
mod cache_cost {
    use super::super::*;
    use crate::kernel::Notice;
    use crate::kernel::fake::FakeKernel;

    /// spec: E20, E6, M16, G23
    #[test]
    fn monitor_resync_discards_addresses_missing_from_the_complete_snapshot() {
        let mut kernel = FakeKernel::new(42);
        let index = kernel.add_link("wan", false);
        let address = "192.0.2.1".parse().unwrap();
        kernel.add_addr(index, address);
        let mut r = Reconciler::new(kernel, Box::new(IphostResolve::default()));
        r.reconcile(toml::from_str("[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='wan'").unwrap());
        assert_eq!(r.addresses.len(), 1);
        r.k.del_addr(index, address);
        r.handle(Source::Monitor, Notice::Loss);
        assert!(
            r.addresses.is_empty(),
            "resync retained an address absent from the complete dump"
        );
        assert!(r.address_devices.contains(&index));
    }

    /// spec: G12, M16, G23
    #[test]
    fn unbound_siblings_of_a_bound_vrf_member_never_enter_the_cache() {
        let mut kernel = FakeKernel::new(42);
        let vrf = kernel.add_link("vrf", true);
        let member = kernel.add_link("wan", false);
        kernel.set_master(member, Some(vrf));
        kernel.add_addr(member, "192.0.2.1".parse().unwrap());
        let mut r = Reconciler::new(kernel, Box::new(IphostResolve::default()));
        assert!(r.reconcile(toml::from_str("[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='wan'").unwrap()));
        r.k.clear_ops();
        for index in 1000..11_000 {
            r.handle(
                Source::Monitor,
                Notice::LinkNew(crate::kernel::LinkInfo::new(
                    index,
                    L2tpIfName::new(b"foreign").unwrap(),
                    true,
                    false,
                    Some(vrf),
                )),
            );
        }
        assert!(r.k.ops().is_empty());
        assert_eq!(
            r.masters.len(),
            1,
            "unbound siblings accumulated in the cache"
        );
        assert_eq!(r.members[&vrf], [member].into_iter().collect());
        assert!(r.changed_devices.is_empty());
        assert_eq!(r.address_devices, [member].into_iter().collect());
    }

    /// spec: E4, E6, E20, M16, G23
    #[test]
    fn vrf_cache_references_follow_binding_removal_and_member_moves() {
        let mut kernel = FakeKernel::new(42);
        let old = kernel.add_link("oldvrf", true);
        let new = kernel.add_link("newvrf", true);
        let a = kernel.add_link("a", false);
        let b = kernel.add_link("b", false);
        let c = kernel.add_link("c", false);
        for (device, master, address) in [
            (a, old, "192.0.2.1"),
            (b, old, "192.0.2.2"),
            (c, new, "192.0.2.3"),
        ] {
            kernel.set_master(device, Some(master));
            kernel.add_addr(device, address.parse().unwrap());
        }
        let mut r = Reconciler::new(kernel, Box::new(IphostResolve::default()));
        let one = "[host]\nfix_bindv6only=false\n[tunnels.member]\ntunnel_id=11\nremote_addr='192.0.2.254'\nbind_interface='a'";
        let both = format!(
            "{one}\n[tunnels.vrf]\ntunnel_id=10\nremote_addr='192.0.2.253'\nbind_interface='oldvrf'"
        );
        assert!(r.reconcile(toml::from_str(&both).unwrap()));
        assert_eq!(r.members[&old], [a, b].into_iter().collect());
        assert!(!r.masters.contains_key(&c));
        assert!(r.address_devices.contains(&old) && r.address_devices.contains(&b));
        assert!(r.reconcile(toml::from_str(one).unwrap()));
        assert_eq!(r.members[&old], [a].into_iter().collect());
        assert!(r.vrfs.contains_key(&old));
        assert_eq!(r.address_devices, [a].into_iter().collect());
        assert!(!r.addresses.contains_key(&b));
        r.k.set_master(a, Some(new));
        r.handle(
            Source::Monitor,
            Notice::LinkNew(r.k.link(a).unwrap().clone()),
        );
        assert_eq!(r.masters.get(&a), Some(&new));
        assert_eq!(r.members[&new], [a].into_iter().collect());
        assert!(!r.members.contains_key(&old) && !r.vrfs.contains_key(&old));
        assert!(r.vrfs.contains_key(&new));
        r.reconcile(Config::new());
        assert!(r.masters.is_empty() && r.members.is_empty() && r.vrfs.is_empty());
        assert!(
            r.address_devices.is_empty() && r.addresses.is_empty() && r.changed_devices.is_empty()
        );
        assert_eq!(r.k.link(a).unwrap().master, Some(new));
        assert_eq!(r.k.link(b).unwrap().master, Some(old));
        assert_eq!(r.k.link(c).unwrap().master, Some(new));
    }

    /// spec: E20, E21, M16
    #[test]
    fn failed_address_seed_is_retried_by_monitor_resync() {
        let mut kernel = FakeKernel::new(42);
        let device = kernel.add_link("wan", false);
        let address = "192.0.2.1".parse().unwrap();
        kernel.add_addr(device, address);
        // Initial indexing and the first convergence can each seed addresses.
        for _ in 0..2 {
            kernel.fail_next("dump", nix::errno::Errno::EIO);
        }
        let mut r = Reconciler::new(kernel, Box::new(IphostResolve::default()));
        r.reconcile(toml::from_str("[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='wan'").unwrap());
        assert!(r.ready());
        assert!(r.monitor_pending && !r.address_devices.contains(&device));
        assert_eq!(r.next_deadline(), Some(r.k.now() + RETRY));
        r.k.advance(RETRY);
        r.tick();
        assert!(!r.monitor_pending);
        assert!(r.address_devices.contains(&device));
        assert_eq!(
            r.addresses.get(&device),
            Some(&[address].into_iter().collect())
        );
        assert!(r.changed_devices.is_empty());
        assert_eq!(r.next_deadline(), None);
    }

    /// spec: G12, M16
    #[test]
    fn unchanged_bound_link_workload_preserves_other_dependencies() {
        let _socket_workload = super::socket_workload();
        for count in [1, 100, 300] {
            let mut kernel = FakeKernel::new(42);
            let mut text = "[host]\nfix_bindv6only=false\n".to_owned();
            let mut first = None;
            for n in 0..count {
                let device = kernel.add_link(&format!("wan{n}"), false);
                first.get_or_insert(device);
                kernel.add_addr(device, "192.0.2.1".parse().unwrap());
                kernel.set_up(device, true);
                text += &format!(
                    "[tunnels.t{n}]\ntunnel_id={}\nremote_addr='192.0.2.254'\nbind_interface='wan{n}'\n",
                    n + 1
                );
            }
            let mut r = Reconciler::new(kernel, Box::new(IphostResolve::default()));
            assert!(r.reconcile(toml::from_str(&text).unwrap()));
            let link = r.k.link(first.unwrap()).unwrap().clone();
            r.k.clear_ops();
            let started = Instant::now();
            for _ in 0..500 {
                r.handle(Source::Monitor, Notice::LinkNew(link.clone()));
            }
            println!(
                "CACHE_COST bindings={count} events=500 elapsed_ns={}",
                started.elapsed().as_nanos()
            );
            assert!(
                r.k.ops().is_empty(),
                "unchanged link issued kernel operations"
            );
            assert_eq!(r.tunnels.len(), count);
            assert_eq!(r.address_devices.len(), count);
            assert!(r.changed_devices.is_empty() && r.changed_bindings.is_empty());

            let old = r.k.add_link("oldvrf", true);
            let new = r.k.add_link("newvrf", true);
            let devices: Vec<_> = r.address_devices.iter().copied().collect();
            for device in devices {
                r.k.set_master(device, Some(old));
                r.handle(
                    Source::Monitor,
                    Notice::LinkNew(r.k.link(device).unwrap().clone()),
                );
            }
            r.k.clear_ops();
            let started = Instant::now();
            for n in 0..500 {
                let master = if n % 2 == 0 { new } else { old };
                r.k.set_master(link.index, Some(master));
                r.handle(
                    Source::Monitor,
                    Notice::LinkNew(r.k.link(link.index).unwrap().clone()),
                );
            }
            println!(
                "MEMBER_COST bindings={count} events=500 elapsed_ns={}",
                started.elapsed().as_nanos()
            );
            assert_eq!(
                r.k.ops()
                    .iter()
                    .filter(|op| op.starts_with("connect "))
                    .count(),
                500
            );
            assert_eq!(r.masters.len(), count);
            assert_eq!(r.members[&old].len(), count);
            assert!(r.changed_devices.is_empty() && r.changed_bindings.is_empty());
        }
    }
}
