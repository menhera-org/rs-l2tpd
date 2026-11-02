use super::*;
use crate::config::Config;
use crate::kernel::fake::FakeKernel;
use crate::reconciler::records::{Connection, TunnelRecord};
use crate::reconciler::{IphostResolve, RETRY};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Instant;

/// spec: S4, S8, S22, S23, A14
#[test]
fn timed_out_creation_keeps_uncertainty_until_a_complete_fresh_scan() {
    use crate::kernel::SessionCreate;
    for asynchronous in [false, true] {
        for applied in [false, true] {
            for extra in ["", "interface_hwaddr='02:00:5e:00:53:01'"] {
                let mut r =
                    Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
                r.k.set_async_session_delete(asynchronous);
                let tunnel = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\n";
                assert!(r.reconcile(toml::from_str(tunnel).unwrap()));
                let config: Config = toml::from_str(&format!("{tunnel}\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'\n{extra}")).unwrap();
                let session = &config.sessions()["s"];
                let identity = config.session_identity("s").unwrap();
                let parent = r.k.tunnel_socket(10).unwrap();
                r.k.fail_next("create", Errno::ETIMEDOUT);
                r.stage("s", session, identity, 10).unwrap();
                assert!(matches!(
                    r.sessions[&100].state,
                    Identity::Lost { staged: true }
                ));
                let name = r.sessions[&100].created_as.unwrap();
                // Complete the uncertain kernel operation before verification.
                if applied {
                    r.k.create_session(&SessionCreate::new(
                        10,
                        100,
                        session.peer_session_id(),
                        session.cookie(),
                        session.peer_cookie(),
                        name,
                    ))
                    .unwrap();
                }
                r.k.clear_ops();
                r.k.fail_next("scan", Errno::EIO);
                assert!(!r.converge_session(100));
                assert!(r.sessions.contains_key(&100));
                assert!(r.reserved.contains_key(&name));
                assert_eq!(r.k.session(10, 100).unwrap().is_some(), applied);
                assert!(r.k.ops().is_empty());
                r.k.scan_sessions(None, &mut |_| {}).unwrap(); // the failed scan was attempted
                assert!(!r.converge_session(100));
                if applied {
                    r.k.tick();
                    if r.sessions.contains_key(&100) {
                        assert!(!r.converge_session(100));
                    }
                }
                assert!(!r.sessions.contains_key(&100));
                assert!(r.k.session(10, 100).unwrap().is_none());
                assert_eq!(
                    r.k.ops()
                        .iter()
                        .filter(|op| op.starts_with("delete-name "))
                        .count(),
                    usize::from(applied)
                );
                r.release_departed();
                assert!(!r.reserved.contains_key(&name));
                r.stage("s", session, identity, 10).unwrap();
                assert!(r.converge_session(100));
                let recreated = r.k.session(10, 100).unwrap().unwrap();
                assert_eq!(
                    recreated.ifname().unwrap().to_string_lossy() == "l2tp0",
                    extra.is_empty()
                );
                let index = r.k.session_index(10, 100).unwrap();
                assert_eq!(r.k.link(index).unwrap().name().to_string_lossy(), "l2tp0");
                assert_eq!(r.k.tunnel_socket(10), Some(parent));
            }
        }
    }
}

/// spec: C14, M6, M16, G23
#[test]
fn wanted_lookup_cost_and_identity_checks() {
    for count in [1, 100, 300, 1000] {
        let mut text = String::new();
        for id in 1..=count {
            text += &format!(
                "[tunnels.t{id:04}]\ntunnel_id={id}\nremote_addr='192.0.2.2'\n[sessions.s{id:04}]\ntunnel_name='t{id:04}'\nsession_id={id}\ninterface_name='s{id}'\n"
            );
        }
        let config: Config = toml::from_str(&text).unwrap();
        let tunnel_name = format!("t{count:04}");
        let session_name = format!("s{count:04}");
        let tunnel = &config.tunnels()[&tunnel_name];
        let session = &config.sessions()[&session_name];
        let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
        // Synthetic records isolate lookup cost without opening count sockets.
        r.tunnels.insert(
            count,
            TunnelRecord {
                name: tunnel_name.clone(),
                config: tunnel.clone(),
                identity: tunnel.identity(),
                socket: crate::kernel::SocketId::new(0),
                family: crate::config::Family::V4,
                bound: None,
                bind_index: None,
                zone_index: None,
                connection: Connection::Disconnected { pending: None },
                stale: false,
            },
        );
        r.sessions.insert(
            count,
            SessionRecord {
                name: session_name.clone(),
                config: session.clone(),
                identity: config.session_identity(&session_name).unwrap(),
                tunnel_id: count,
                state: Identity::Adopted,
                created_as: None,
                current_name: None,
                name_state: Enforce::Pending,
                hwaddr: None,
                hwaddr_state: Enforce::Pending,
                kernel_hwaddr: None,
            },
        );
        r.wanted_tunnels = config
            .tunnels()
            .iter()
            .map(|(n, t)| (t.tunnel_id(), n.clone()))
            .collect();
        r.wanted_sessions = config
            .sessions()
            .iter()
            .map(|(n, s)| (s.session_id(), n.clone()))
            .collect();
        r.accepted = config;
        let scan = || {
            let tunnel = r
                .accepted
                .tunnels()
                .iter()
                .find(|(_, t)| t.identity() == r.tunnels[&count].identity)
                .map(|(n, t)| (n.clone(), t.clone()));
            let session = r
                .accepted
                .sessions()
                .iter()
                .find(|(n, _)| r.accepted.session_identity(n) == Some(r.sessions[&count].identity))
                .map(|(n, s)| (n.clone(), s.clone()));
            (tunnel, session)
        };
        assert_eq!(scan(), (r.tunnel_wanted(count), r.session_wanted(count)));
        let started = Instant::now();
        for _ in 0..500 {
            black_box(scan());
        }
        let scan_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        for _ in 0..500 {
            black_box((r.tunnel_wanted(count), r.session_wanted(count)));
        }
        println!(
            "WANTED_LOOKUP entries={count} queries=500 scan_ns={scan_ns} indexed_ns={}",
            started.elapsed().as_nanos()
        );
        r.tunnels.get_mut(&count).unwrap().identity =
            crate::config::TunnelIdentity::new(count, count + 1);
        assert!(r.tunnel_wanted(count).is_none());
        let cookie = crate::config::Cookie::new(&[1, 2, 3, 4]).unwrap();
        for (tunnel, sid, peer, sent, received) in [
            (count + 1, count, count, None, None),
            (count, count + 1, count, None, None),
            (count, count, count + 1, None, None),
            (count, count, count, Some(cookie), None),
            (count, count, count, None, Some(cookie)),
        ] {
            r.sessions.get_mut(&count).unwrap().identity = crate::config::SessionIdentity::new(
                crate::config::TunnelIdentity::new(tunnel, tunnel),
                sid,
                peer,
                sent,
                received,
            );
            assert!(r.session_wanted(count).is_none());
        }
        r.wanted_tunnels.clear();
        r.wanted_sessions.clear();
        assert!(r.tunnel_wanted(count).is_none());
        assert!(r.session_wanted(count).is_none());
        assert!(r.tunnel_wanted(count + 1).is_none());
        assert!(r.session_wanted(count + 1).is_none());
        assert!(r.k.ops().is_empty());
    }
}

/// spec: C14, M6, G23
#[test]
fn desired_indexes_follow_operator_names_and_release_on_shutdown() {
    let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
    let text = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'\n";
    assert!(r.reconcile(toml::from_str(text).unwrap()));
    let socket = r.tunnels[&10].socket;
    let device = r.k.session_index(10, 100);
    let renamed = text
        .replace("tunnels.a", "tunnels.z")
        .replace("sessions.s", "sessions.q")
        .replace("tunnel_name='a'", "tunnel_name='z'");
    assert!(r.reconcile(toml::from_str(&renamed).unwrap()));
    assert_eq!(r.wanted_tunnels, BTreeMap::from([(10, "z".to_owned())]));
    assert_eq!(r.wanted_sessions, BTreeMap::from([(100, "q".to_owned())]));
    assert_eq!(r.tunnel_wanted(10).unwrap().0, "z");
    assert_eq!(r.session_wanted(100).unwrap().0, "q");
    assert_eq!(r.tunnels[&10].socket, socket);
    assert_eq!(r.k.session_index(10, 100), device);
    assert!(r.shutdown());
    assert!(r.wanted_tunnels.is_empty());
    assert!(r.wanted_sessions.is_empty());
}

/// spec: S11, S19, S27, M6, G2, G4
#[test]
fn a_removed_middle_of_a_rename_chain_releases_only_its_own_cached_name() {
    for fail_rename in [false, true] {
        let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
        let document = |changed: bool| {
            let mut text = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\n".to_owned();
            for n in 0..3 {
                let target = n + usize::from(changed);
                text += &format!(
                    "[sessions.s{n}]\ntunnel_name='a'\nsession_id={}\ninterface_name='n{target}'\n",
                    100 + n
                );
            }
            toml::from_str(&text).unwrap()
        };
        assert!(r.reconcile(document(false)));
        let first = r.k.session_index(10, 100);
        let middle = r.k.session_index(10, 101);
        let last = r.k.session_index(10, 102);
        r.k.operator_delete_session(10, 101);
        r.k.tick();
        if fail_rename {
            r.k.fail_next("rename", nix::errno::Errno::EIO);
        }
        r.reconcile(document(true));
        for _ in 0..3 {
            r.k.advance(super::super::RETRY);
            r.k.tick();
            for notice in r.k.take_monitor() {
                r.handle(super::super::Source::Monitor, notice);
            }
            for notice in r.k.take_l2tp() {
                r.handle(super::super::Source::L2tp, notice);
            }
            r.tick();
        }
        assert_eq!(r.k.session_index(10, 100), first);
        assert_ne!(r.k.session_index(10, 101), middle);
        assert_eq!(r.k.session_index(10, 102), last);
        for n in 0..3 {
            let index = r.k.session_index(10, 100 + n).unwrap();
            assert_eq!(
                r.k.link(index).unwrap().name().to_string_lossy(),
                format!("n{}", n + 1)
            );
        }
    }
}

/// spec: S11, S17, G2, G4
#[test]
fn overlapping_retained_targets_never_move_the_first_completed_holder() {
    let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
    let text = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\n[sessions.a]\ntunnel_name='a'\nsession_id=100\ninterface_name='n0'\n[sessions.b]\ntunnel_name='a'\nsession_id=101\ninterface_name='n1'\n";
    assert!(r.reconcile(toml::from_str(text).unwrap()));
    // Old records retained after failed deletion can overlap new targets.
    for (sid, record) in &mut r.sessions {
        record.config = SessionConfig::builder("a", *sid, L2tpIfName::new(b"n2").unwrap())
            .build()
            .unwrap();
        record.name_state = Enforce::Pending;
    }
    r.k.clear_ops();
    r.clear_swaps();
    assert_eq!(
        r.sessions[&100].current_name.unwrap().to_string_lossy(),
        "n2"
    );
    assert_eq!(r.sessions[&100].name_state, Enforce::Applied);
    assert_eq!(
        r.sessions[&101].current_name.unwrap().to_string_lossy(),
        "n1"
    );
    assert_eq!(r.sessions[&101].name_state, Enforce::Pending);
    assert_eq!(
        r.k.ops()
            .iter()
            .filter(|op| op.starts_with("rename "))
            .count(),
        1
    );
}

/// spec: S11, M6, G2, G4
#[test]
fn duplicate_cached_names_remain_held_until_the_last_record_moves() {
    let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
    let document = |changed: bool| {
        let mut text =
            "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\n"
                .to_owned();
        for n in 0..3 {
            let target = n + if changed { 2 } else { 0 };
            text += &format!(
                "[sessions.s{n}]\ntunnel_name='a'\nsession_id={}\ninterface_name='n{target}'\n",
                100 + n
            );
        }
        toml::from_str(&text).unwrap()
    };
    assert!(r.reconcile(document(false)));
    r.sessions.get_mut(&100).unwrap().current_name = Some(L2tpIfName::new(b"n1").unwrap());
    r.k.clear_ops();
    assert!(r.reconcile(document(true)));
    assert!(!r.k.ops().iter().any(|op| op.contains("rsl2tp-r")));
    for n in 0..3 {
        let index = r.k.session_index(10, 100 + n).unwrap();
        assert_eq!(
            r.k.link(index).unwrap().name().to_string_lossy(),
            format!("n{}", n + 2)
        );
    }
}

fn staging_fixture(extra: &str) -> (Reconciler<FakeKernel>, Config) {
    let tunnel =
        "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\n";
    let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
    assert!(r.reconcile(toml::from_str(tunnel).unwrap()));
    let config = toml::from_str(&format!(
        "{tunnel}[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'\n{extra}"
    ))
    .unwrap();
    (r, config)
}

/// spec: S4, S7, S8, G2
#[test]
fn staging_uses_a_free_eighth_name_and_refuses_after_eight_collisions() {
    let mut predictor = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
    let names: Vec<_> = (0..8)
        .map(|_| predictor.random_name("rsl2tp-t").unwrap())
        .collect();
    assert_eq!(
        names
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        8
    );
    for collisions in [7, 8] {
        let (mut r, config) = staging_fixture("interface_hwaddr='02:00:5e:00:53:01'\n");
        let configured_mac = config.sessions()["s"].interface_hwaddr();
        let parent = r.k.tunnel_socket(10).unwrap();
        let foreign: Vec<_> = names[..collisions]
            .iter()
            .map(|name| {
                let index = r.k.add_link(name.to_str().unwrap(), false);
                let link = r.k.link(index).unwrap().clone();
                let mac = r.k.ether_addr(index).unwrap();
                (index, link, mac)
            })
            .collect();
        r.k.fail_after("random", 8, Errno::EIO);
        r.k.clear_ops();
        let result = r.stage(
            "s",
            &config.sessions()["s"],
            config.session_identity("s").unwrap(),
            10,
        );
        if collisions == 7 {
            result.unwrap();
            assert_eq!(r.sessions[&100].created_as, Some(names[7]));
            assert!(matches!(r.sessions[&100].state, Identity::Staged(_)));
            assert_eq!(r.reserved[&names[7]], (10, 100));
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Other);
            assert!(error.to_string().contains("eight staging names"));
            assert!(r.sessions.is_empty() && r.reserved.is_empty());
            assert!(r.k.session(10, 100).unwrap().is_none());
            assert!(r.k.ops().is_empty());
        }
        assert_eq!(
            r.k.random().unwrap_err().raw_os_error(),
            Some(Errno::EIO as i32)
        );
        let before = r.k.session_index(10, 100);
        assert!(r.reconcile(config));
        assert!(r.ready());
        assert_eq!(r.k.tunnel_socket(10), Some(parent));
        if before.is_some() {
            assert_eq!(r.k.session_index(10, 100), before);
        }
        assert_eq!(r.reserved.len(), 1);
        let index = r.k.session_index(10, 100).unwrap();
        assert_eq!(r.k.link(index).unwrap().name().to_string_lossy(), "l2tp0");
        assert_eq!(r.k.ether_addr(index).unwrap(), configured_mac);
        let hwaddr =
            r.k.ops()
                .iter()
                .position(|op| op.starts_with(&format!("hwaddr {index} ")))
                .unwrap();
        let publish =
            r.k.ops()
                .iter()
                .position(|op| op == &format!("rename {index} l2tp0"))
                .unwrap();
        assert!(hwaddr < publish, "configured MAC must precede publication");
        for (index, link, mac) in foreign {
            assert_eq!(r.k.link(index), Some(&link));
            assert_eq!(r.k.ether_addr(index).unwrap(), mac);
        }
    }
}

/// spec: S4, S7, S14, K19
#[test]
fn a_creation_refusal_without_a_name_collision_preserves_the_errno_and_retries_cleanly() {
    for errno in [Errno::EEXIST, Errno::ENFILE, Errno::EPERM] {
        let (mut r, config) = staging_fixture("");
        let parent = r.k.tunnel_socket(10).unwrap();
        r.k.fail_next("create", errno);
        r.k.fail_next("random", Errno::EIO);
        let error = r
            .stage(
                "s",
                &config.sessions()["s"],
                config.session_identity("s").unwrap(),
                10,
            )
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(errno as i32));
        assert!(r.sessions.is_empty() && r.reserved.is_empty());
        assert!(r.k.session(10, 100).unwrap().is_none());
        assert_eq!(
            r.k.random().unwrap_err().raw_os_error(),
            Some(Errno::EIO as i32)
        );
        assert!(r.reconcile(config));
        assert!(r.ready());
        assert_eq!(r.k.tunnel_socket(10), Some(parent));
        assert_eq!(r.reserved.len(), 1);
        let index = r.k.session_index(10, 100).unwrap();
        assert_eq!(r.k.link(index).unwrap().name().to_string_lossy(), "l2tp0");
    }
}

/// spec: S8, S10, S18, G4
#[test]
fn a_pending_name_already_observed_as_the_target_needs_no_kernel_write() {
    let (mut r, config) = staging_fixture("");
    assert!(r.reconcile(config));
    let registration = *r.sessions[&100].state.registration().unwrap();
    r.sessions.get_mut(&100).unwrap().name_state = Enforce::Pending;
    r.k.clear_ops();
    r.clear_swaps();
    assert!(r.converge_session(100));
    assert_eq!(r.sessions[&100].name_state, Enforce::Applied);
    assert_eq!(r.sessions[&100].state, Identity::Proved(registration));
    assert!(r.k.ops().is_empty(), "already satisfied name was rewritten");
    let record = r.sessions.get_mut(&100).unwrap();
    record.state = Identity::Adopted;
    record.name_state = Enforce::Pending;
    r.skip_unmanageable(100);
    assert_eq!(r.sessions[&100].name_state, Enforce::Pending);
    assert!(
        r.k.ops().is_empty(),
        "already satisfied adopted name was rewritten"
    );
}

/// spec: S8, S10, S18, G4
#[test]
fn a_name_observed_during_staging_remains_subject_to_first_publication() {
    let (mut r, config) = staging_fixture("interface_hwaddr='02:00:5e:00:53:01'");
    r.accepted = config.clone();
    r.wanted_sessions.insert(100, "s".into());
    r.stage(
        "s",
        &config.sessions()["s"],
        config.session_identity("s").unwrap(),
        10,
    )
    .unwrap();
    let registration = *r.sessions[&100].state.registration().unwrap();
    let manager = L2tpIfName::new(b"manager").unwrap();
    r.k.rename_link(registration.index, "manager");
    r.session_device_changed(100, manager, false);
    assert_eq!(r.sessions[&100].current_name, Some(manager));
    assert_eq!(r.sessions[&100].name_state, Enforce::Pending);
    assert!(r.converge_session(100));
    assert_eq!(
        r.k.link(registration.index)
            .unwrap()
            .name()
            .to_string_lossy(),
        "l2tp0"
    );
    assert_eq!(r.sessions[&100].name_state, Enforce::Applied);
}

/// spec: S12, S19, S22, G2, G4
#[test]
fn device_notices_without_identity_proof_or_a_readable_mac_never_authorize_writes() {
    for case in [
        "lost-applied",
        "lost-deferred",
        "proof-applied",
        "proof-deferred",
        "ether-error",
        "ether-absent",
    ] {
        let (mut r, config) = staging_fixture("interface_hwaddr='02:00:5e:00:53:01'");
        assert!(r.reconcile(config));
        let index = r.k.session_index(10, 100).unwrap();
        let name = r.k.link(index).unwrap().name();
        if case.starts_with("lost") {
            r.sessions.get_mut(&100).unwrap().state = Identity::Lost { staged: false };
        } else if case.starts_with("proof") {
            r.k.lose_lifetime();
        } else if case == "ether-error" {
            r.k.fail_next("link", Errno::EIO);
        } else {
            r.k.clear_link_hwaddr(index);
        }
        let enforcement = if case.ends_with("deferred") {
            Enforce::Deferred
        } else {
            Enforce::Applied
        };
        r.sessions.get_mut(&100).unwrap().hwaddr_state = enforcement;
        let before = r.k.hwaddr(index);
        r.k.clear_ops();
        r.session_device_changed(100, name, false);
        assert_eq!(r.sessions[&100].hwaddr_state, enforcement, "{case}");
        assert_eq!(r.k.hwaddr(index), before, "{case}");
        assert!(r.k.ops().is_empty(), "{case}: {:?}", r.k.ops());
        if case.starts_with("lost") {
            let renamed = L2tpIfName::new(b"late-name").unwrap();
            r.session_device_changed(100, renamed, false);
            assert_eq!(r.sessions[&100].current_name, Some(renamed));
            assert_eq!(r.sessions[&100].name_state, Enforce::Applied);
            assert!(r.k.ops().is_empty());
        }
    }
}

/// spec: S9, S22, G2, G4
#[test]
fn deletion_without_a_stored_creation_name_neither_scans_nor_guesses() {
    let (mut r, config) = staging_fixture("");
    assert!(r.reconcile(config));
    let index = r.k.session_index(10, 100).unwrap();
    r.sessions.get_mut(&100).unwrap().created_as = None;
    r.k.fail_next("scan", Errno::EIO);
    r.k.clear_ops();
    assert!(r.delete_verified(100));
    assert_eq!(r.k.session_index(10, 100), Some(index));
    assert!(r.k.ops().is_empty());
    assert_eq!(
        r.k.scan_sessions(None, &mut |_| {})
            .unwrap_err()
            .raw_os_error(),
        Some(Errno::EIO as i32),
        "missing name must not consume a dump"
    );
}

/// spec: S9, S22, E12, G2
#[test]
fn deletion_races_accept_enodev_after_both_proof_and_complete_dump() {
    for lost in [false, true] {
        let (mut r, config) = staging_fixture("");
        assert!(r.reconcile(config));
        let index = r.k.session_index(10, 100).unwrap();
        r.k.fail_next("delete", Errno::ENODEV);
        r.k.clear_ops();
        let removed = if lost {
            r.delete_verified(100)
        } else {
            r.delete_session(100)
        };
        assert!(removed);
        assert_eq!(r.k.session_index(10, 100), Some(index));
        assert!(r.deleting_sessions.is_empty());
        assert!(r.k.ops().is_empty());
        assert!(
            r.k.delete_session(10, 100).is_ok(),
            "the injected race was consumed"
        );
    }
}

/// spec: S25, S26, T8, K17, G9, G20
#[test]
fn failed_child_deletion_still_retires_its_unwanted_parent_and_local_record() {
    let (mut r, config) = staging_fixture("");
    assert!(r.reconcile(config));
    let held = r.k.clone_fd(r.tunnels[&10].socket).unwrap();
    r.k.fail_next("delete", Errno::EIO);
    assert!(!r.reconcile(Config::new()));
    assert!(r.sessions.is_empty());
    assert!(r.tunnels.is_empty());
    assert!(
        r.k.ops()
            .iter()
            .any(|operation| operation.starts_with("close "))
    );
    r.k.tick();
    assert!(r.k.session(10, 100).unwrap().is_some());
    drop(held);
    // A concurrently forked fixture can retain CLOEXEC descriptors until exec.
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    let fake_now = r.k.now();
    while r.k.session(10, 100).unwrap().is_some() {
        assert!(
            Instant::now() < deadline,
            "last socket reference remained open"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
        r.k.tick();
    }
    assert_eq!(r.k.now(), fake_now);
    r.k.advance(super::super::RETRY);
    r.tick();
    assert!(r.ready());
    assert!(r.k.tunnel(10).unwrap().is_none());
    assert!(r.reserved.is_empty());
}

/// spec: S28, T8, K17, E12, G20, G23
#[test]
fn an_unwanted_adopted_parent_drops_its_unmatched_child_retry_and_report() {
    let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
    let socket =
        r.k.create_socket(crate::kernel::Family::V6, 10, 20)
            .unwrap();
    r.k.register_tunnel(socket, 10, 20).unwrap();
    r.k.create_session(&crate::kernel::SessionCreate::new(
        10,
        101,
        101,
        None,
        None,
        L2tpIfName::new(b"unmatched").unwrap(),
    ))
    .unwrap();
    let fd = r.k.clone_fd(socket).unwrap();
    r.k.close(socket);
    r.inherit("t10".into(), fd);
    let mut config = Config::new();
    config.set_host(crate::config::HostConfig::new().with_fix_bindv6only(false));
    config
        .insert_tunnel(
            "a",
            crate::config::TunnelConfig::builder(10)
                .peer_tunnel_id(20)
                .ip_version(crate::kernel::Family::V6)
                .build()
                .unwrap(),
        )
        .unwrap();
    r.k.fail_next("delete", Errno::EPERM);
    assert!(!r.reconcile(config));
    assert_eq!(
        r.unmatched_sessions.iter().copied().collect::<Vec<_>>(),
        [(10, 101)]
    );
    let label = crate::reconciler::report::session("", 10, 101);
    assert!(r.report.is_open(&label, "adoption-delete"));
    r.k.fail_next("delete", Errno::EPERM);
    assert!(!r.reconcile(Config::new()));
    assert!(r.unmatched_sessions.is_empty());
    assert!(!r.report.is_open(&label, "adoption-delete"));
    assert!(r.tunnels.is_empty());
    r.k.tick();
    r.k.advance(super::super::RETRY);
    r.tick();
    assert!(r.ready());
    assert!(r.k.session(10, 101).unwrap().is_none());
}

/// spec: S11, S25, G2, G12, C14
#[test]
fn competing_pending_names_preserve_the_first_owner_during_failed_removal() {
    use crate::kernel::Notice;
    use crate::reconciler::Source;

    for already_named in [false, true] {
        let document = |first: &str, second: Option<&str>| {
            let mut text = format!(
                "[host]\nfix_bindv6only=false\n[tunnels.t]\ntunnel_id=10\nremote_addr='192.0.2.2'\n[sessions.a]\ntunnel_name='t'\nsession_id=100\ninterface_name='{first}'\n"
            );
            if let Some(second) = second {
                text += &format!(
                    "[sessions.b]\ntunnel_name='t'\nsession_id=101\ninterface_name='{second}'\n"
                );
            }
            toml::from_str::<Config>(&text).unwrap()
        };
        let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
        assert!(r.reconcile(document("first", Some("second"))));
        let first = r.k.session_index(10, 100).unwrap();
        let second = r.k.session_index(10, 101).unwrap();
        let foreign = r.k.add_link("target", false);
        assert!(!r.reconcile(document("first", Some("target"))));
        assert_eq!(r.sessions[&101].name_state, Enforce::Pending);
        assert_eq!(r.k.link(second).unwrap().name().to_string_lossy(), "second");
        r.k.remove_link(foreign);
        if already_named {
            r.k.rename_link(first, "target");
            r.handle(
                Source::Monitor,
                Notice::LinkNew(r.k.link(first).unwrap().clone()),
            );
        }
        r.k.clear_ops();
        r.k.fail_next("delete", Errno::EIO);
        if !already_named {
            r.k.fail_after("rename", 2, Errno::EIO);
        }
        assert!(!r.reconcile(document("target", None)));
        assert_eq!(r.k.session_index(10, 100), Some(first));
        assert_eq!(r.k.session_index(10, 101), Some(second));
        assert_eq!(r.k.link(first).unwrap().name().to_string_lossy(), "target");
        assert_eq!(r.k.link(second).unwrap().name().to_string_lossy(), "second");
        let renames =
            r.k.ops()
                .iter()
                .filter(|op| op.starts_with("rename "))
                .count();
        assert_eq!(renames, usize::from(!already_named));
        if !already_named {
            // Two attempts suffice: the winner and the unwanted loser's ordinary convergence.
            assert_eq!(
                r.k.rename(first, &L2tpIfName::new("target").unwrap())
                    .unwrap_err()
                    .raw_os_error(),
                Some(Errno::EIO as i32)
            );
        }
    }
}

/// spec: E27, T9, E18, M14, G2
#[test]
fn an_unverified_tunnel_deletion_is_retried_by_the_tick_without_recreating_it() {
    use crate::kernel::Notice;
    use crate::reconciler::Source;
    let mut k = FakeKernel::new(42);
    let wan = k.add_link("wan", false);
    k.add_addr(wan, "192.0.2.1".parse().unwrap());
    let mut r = Reconciler::new(k, Box::new(IphostResolve::default()));
    let config: Config = toml::from_str(
        "[host]\nfix_bindv6only=false\n[tunnels.t]\ntunnel_id=10\nremote_addr='192.0.2.2'\n",
    )
    .unwrap();
    assert!(r.reconcile(config));
    let socket = r.k.tunnel_socket(10).unwrap();
    r.k.fail_next("tunnel", Errno::EIO);
    r.handle(Source::L2tp, Notice::TunnelDeleted { tunnel_id: 10 });
    assert!(r.verify_tunnels.contains(&10));
    r.k.clear_ops();
    r.k.fail_next("tunnel", Errno::EIO);
    r.k.advance(RETRY);
    r.tick();
    // The tick must consume the failed lookup, rather than merely retain its task.
    assert_eq!(r.k.tunnel(10).unwrap().unwrap().tunnel_id(), 10);
    assert!(r.verify_tunnels.contains(&10));
    assert_eq!(r.k.tunnel_socket(10), Some(socket));
    assert!(r.k.ops().is_empty());
    r.reconcile(Config::new());
    assert!(r.verify_tunnels.is_empty());
    r.k.tick();
    assert!(r.k.tunnel_socket(10).is_none());
    assert!(!r.k.ops().iter().any(|op| op.starts_with("socket ")));
}

/// spec: T22, C14, G2
#[test]
fn an_unwanted_record_has_no_in_place_configuration_update() {
    let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
    assert!(
        r.reconcile(
            toml::from_str(
                "[host]\nfix_bindv6only=false\n[tunnels.t]\ntunnel_id=10\nremote_addr='192.0.2.2'\n"
            )
            .unwrap()
        )
    );
    let socket = r.tunnels[&10].socket;
    let config = r.tunnels[&10].config.clone();
    // Isolate the update guard for a record whose removal has not yet run.
    r.accepted = Config::new();
    r.wanted_tunnels.clear();
    r.k.clear_ops();
    r.update_tunnels_in_place();
    assert_eq!(r.tunnels[&10].socket, socket);
    assert_eq!(r.tunnels[&10].config, config);
    assert_eq!(r.tunnels[&10].name, "t");
    assert!(r.k.ops().is_empty());
}

/// spec: T22, T27, E3, E6, M17
#[test]
fn a_replaced_zone_reconnects_the_existing_socket_even_when_its_peer_is_unchanged() {
    use crate::kernel::Notice;
    use crate::reconciler::Source;
    let mut k = FakeKernel::new(42);
    let old = k.add_link("zone", false);
    k.add_addr(old, "fe80::1".parse().unwrap());
    let mut r = Reconciler::new(k, Box::new(IphostResolve::default()));
    assert!(r.reconcile(toml::from_str("[host]\nfix_bindv6only=false\n[tunnels.t]\ntunnel_id=10\nip_version='V6'\nremote_addr='fe80::2%zone'\n").unwrap()));
    let socket = r.tunnels[&10].socket;
    assert_eq!(r.tunnels[&10].zone_index, Some(old));
    r.k.remove_link(old);
    let new = r.k.add_link("zone", false);
    r.k.add_addr(new, "fe80::1".parse().unwrap());
    r.k.clear_ops();
    r.handle(
        Source::Monitor,
        Notice::LinkNew(r.k.link(new).unwrap().clone()),
    );
    assert_ne!(old, new);
    assert_eq!(r.tunnels[&10].zone_index, Some(new));
    assert_eq!(r.tunnels[&10].socket, socket);
    assert!(r.k.connection(socket).is_some());
    assert_eq!(
        r.k.ops()
            .iter()
            .filter(|op| op.starts_with("disconnect "))
            .count(),
        1
    );
    assert_eq!(
        r.k.ops()
            .iter()
            .filter(|op| op.starts_with("connect "))
            .count(),
        1
    );
    assert!(
        !r.k.ops()
            .iter()
            .any(|op| op.starts_with("socket ") || op.starts_with("close "))
    );
}

/// spec: P16, S26, G20, G9
#[test]
fn shutdown_with_a_failed_session_delete_retires_its_tunnel_and_reports_the_failure() {
    let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
    assert!(r.reconcile(toml::from_str("[host]\nfix_bindv6only=false\n[tunnels.t]\ntunnel_id=10\nremote_addr='192.0.2.2'\n[sessions.s]\ntunnel_name='t'\nsession_id=100\ninterface_name='owned'\n").unwrap()));
    r.k.fail_next("delete", Errno::EIO);
    assert!(!r.shutdown());
    assert!(r.tunnels.is_empty());
    assert!(r.sessions.is_empty());
    assert_eq!(r.k.open_sockets(), 0);
    r.k.tick();
    assert!(r.shutdown());
    assert!(r.k.session_index(10, 100).is_none());
}
