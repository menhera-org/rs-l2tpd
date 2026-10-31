//! Regressions from the phase 5 completion review.
use super::{TUNNEL, config, deliver, ops, reconciler, run_for};
use nix::errno::Errno;
use rs_l2tpd::kernel::{AddrInfo, Family, Kernel, Notice, SessionCreate};
use rs_l2tpd::reconciler::Source;

fn session(extra: &str) -> String {
    format!(
        "{TUNNEL}\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'\n{extra}"
    )
}

/// spec: S4, S7, S8, S27, G22
#[test]
fn direct_creation_and_recreation_preserve_publication_rules() {
    for (extra, source, retry) in ["", "interface_hwaddr='02:00:5e:00:53:01'"]
        .into_iter()
        .flat_map(|extra| {
            [
                (Source::Monitor, false),
                (Source::L2tp, false),
                (Source::L2tp, true),
            ]
            .map(|(source, retry)| (extra, source, retry))
        })
    {
        let (mut r, _) = reconciler();
        assert!(r.reconcile(config(&session(extra))));
        let first = r.kernel().session_index(10, 100).unwrap();
        let created = r.kernel_mut().session(10, 100).unwrap().unwrap();
        assert_eq!(
            created.ifname().unwrap().to_string_lossy() == "l2tp0",
            extra.is_empty()
        );
        deliver(&mut r);
        ops(&mut r);
        r.kernel_mut().operator_delete_session(10, 100);
        r.kernel_mut().tick();
        let monitor = r.kernel_mut().take_monitor();
        let l2tp = r.kernel_mut().take_l2tp();
        if retry {
            r.kernel_mut().fail_next("session", Errno::EIO);
        }
        for notice in match source {
            Source::Monitor => monitor,
            Source::L2tp => l2tp,
            _ => unreachable!(),
        } {
            r.handle(source, notice);
        }
        if retry {
            assert!(r.kernel().session_index(10, 100).is_none());
            r.tick();
        }
        let next = r.kernel().session_index(10, 100).unwrap();
        assert_ne!(first, next);
        let recreated = r.kernel_mut().session(10, 100).unwrap().unwrap();
        assert_eq!(
            recreated.ifname().unwrap().to_string_lossy() == "l2tp0",
            extra.is_empty(),
            "creation name after {source:?} removal"
        );
        assert_eq!(
            r.kernel().link(next).unwrap().name().to_string_lossy(),
            "l2tp0"
        );
        if extra.is_empty() {
            assert!(!ops(&mut r).iter().any(|op| op.starts_with("rename")));
        } else {
            assert_eq!(
                r.kernel().hwaddr(next).unwrap().to_string(),
                "02:00:5e:00:53:01"
            );
            let trace = ops(&mut r);
            assert!(
                trace
                    .iter()
                    .position(|op| op.starts_with("hwaddr"))
                    .unwrap()
                    < trace
                        .iter()
                        .position(|op| op.starts_with("rename"))
                        .unwrap()
            );
        }
        assert!(r.ready());
    }
}

/// spec: T21, T27, E3, G17, A12
#[test]
fn a_failed_scoped_connect_can_change_its_kernel_binding() {
    let (mut r, _) = reconciler();
    let old = r.kernel_mut().add_link("zone", false);
    let peer = "fe80::1".parse().unwrap();
    r.kernel_mut().refuse(peer, Some(Errno::ENETUNREACH));
    let text = "[tunnels.a]\ntunnel_id=10\nremote_addr='fe80::1%zone'";
    assert!(r.reconcile(config(text)));
    let socket = r.kernel().tunnel_socket(10).unwrap();
    assert_eq!(
        r.kernel().binding(socket),
        Some(old),
        "failed connect has side effects"
    );
    r.kernel_mut().remove_link(old);
    let next = r.kernel_mut().add_link("zone", false);
    r.kernel_mut().add_addr(next, "fe80::2".parse().unwrap());
    r.kernel_mut().refuse(peer, None);
    deliver(&mut r);
    run_for(&mut r, 1);
    assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
    assert_eq!(r.kernel().binding(socket), Some(next));
    assert!(r.kernel().transmits(10));
}

/// spec: V6, V7, G19, T24
#[test]
fn recreation_keeps_the_watch_and_answer_without_another_dns_response() {
    let (mut r, answers) = reconciler();
    let eth = r.kernel_mut().add_link("eth", false);
    r.kernel_mut().add_addr(eth, "192.0.2.1".parse().unwrap());
    let text = TUNNEL
        .replace("192.0.2.2", "peer.example")
        .replace("remote_addr", "ip_version='V4'\nremote_addr");
    r.reconcile(config(&text));
    answers.answer("peer.example", &["192.0.2.2"]);
    run_for(&mut r, 1);
    let watch = answers.watching()[0].id();
    let old = r.kernel().tunnel_socket(10).unwrap();
    r.reconcile(config(
        &text.replace("peer_tunnel_id = 20", "peer_tunnel_id = 21"),
    ));
    run_for(&mut r, 2);
    let next = r.kernel().tunnel_socket(10).unwrap();
    assert_ne!(old, next);
    assert_eq!(answers.watching()[0].id(), watch);
    assert!(r.kernel().transmits(10), "no further answer was delivered");
}

/// spec: S21, T25, G13, M14
#[test]
fn a_moved_session_recreation_reaches_the_conflict_budget_then_recovers() {
    let (mut r, _) = reconciler();
    r.reconcile(config(&session("")));
    let moved = r.kernel().session_index(10, 100).unwrap();
    r.kernel_mut().remove_link(moved);
    deliver(&mut r);
    r.reconcile(config(&session("peer_session_id=101")));
    run_for(&mut r, 10);
    assert!(
        r.ready(),
        "conflict is eventually left out, rather than silently gated"
    );
    assert_eq!(r.kernel().session_index(10, 100), Some(moved));
    r.kernel_mut().operator_delete_session(10, 100);
    run_for(&mut r, 30);
    assert_ne!(r.kernel().session_index(10, 100), Some(moved));
    assert!(r.ready());
}

/// spec: C14, M6, S11, S10, M19
#[test]
fn a_survivor_takes_a_removed_sessions_name_without_becoming_an_override() {
    for asynchronous in [false, true] {
        let (mut r, _) = reconciler();
        r.kernel_mut().set_async_session_delete(asynchronous);
        let first = session("interface_hwaddr='02:00:5e:00:53:01'")
            + "\n[sessions.old]\ntunnel_name='a'\nsession_id=101\ninterface_name='l2tp1'";
        r.reconcile(config(&first));
        deliver(&mut r); // Includes the obsolete creation-time name.
        let survivor = r.kernel().session_index(10, 100).unwrap();
        let next = session("interface_hwaddr='02:00:5e:00:53:01'").replace("'l2tp0'", "'l2tp1'");
        let complete = r.reconcile(config(&next));
        assert_eq!(complete, !asynchronous);
        if asynchronous {
            assert!(r.kernel().session_index(10, 101).is_some());
            assert_eq!(
                r.kernel().link(survivor).unwrap().name().to_string_lossy(),
                "l2tp0"
            );
            run_for(&mut r, 1);
            deliver(&mut r);
            assert!(r.reconcile(config(&next)));
        }
        assert_eq!(r.kernel().session_index(10, 100), Some(survivor));
        assert_eq!(r.kernel().session_index(10, 101), None);
        assert_eq!(
            r.kernel().link(survivor).unwrap().name().to_string_lossy(),
            "l2tp1"
        );
        r.kernel_mut().rename_link(survivor, "manager");
        deliver(&mut r);
        r.reconcile(config(&next));
        assert_eq!(
            r.kernel().link(survivor).unwrap().name().to_string_lossy(),
            "manager"
        );
    }
}

/// spec: G1, G6, S4, M4, E12
#[test]
fn random_and_creation_failures_are_local_and_retryable() {
    for failure in ["random", "create"] {
        let (mut r, _) = reconciler();
        let text = session("interface_hwaddr='02:00:5e:00:53:01'")
            + "\n[sessions.zgood]\ntunnel_name='a'\nsession_id=101\ninterface_name='good'";
        r.kernel_mut().fail_next(failure, Errno::EPERM);
        assert!(!r.reconcile(config(&text)));
        assert!(r.kernel().session_index(10, 100).is_none());
        let good = r.kernel().session_index(10, 101).unwrap();
        run_for(&mut r, 1);
        assert!(r.ready());
        assert_eq!(r.kernel().session_index(10, 101), Some(good));
        assert!(r.kernel().session_index(10, 100).is_some());
    }
}

/// spec: M4, G6, S28, P14, E12
#[test]
fn an_unmatched_adopted_session_does_not_reject_its_tunnel_or_sibling() {
    let (mut r, _) = reconciler();
    let socket = r.kernel_mut().create_socket(Family::V6, 10, 20).unwrap();
    r.kernel_mut().register_tunnel(socket, 10, 20).unwrap();
    for (sid, name) in [(100, "matched"), (101, "unmatched")] {
        r.kernel_mut()
            .create_session(&SessionCreate::new(
                10,
                sid,
                sid,
                None,
                None,
                rs_l2tpd::config::L2tpIfName::new(name.as_bytes()).unwrap(),
            ))
            .unwrap();
    }
    let matched = r.kernel().session_index(10, 100).unwrap();
    let fd = r.kernel().clone_fd(socket).unwrap();
    r.kernel_mut().close(socket);
    r.inherit("t10".into(), fd);
    r.kernel_mut().fail_next("delete", Errno::EPERM);
    assert!(!r.reconcile(config(&session(""))));
    assert_eq!(r.kernel().open_sockets(), 1);
    assert_eq!(r.kernel().session_index(10, 100), Some(matched));
    assert!(r.kernel().session_index(10, 101).is_some());
    run_for(&mut r, 2);
    assert!(r.ready());
    assert_eq!(r.kernel().session_index(10, 100), Some(matched));
    assert!(r.kernel().session_index(10, 101).is_none());
}

/// spec: E2, E6, T19, G23
#[test]
fn an_ipv4_label_notice_does_not_reconnect_a_second_time() {
    let (mut r, _) = reconciler();
    let wan = r.kernel_mut().add_link("wan", false);
    let address = "192.0.2.1".parse().unwrap();
    r.kernel_mut().add_addr(wan, address);
    r.reconcile(config(&(TUNNEL.to_owned() + "bind_interface='wan'")));
    deliver(&mut r);
    ops(&mut r);
    r.handle(
        Source::Monitor,
        Notice::AddrNew(AddrInfo::new(wan, address)),
    );
    assert!(ops(&mut r).is_empty(), "label-only address notification");
    r.kernel_mut().rename_link(wan, "away");
    deliver(&mut r);
    assert_eq!(
        ops(&mut r)
            .iter()
            .filter(|op| op.starts_with("disconnect"))
            .count(),
        1
    );
    r.handle(
        Source::Monitor,
        Notice::AddrNew(AddrInfo::new(wan, address)),
    );
    assert!(ops(&mut r).is_empty());
    r.kernel_mut().rename_link(wan, "wan");
    deliver(&mut r);
    let after = ops(&mut r);
    assert_eq!(
        after.iter().filter(|op| op.starts_with("connect ")).count(),
        1,
        "{after:?}"
    );
    r.handle(
        Source::Monitor,
        Notice::AddrNew(AddrInfo::new(wan, address)),
    );
    assert!(ops(&mut r).is_empty());
}

/// spec: G13, O2, O3, O4, E20, T21, T25, R9
#[test]
fn completion_report_counts() {
    // Forking here can temporarily inherit other tests' fake socket references.
    struct Capture {
        owner: std::thread::ThreadId,
        messages: std::sync::Mutex<Vec<(log::Level, String)>>,
    }
    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            std::thread::current().id() == self.owner
        }
        fn log(&self, r: &log::Record<'_>) {
            if self.enabled(r.metadata()) {
                self.messages
                    .lock()
                    .unwrap()
                    .push((r.level(), r.args().to_string()));
            }
        }
        fn flush(&self) {}
    }
    let capture = Box::leak(Box::new(Capture {
        owner: std::thread::current().id(),
        messages: Default::default(),
    }));
    log::set_logger(capture).unwrap();
    log::set_max_level(log::LevelFilter::Debug);
    let count = |level, text: &str| {
        capture
            .messages
            .lock()
            .unwrap()
            .iter()
            .filter(|(l, message)| *l == level && message.contains(text))
            .count()
    };
    std::thread::spawn(|| log::error!("cannot be created: another test"))
        .join()
        .unwrap();
    assert_eq!(count(log::Level::Error, "cannot be created:"), 0);
    for (error, level) in [
        (Errno::EPERM, log::Level::Error),
        (Errno::EACCES, log::Level::Error),
        (Errno::EPROTONOSUPPORT, log::Level::Error),
        (Errno::EOPNOTSUPP, log::Level::Error),
        (Errno::EAGAIN, log::Level::Warn),
        (Errno::ENOMEM, log::Level::Warn),
        (Errno::ENOBUFS, log::Level::Warn),
        (Errno::EMFILE, log::Level::Warn),
    ] {
        for creating_session in [false, true] {
            capture.messages.lock().unwrap().clear();
            let (mut r, _) = reconciler();
            if creating_session {
                r.reconcile(config(TUNNEL));
            }
            for _ in 0..3 {
                r.kernel_mut().fail_next(
                    if creating_session {
                        "create"
                    } else {
                        "register"
                    },
                    error,
                );
            }
            r.reconcile(config(&if creating_session {
                session("")
            } else {
                TUNNEL.to_owned()
            }));
            run_for(&mut r, 2);
            assert!(!r.ready(), "session must still be missing: {error:?}");
            assert_eq!(count(level, "cannot be created:"), 1, "{error:?}");
            let label = if creating_session {
                "session s (tunnel_id=10, session_id=100):"
            } else {
                "tunnel a (tunnel_id=10):"
            };
            assert!(
                capture
                    .messages
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(_, message)| message.contains("cannot be created:"))
                    .all(|(_, message)| message.starts_with(label)),
                "{label}"
            );
            let other = if level == log::Level::Error {
                log::Level::Warn
            } else {
                log::Level::Error
            };
            assert_eq!(count(other, "cannot be created:"), 0, "{error:?}");
            run_for(&mut r, 1);
            assert!(r.ready(), "retry must recover: {error:?}");
            assert_eq!(count(level, "cannot be created:"), 1, "{error:?}");
        }
    }
    capture.messages.lock().unwrap().clear();
    let (mut mixed, _) = reconciler();
    mixed.reconcile(config(TUNNEL));
    for error in [
        Errno::EAGAIN,
        Errno::EPROTONOSUPPORT,
        Errno::EAGAIN,
        Errno::EPROTONOSUPPORT,
    ] {
        mixed.kernel_mut().fail_next("create", error);
    }
    mixed.reconcile(config(&session("")));
    run_for(&mut mixed, 3);
    assert!(!mixed.ready());
    assert_eq!(count(log::Level::Warn, "cannot be created:"), 1);
    assert_eq!(
        count(log::Level::Error, "cannot be created:"),
        1,
        "a newly observed host defect must be promoted once"
    );
    run_for(&mut mixed, 1);
    assert!(mixed.ready());
    capture.messages.lock().unwrap().clear();
    let (mut resolver_case, answers) = reconciler();
    answers.refuse(true);
    let named = TUNNEL.replace("\"192.0.2.2\"", "\"controlled.example\"\nip_version='V6'");
    resolver_case.reconcile(config(&named));
    assert!(
        resolver_case.ready(),
        "resolver defects do not withhold readiness"
    );
    run_for(&mut resolver_case, 30);
    assert_eq!(count(log::Level::Error, "its resolver waits:"), 1);
    assert_eq!(count(log::Level::Warn, "its resolver waits:"), 0);
    answers.refuse(false);
    run_for(&mut resolver_case, 30);
    assert_eq!(count(log::Level::Info, "its resolver started"), 1);
    capture.messages.lock().unwrap().clear();
    let (mut r, _) = reconciler();
    r.reconcile(config(TUNNEL));
    for _ in 0..6 {
        r.kernel_mut().fail_next("dump", Errno::EIO);
    }
    r.handle(Source::Monitor, Notice::Loss);
    run_for(&mut r, 5);
    assert_eq!(count(log::Level::Warn, "lost notifications"), 1);
    run_for(&mut r, 1);
    assert_eq!(count(log::Level::Info, "resynchronised"), 1);
    for _ in 0..6 {
        r.kernel_mut().fail_next("disconnect", Errno::EPERM);
    }
    let changed = TUNNEL.replace("192.0.2.2", "192.0.2.3");
    r.reconcile(config(&changed));
    run_for(&mut r, 5);
    assert_eq!(count(log::Level::Error, "disconnect failed"), 1);
    run_for(&mut r, 1);
    assert_eq!(count(log::Level::Info, "disconnected"), 1);

    let (mut r, _) = reconciler();
    r.reconcile(config(&session("")));
    let moved = r.kernel().session_index(10, 100).unwrap();
    r.kernel_mut().remove_link(moved);
    deliver(&mut r);
    r.reconcile(config(&session("peer_session_id=101")));
    run_for(&mut r, 10);
    assert_eq!(count(log::Level::Warn, "left out"), 1);
    r.kernel_mut().operator_delete_session(10, 100);
    run_for(&mut r, 30);
    assert_eq!(count(log::Level::Info, "identifiers free, created"), 1);
}

/// spec: P14, L13
#[test]
fn a_definitively_wrong_inherited_socket_is_retired_once() {
    let (mut r, _) = reconciler();
    let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    r.inherit("t10".into(), stream.into());
    r.kernel_mut().fail_next("adopt", Errno::ESOCKTNOSUPPORT);
    assert!(r.reconcile(rs_l2tpd::config::Config::new()));
    assert_eq!(r.next_deadline(), None);
}
