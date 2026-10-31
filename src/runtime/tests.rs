use super::*;
use crate::config::{Family, SessionConfig, TunnelConfig};
use crate::kernel::fake::FakeKernel;
use crate::reconciler::Lookup;
use std::io;
use std::net::IpAddr;
use std::task::{Context, Waker};

struct NoDns;
impl Resolve for NoDns {
    fn watch(&mut self, _: Lookup) -> io::Result<()> {
        Ok(())
    }
    fn unwatch(&mut self, _: u64) {}
    fn poll(&mut self) -> Vec<(u64, Vec<IpAddr>)> {
        vec![]
    }
}
fn engine() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn runtime() -> Runtime<FakeKernel> {
    Runtime::with_kernel(FakeKernel::new(42), Box::new(NoDns), vec![])
        .map_err(|(e, _)| e)
        .unwrap()
}
fn finish(r: &mut Runtime<FakeKernel>) {
    if !r.shutdown().unwrap() {
        r.reconciler.kernel_mut().tick();
    }
    assert!(r.shutdown().unwrap());
}
fn config() -> Config {
    let mut config = Config::new();
    config
        .insert_tunnel(
            "wan",
            TunnelConfig::builder(10)
                .ip_version(Family::V6)
                .build()
                .unwrap(),
        )
        .unwrap();
    config
        .insert_session(
            "lan",
            SessionConfig::builder("wan", 100, "l2tp0".parse().unwrap())
                .build()
                .unwrap(),
        )
        .unwrap();
    config
}

/// spec: R39, L10, E20, G14
#[test]
fn a_dropped_source_removal_stays_stale_until_resync_is_forwarded() {
    engine().block_on(async {
        let mut r = runtime();
        let device = r.reconciler.kernel_mut().add_link("wan", false);
        let source = "192.0.2.1".parse().unwrap();
        r.reconciler.kernel_mut().add_addr(device, source);
        let mut config = Config::new();
        config
            .insert_tunnel(
                "a",
                TunnelConfig::builder(10)
                    .ip_version(Family::V4)
                    .remote_addr(crate::config::RemoteAddr::Ip {
                        addr: "192.0.2.2".parse().unwrap(),
                        zone: None,
                    })
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert!(r.reconcile(config));
        assert!(r.reconciler.kernel().transmits(10));
        r.reconciler.kernel_mut().take_monitor();
        r.reconciler.kernel_mut().clear_ops();
        r.reconciler.kernel_mut().del_addr(device, source);
        let dropped = r.reconciler.kernel_mut().take_monitor();
        assert!(matches!(dropped.as_slice(), [Notice::AddrDel(_)]));
        assert!(
            r.reconciler.kernel().transmits(10),
            "an unforwarded event cannot update the record"
        );
        assert!(r.reconciler.kernel().ops().is_empty());
        r.handle_event(ControlEvent::Kernel {
            source: Source::Monitor,
            notice: Notice::Loss,
        })
        .unwrap();
        assert!(!r.reconciler.kernel().transmits(10));
        assert!(
            r.ready(),
            "connectivity does not control existence/readiness"
        );
        finish(&mut r);
    });
}

/// spec: R41, R38, G14, L11
#[test]
fn absent_log_sink_does_not_change_kernel_refusal_or_recovery() {
    assert_eq!(log::max_level(), log::LevelFilter::Off);
    engine().block_on(async {
        let mut r = runtime();
        r.reconciler
            .kernel_mut()
            .fail_next("socket", nix::errno::Errno::EPERM);
        assert!(!r.reconcile(config()));
        assert!(!r.ready());
        r.reconciler.kernel_mut().advance(Duration::from_secs(1));
        r.handle_event(ControlEvent::Tick).unwrap();
        assert!(r.ready());
        assert!(r.reconciler.kernel().session_index(10, 100).is_some());
        finish(&mut r);
    });
}

/// spec: R37, L10, L11, A21, G14
#[test]
fn event_wait_without_tokio_reports_an_error_and_channels_remain_usable() {
    let engine = engine();
    let mut r = engine.block_on(async { runtime() });
    assert!(tokio::runtime::Handle::try_current().is_err());
    let control = r.control();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        pin!(control.reload_wait()).poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        pin!(control.tunable_written(1, false)).poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        pin!(control.socket_forgotten(2, false)).poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    let Poll::Ready(event) = pin!(r.next_event()).poll(&mut cx) else {
        panic!("the queued reload must be available without a timer");
    };
    assert!(matches!(event, ControlEvent::Reload { .. }));
    r.handle_event(event).unwrap();
    for id in [1, 2] {
        let Poll::Ready(event) = pin!(r.next_event()).poll(&mut cx) else {
            panic!("the queued completion must be available without a timer");
        };
        assert!(
            matches!(event, ControlEvent::TunableWritten { id: 1, .. }) && id == 1
                || matches!(event, ControlEvent::SocketForgotten { id: 2, .. }) && id == 2
        );
        r.handle_event(event).unwrap();
    }
    // A distant synthetic deadline exercises timer construction without a wait.
    r.stopping = Some(r.reconciler.kernel().now() + Duration::from_secs(3600));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Poll::Ready(event) = pin!(r.next_event()).poll(&mut cx) else {
            panic!("a missing Tokio context must be reported immediately");
        };
        event
    }));
    assert!(outcome.is_ok(), "waiting outside Tokio must not panic");
    let event = outcome.unwrap();
    assert!(matches!(r.handle_event(event), Err(Error::Other(_))));
    r.stopping = None;
    finish(&mut r);
}

/// spec: L6, L9, L10, A6, A13
#[test]
fn queue_full_waiter_and_shutdown_precedence() {
    engine().block_on(async {
        let mut r = runtime();
        let control = r.control();
        for _ in 0..QUEUE_CAPACITY {
            control.reload().unwrap();
        }
        assert!(control.reload().is_err());
        assert!(control.restart().is_err());
        let mut waiting = pin!(control.reload_wait());
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let event = r.next_event().await;
        assert!(matches!(event, ControlEvent::Reload { generation: 1 }));
        assert!(
            control.restart().is_err(),
            "dequeue alone must not free a pending request's admission slot"
        );
        r.handle_event(event).unwrap();
        waiting.await.unwrap();
        control.shutdown();
        let event = r.next_event().await;
        assert!(matches!(event, ControlEvent::Shutdown));
        r.handle_event(event).unwrap();
        finish(&mut r);
    });
}

/// spec: L6, L9, L13, A6, A13
#[test]
fn dropping_the_owner_releases_a_waiter_and_rejects_later_completions() {
    let engine = engine();
    let control = engine.block_on(async {
        let r = runtime();
        let control = r.control();
        for _ in 0..QUEUE_CAPACITY {
            control.send(ControlEvent::Tick).await.unwrap();
        }
        assert!(control.reload().is_err());
        assert!(control.restart().is_err());
        {
            let mut waiting = pin!(control.reload_wait());
            assert!(
                waiting
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            drop(r);
            assert!(waiting.await.is_err());
        }
        control
    });
    assert!(control.reload().is_err());
    assert!(control.restart().is_err());
    assert!(control.tunable_written_blocking(1, true).is_err());
    assert!(control.socket_forgotten_blocking(1, true).is_err());
    engine.block_on(async {
        assert!(control.reload_wait().await.is_err());
        assert!(control.tunable_written(1, true).await.is_err());
        assert!(control.socket_forgotten(1, true).await.is_err());
    });
    control.shutdown();
    control.shutdown();
    assert_eq!(control.config(), Config::new());
}

/// spec: L9, L10, A6
#[test]
fn subscription_loss_survives_a_full_queue_and_a_second_loss() {
    engine().block_on(async {
        let mut r = runtime();
        for _ in 0..QUEUE_CAPACITY {
            r.control().reload().unwrap();
        }
        r.reconciler.kernel_mut().add_link("eth0", false);
        while !r.control.shared.loss[0].load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        let event = r.next_event().await;
        assert!(matches!(
            event,
            ControlEvent::Kernel {
                source: Source::Monitor,
                notice: Notice::Loss
            }
        ));
        // Another overflow after consuming the flag must survive this resync.
        r.reconciler.kernel_mut().add_link("eth1", false);
        while !r.control.shared.loss[0].load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        r.handle_event(event).unwrap();
        assert!(matches!(
            r.next_event().await,
            ControlEvent::Kernel {
                source: Source::Monitor,
                notice: Notice::Loss
            }
        ));
        finish(&mut r);
    });
}

/// spec: L9, L10, A7, A14
#[test]
fn lifetime_proofs_do_not_use_the_full_event_queue() {
    engine().block_on(async {
        let mut r = runtime();
        assert!(r.reconcile(config()));
        for _ in 0..QUEUE_CAPACITY {
            r.control().reload().unwrap();
        }
        let mut config = config();
        config
            .insert_session(
                "lan",
                SessionConfig::builder("wan", 100, "renamed".parse().unwrap())
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert!(r.reconcile(config));
        assert!(
            r.reconciler
                .kernel()
                .ops()
                .iter()
                .any(|op| op.contains("renamed"))
        );
        finish(&mut r);
    });
}

/// spec: L12, L9, L10
#[test]
fn tunable_handshake_is_observed_forwarded_and_answered_without_host_io() {
    engine().block_on(async {
        let mut r = runtime();
        r.reconciler.kernel_mut().bindv6only = true;
        assert!(!r.reconcile(config()));
        let event = r.next_event().await;
        let id = match &event {
            ControlEvent::WriteTunable {
                id,
                name,
                value,
                deadline,
            } => {
                assert_eq!((*name, *value), ("net.ipv6.bindv6only", "0"));
                assert_eq!(
                    *deadline - r.reconciler.kernel().now(),
                    Duration::from_secs(5)
                );
                *id
            }
            _ => panic!("expected tunable request"),
        };
        r.handle_event(event).unwrap();
        assert!(r.reconciler.kernel().tunnel_socket(10).is_none());
        r.reconciler.kernel_mut().bindv6only = false;
        r.control().tunable_written(id, true).await.unwrap();
        let event = r.next_event().await;
        r.handle_event(event).unwrap();
        assert!(r.ready());
        finish(&mut r);
    });
}

/// spec: L12
#[test]
fn tunable_timeout_ignores_late_success_and_shutdown_cancels_pending() {
    engine().block_on(async {
        let mut r = runtime();
        r.reconciler.kernel_mut().bindv6only = true;
        r.reconcile(config());
        let event = r.next_event().await;
        let ControlEvent::WriteTunable { id, .. } = event else {
            panic!("expected request")
        };
        r.handle_event(event).unwrap();
        for _ in 0..QUEUE_CAPACITY {
            r.control().reload().unwrap();
        }
        r.reconciler.kernel_mut().advance(Duration::from_secs(5));
        let event = r.next_event().await;
        assert!(matches!(event, ControlEvent::Tick));
        r.handle_event(event).unwrap();
        let socket = r.reconciler.kernel().tunnel_socket(10).unwrap();
        r.handle_event(ControlEvent::TunableWritten { id, success: true })
            .unwrap();
        assert_eq!(r.reconciler.kernel().tunnel_socket(10), Some(socket));
        finish(&mut r);

        let mut r = runtime();
        r.reconciler.kernel_mut().bindv6only = true;
        r.reconcile(config());
        r.handle_event(ControlEvent::Shutdown).unwrap();
        finish(&mut r);
        assert!(
            !r.outgoing
                .iter()
                .any(|event| matches!(event, ControlEvent::WriteTunable { .. }))
        );
        assert!(r.reconciler.kernel().tunnel_socket(10).is_none());
    });
}

/// spec: L13, L5
#[test]
fn adopted_names_are_verified_or_retired_and_store_wait_is_bounded() {
    engine().block_on(async {
        let mut kernel = FakeKernel::new(42);
        let socket = kernel.operator_replace_tunnel(10, 10);
        let adopted = vec![AdoptedSocket::new("t10", kernel.clone_fd(socket).unwrap())];
        kernel.close(socket);
        let mut r = Runtime::with_kernel(kernel, Box::new(NoDns), adopted)
            .map_err(|(e, _)| e)
            .unwrap();
        r.set_store_capacity(1);
        r.reconcile(config());
        assert!(r.ready());
        assert!(
            r.restart_sockets()
                .unwrap()
                .iter()
                .any(|s| s.tunnel_id() == Some(10))
        );
        assert!(!r.shutdown().unwrap());
        let event = r.next_event().await;
        let id = match &event {
            ControlEvent::ForgetSocket { name, id, .. } => {
                assert_eq!(name, "t10");
                *id
            }
            _ => panic!("expected withdrawal"),
        };
        r.handle_event(event).unwrap();
        r.control().socket_forgotten(id, true).await.unwrap();
        let event = r.next_event().await;
        r.handle_event(event).unwrap();
        r.reconciler.kernel_mut().tick();
        finish(&mut r);

        let (fd, _) = std::os::unix::net::UnixStream::pair().unwrap();
        let adopted = vec![AdoptedSocket::new("bad name", fd.into())];
        let mut r = Runtime::with_kernel(FakeKernel::new(42), Box::new(NoDns), adopted)
            .map_err(|(e, _)| e)
            .unwrap();
        r.set_store_capacity(1);
        r.reconcile(Config::new());
        let event = r.next_event().await;
        assert!(matches!(&event, ControlEvent::ForgetSocket { name, .. } if name == "bad name"));
        r.handle_event(event).unwrap();
        assert!(!r.shutdown().unwrap());
        r.reconciler.kernel_mut().advance(Duration::from_secs(4));
        assert!(r.shutdown().is_err());

        // A valid name still needs descriptor verification, not just parsing.
        let (fd, _) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut r = Runtime::with_kernel(
            FakeKernel::new(42),
            Box::new(NoDns),
            vec![AdoptedSocket::new("t10", fd.into())],
        )
        .map_err(|(e, _)| e)
        .unwrap();
        r.set_store_capacity(1);
        r.reconcile(config());
        assert!(!r.ready());
        let event = r.next_event().await;
        assert!(matches!(&event, ControlEvent::ForgetSocket { name, .. } if name == "t10"));
        r.handle_event(event).unwrap();
        assert!(r.reconciler.kernel().tunnel_socket(10).is_none());
        assert!(!r.shutdown().unwrap());
        r.reconciler.kernel_mut().advance(Duration::from_secs(1));
        // The old reconcile retry is due, but shutdown stopped policy timers.
        let mut waiting = pin!(r.next_event());
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    });
}

/// spec: L13
#[test]
fn store_submission_and_withdrawal_acknowledgements_keep_the_incarnation() {
    engine().block_on(async {
        let mut r = runtime();
        r.set_store_capacity(1);
        r.reconcile(config());
        let event = r.next_event().await;
        assert!(
            matches!(&event, ControlEvent::StoreSocket { tunnel_id: 10, name, .. } if name == "t10")
        );
        r.handle_event(event).unwrap();
        r.reconcile(Config::new());
        let event = r.next_event().await;
        let ControlEvent::ForgetSocket { id, .. } = &event else {
            panic!("expected withdrawal")
        };
        let id = *id;
        r.handle_event(event).unwrap();
        r.handle_event(ControlEvent::SocketForgotten {
            id: id + 1,
            processed: true,
        })
        .unwrap();
        assert!(r.reconciler.kernel().tunnel_socket(10).is_some());
        r.handle_event(ControlEvent::SocketForgotten {
            id,
            processed: true,
        })
        .unwrap();
        r.reconciler.kernel_mut().tick();
        finish(&mut r);
    });
}

/// spec: L1, L2, L3, L11, A1, A3, A4
#[test]
fn library_boundary_and_extensible_api() {
    // These source assertions supplement execution, not kernel conformance.
    assert!(include_str!("../lib.rs").contains("#![deny(unsafe_code)]"));
    for module in [
        "config",
        "kernel",
        "reconciler",
        "runtime",
        "service",
        "blocking",
    ] {
        assert!(include_str!("../lib.rs").contains(&format!("pub mod {module};")));
    }
    let binary = include_str!("../bin/rs-l2tpd/main.rs");
    assert!(binary.contains("rs_l2tpd::blocking::Service"));
    for forbidden in ["kernel::", "Reconciler", "SessionRecord", "TunnelRecord"] {
        assert!(!binary.contains(forbidden), "{forbidden}");
    }
    for source in [
        include_str!("../runtime.rs"),
        include_str!("../service.rs"),
        include_str!("../blocking.rs"),
    ] {
        for forbidden in ["std::fs", "std::env", "println!", "eprintln!", "unsafe {"] {
            assert!(!source.contains(forbidden), "{forbidden}");
        }
    }
    assert!(include_str!("../runtime.rs").contains("#[non_exhaustive]\npub enum ControlEvent"));
    let Error::Io(error) = Error::from(io::Error::from_raw_os_error(13)) else {
        panic!("errno lost")
    };
    assert_eq!(error.raw_os_error(), Some(13));
}

/// spec: L13, T8, G20
#[test]
fn shutdown_keeps_withdrawal_and_kernel_deletion_windows_separate() {
    engine().block_on(async {
        let mut r = runtime();
        r.set_store_capacity(1);
        r.reconciler.kernel_mut().tunnel_delete_delay = Duration::from_secs(2);
        r.reconcile(config());
        let ControlEvent::StoreSocket { fd, .. } = r.next_event().await else {
            panic!("expected store")
        };
        assert!(!r.shutdown().unwrap());
        let ControlEvent::ForgetSocket { id, .. } = r.next_event().await else {
            panic!("expected withdrawal")
        };
        r.reconciler
            .kernel_mut()
            .advance(Duration::from_millis(1900));
        drop(fd);
        r.handle_event(ControlEvent::SocketForgotten {
            id,
            processed: true,
        })
        .unwrap();
        r.reconciler
            .kernel_mut()
            .advance(Duration::from_millis(100));
        assert!(
            !r.shutdown().unwrap(),
            "kernel deletion still has its own window"
        );
        r.reconciler
            .kernel_mut()
            .advance(Duration::from_millis(1900));
        r.reconciler.kernel_mut().tick();
        finish(&mut r);
    });
}

/// spec: A6, L9, L10
#[test]
fn l2tp_queue_loss_uses_its_own_resync_flag() {
    engine().block_on(async {
        let mut r = runtime();
        r.reconcile(config());
        for _ in 0..QUEUE_CAPACITY {
            r.control().reload().unwrap();
        }
        r.reconciler.kernel_mut().set_l2tp_capacity(0);
        r.reconciler.kernel_mut().operator_delete_session(10, 100);
        while !r.control.shared.loss[1].load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        // Monitor loss can be pending as well; both sources must survive.
        let mut found = false;
        for _ in 0..2 {
            let event = r.next_event().await;
            found |= matches!(
                event,
                ControlEvent::Kernel {
                    source: Source::L2tp,
                    notice: Notice::Loss
                }
            );
            r.handle_event(event).unwrap();
            if found {
                break;
            }
        }
        assert!(found);
        assert!(r.reconciler.kernel().session_index(10, 100).is_some());
        finish(&mut r);
    });
}

/// spec: L5, L9, L11, P16, P17, T8
#[test]
fn cleanup_verifies_kernel_absence_and_reports_a_remaining_reference() {
    engine().block_on(async {
        let mut r = runtime();
        let mut config = config();
        config
            .insert_tunnel(
                "other",
                TunnelConfig::builder(20)
                    .ip_version(Family::V6)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        r.reconcile(config);
        let external = r
            .reconciler
            .kernel()
            .clone_fd(r.reconciler.kernel().tunnel_socket(10).unwrap())
            .unwrap();
        assert!(!r.shutdown().unwrap());
        r.reconciler.kernel_mut().tick();
        assert!(r.reconciler.kernel().tunnel_socket(20).is_none());
        assert!(r.reconciler.kernel().session_index(10, 100).is_none());
        r.reconciler.kernel_mut().advance(Duration::from_secs(2));
        assert!(r.shutdown().is_err());
        drop(external);
    });
}

/// spec: L9
#[test]
fn dropping_runtime_stops_both_subscription_tasks_and_closes_the_queue() {
    engine().block_on(async {
        let r = runtime();
        let tasks: Vec<_> = r.tasks.iter().map(|task| task.abort_handle()).collect();
        let control = r.control();
        drop(r);
        while tasks.iter().any(|task| !task.is_finished()) {
            tokio::task::yield_now().await;
        }
        assert!(control.reload().is_err());
        assert!(control.reload_wait().await.is_err());
    });
}

/// spec: L8, L11, L12, L13
#[test]
fn blocking_completions_work_inside_spawn_blocking() {
    engine().block_on(async {
        let mut runtime = runtime();
        let control = runtime.control();
        let sender = tokio::task::spawn_blocking(move || {
            control.tunable_written_blocking(1, true).unwrap();
            control.socket_forgotten_blocking(1, true).unwrap();
        });
        let event = runtime.next_event().await;
        assert!(matches!(event, ControlEvent::TunableWritten { .. }));
        runtime.handle_event(event).unwrap();
        let event = runtime.next_event().await;
        assert!(matches!(event, ControlEvent::SocketForgotten { .. }));
        runtime.handle_event(event).unwrap();
        sender.await.unwrap();
    });
}

/// spec: L6, L11, A6
#[test]
fn cancelling_unaccepted_reload_wait_does_not_inflate_admission_capacity() {
    engine().block_on(async {
        let mut runtime = runtime();
        let control = runtime.control();
        for _ in 0..QUEUE_CAPACITY {
            assert!(control.tx.try_send(ControlEvent::Tick).is_ok());
        }
        {
            let mut waiting = pin!(control.reload_wait());
            assert!(
                waiting
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            // A program-driven event did not acquire an admission slot.
            runtime.handle_event(ControlEvent::Restart).unwrap();
        }
        for _ in 0..QUEUE_CAPACITY {
            let event = runtime.next_event().await;
            runtime.handle_event(event).unwrap();
        }
        for _ in 0..QUEUE_CAPACITY {
            control.reload().unwrap();
        }
        let event = runtime.next_event().await;
        assert!(
            control.reload().is_err(),
            "a dequeue must not leave an extra admission slot"
        );
        runtime.handle_event(event).unwrap();
        control.reload().unwrap();
    });
}
