//! Service contract exercised on the same fake as the kernel conformance suite.
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rs_l2tpd::config::{Config, Family, HwAddr, L2tpIfName, SessionConfig, TunnelConfig};
use rs_l2tpd::kernel::fake::FakeKernel;
use rs_l2tpd::kernel::*;
use rs_l2tpd::reconciler::{Lookup, Resolve};
use rs_l2tpd::runtime::{AdoptedSocket, Runtime};
use rs_l2tpd::{Error, blocking, service};

#[derive(Clone)]
struct Host(
    Arc<Mutex<FakeKernel>>,
    Arc<Mutex<Option<Gate>>>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<Mutex<Option<mpsc::SyncSender<()>>>>,
    Arc<AtomicBool>,
    Arc<Mutex<Option<Gate>>>,
);
struct Gate {
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}
struct Counted {
    feed: Box<dyn Subscription>,
    count: Arc<AtomicUsize>,
}
impl Subscription for Counted {
    fn poll_notice(&mut self, cx: &mut Context<'_>) -> Poll<Notice> {
        let notice = self.feed.poll_notice(cx);
        if notice.is_ready() {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
        notice
    }
}
impl Host {
    fn new() -> Self {
        Self(
            Arc::new(Mutex::new(FakeKernel::new(42))),
            Arc::new(Mutex::new(None)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(Mutex::new(None)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(None)),
        )
    }
    fn with<T>(&self, f: impl FnOnce(&mut FakeKernel) -> T) -> T {
        f(&mut self.0.lock().unwrap())
    }
    fn callback_context(&self) {
        if self.6.load(Ordering::SeqCst) {
            engine().block_on(async {});
        }
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        if let Some(finished) = self.5.lock().unwrap().take() {
            let _ = finished.send(());
        }
    }
}
macro_rules! forward {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        $(fn $name(&mut self, $($arg: $ty),*) -> $ret {
            self.callback_context();
            self.0.lock().unwrap().$name($($arg),*)
        })*
    };
}
impl Kernel for Host {
    fn rename(&mut self, index: u32, name: &L2tpIfName) -> io::Result<()> {
        self.callback_context();
        let gate = self.1.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.entered.send(()).unwrap();
            gate.release.recv().unwrap();
        }
        self.4.fetch_add(1, Ordering::SeqCst);
        self.0.lock().unwrap().rename(index, name)
    }
    fn create_session(&mut self, create: &SessionCreate) -> io::Result<Registration> {
        self.callback_context();
        let gate = self.7.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.entered.send(()).unwrap();
            gate.release.recv().unwrap();
        }
        self.0.lock().unwrap().create_session(create)
    }
    fn tunnel(&mut self, id: u32) -> io::Result<Option<TunnelInfo>> {
        self.callback_context();
        let mut kernel = self.0.lock().unwrap();
        kernel.tick();
        kernel.tunnel(id)
    }
    fn monitor(&mut self) -> io::Result<Box<dyn Subscription>> {
        self.callback_context();
        Ok(Box::new(Counted {
            feed: self.0.lock().unwrap().monitor()?,
            count: self.2.clone(),
        }))
    }
    fn dump_links(&mut self) -> io::Result<Vec<LinkInfo>> {
        self.callback_context();
        self.3.fetch_add(1, Ordering::SeqCst);
        let gate = self.1.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.entered.send(()).unwrap();
            gate.release.recv().unwrap();
        }
        self.0.lock().unwrap().dump_links()
    }
    fn now(&self) -> Instant {
        self.callback_context();
        self.0.lock().unwrap().now()
    }
    fn only_v6(&self, socket: SocketId) -> io::Result<bool> {
        self.callback_context();
        self.0.lock().unwrap().only_v6(socket)
    }
    fn clone_fd(&self, socket: SocketId) -> io::Result<OwnedFd> {
        self.callback_context();
        self.0.lock().unwrap().clone_fd(socket)
    }
    forward! {
        random() -> io::Result<[u8; 3]>;
        link_by_index(index: u32) -> io::Result<Option<LinkInfo>>;
        create_socket(family: Family, tunnel_id: u32, peer_tunnel_id: u32) -> io::Result<SocketId>;
        scratch_only_v6() -> io::Result<bool>;
        bind_index(socket: SocketId, index: u32) -> io::Result<()>;
        connect(socket: SocketId, peer: &Peer) -> io::Result<IpAddr>;
        disconnect(socket: SocketId) -> io::Result<()>;
        close(socket: SocketId) -> ();
        adopt(fd: OwnedFd) -> io::Result<Adopted>;
        register_tunnel(socket: SocketId, tunnel_id: u32, peer_tunnel_id: u32) -> io::Result<()>;
        session(tunnel_id: u32, session_id: u32) -> io::Result<Option<SessionInfo>>;
        scan_sessions(tunnel_id: Option<u32>, visit: &mut dyn FnMut(&SessionInfo)) -> io::Result<()>;
        delete_session(tunnel_id: u32, session_id: u32) -> io::Result<()>;
        delete_session_by_name(ifname: &L2tpIfName) -> io::Result<()>;
        prove(registration: &Registration) -> Proof;
        release(registration: &Registration) -> ();
        link_by_name(name: &L2tpIfName) -> io::Result<Option<LinkInfo>>;
        set_hwaddr(index: u32, addr: HwAddr) -> io::Result<()>;
        ether_addr(index: u32) -> io::Result<Option<HwAddr>>;
        dump_addrs() -> io::Result<Vec<AddrInfo>>;
        l2tp_events() -> io::Result<Box<dyn Subscription>>;
    }
}
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
fn config(id: u32) -> Config {
    let mut config = Config::new();
    config
        .insert_tunnel(
            "wan",
            TunnelConfig::builder(id)
                .ip_version(Family::V6)
                .build()
                .unwrap(),
        )
        .unwrap();
    config
        .insert_session(
            "lan",
            SessionConfig::builder("wan", id + 100, L2tpIfName::new("l2tp0").unwrap())
                .build()
                .unwrap(),
        )
        .unwrap();
    config
}
fn wait(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "condition did not become true");
        std::thread::yield_now();
    }
}
fn engine() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn start(host: &Host, config: Config) -> blocking::Service {
    blocking::Service::with_kernel(config, host.clone(), Box::new(NoDns), vec![])
        .map_err(|(e, _)| e)
        .unwrap()
}

fn synchronize(control: &rs_l2tpd::runtime::Control, ready: &mpsc::Receiver<()>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        control.restart().unwrap();
        if ready.recv_timeout(Duration::from_millis(10)).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "run did not start");
    }
}

/// spec: L5, L8, L11, A2, G14, R37
#[test]
fn blocking_converges_and_drop_removes_children_before_parents() {
    let host = Host::new();
    let mut service = start(&host, config(10));
    assert!(service.converge().unwrap().is_empty());
    assert!(host.with(|k| k.session_index(10, 110).is_some()));
    host.with(|k| k.clear_ops());
    drop(service);
    host.with(|k| {
        k.tick();
        assert!(k.session_index(10, 110).is_none());
        assert!(k.tunnel_socket(10).is_none());
        let ops = k.ops();
        let deletion = ops.iter().position(|s| s.starts_with("delete")).unwrap();
        let close = ops.iter().position(|s| s.starts_with("close")).unwrap();
        assert!(deletion < close, "{ops:?}");
    });
}

/// spec: L5, L8
#[test]
fn drop_before_run_retires_inherited_entries_and_works_inside_tokio() {
    engine().block_on(async {
        let host = Host::new();
        let (fd, _) = std::os::unix::net::UnixStream::pair().unwrap();
        let service = blocking::Service::with_kernel(
            Config::new(),
            host,
            Box::new(NoDns),
            vec![AdoptedSocket::new("invalid-name", fd.into())],
        )
        .map_err(|(e, _)| e)
        .unwrap();
        drop(service);
    });
}

/// spec: L5, L6, L7, A2, G14, E26
#[test]
fn reload_error_keeps_config_then_success_applies_and_restart_resumes() {
    let host = Host::new();
    let mut service = start(&host, config(10));
    service.converge().unwrap();
    let control = service.control();
    let (callback_tx, callback_rx) = mpsc::sync_channel(1);
    let (restart_tx, restart_rx) = mpsc::sync_channel(1);
    let (ready_tx, ready_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let mut calls = 0;
        service.run(
            move |_| {
                calls += 1;
                callback_tx.send(calls).unwrap();
                if calls == 1 {
                    Err(Error::Other("bad reload".into()))
                } else {
                    Ok(config(20))
                }
            },
            move |sockets| {
                assert_eq!(sockets.len(), 1);
                if sockets[0].tunnel_id() == Some(10) {
                    ready_tx.send(()).unwrap();
                    return Ok(());
                }
                assert_eq!(sockets[0].tunnel_id(), Some(20));
                restart_tx.send(()).unwrap();
                Err(Error::Other("exec refused".into()))
            },
        )
    });
    synchronize(&control, &ready_rx);
    control.reload().unwrap();
    assert_eq!(callback_rx.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
    assert_eq!(control.config(), config(10));
    control.reload().unwrap();
    assert_eq!(callback_rx.recv_timeout(Duration::from_secs(5)).unwrap(), 2);
    wait(|| control.config() == config(20));
    // Fake socket teardown is deliberately asynchronous.
    host.with(|k| {
        k.advance(Duration::from_secs(2));
        k.tick();
    });
    control.restart().unwrap();
    restart_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    control.shutdown();
    assert!(thread.join().unwrap().is_ok());
}

/// spec: L5, L7
#[test]
fn callback_panic_returns_only_after_cleanup() {
    let host = Host::new();
    let mut service = start(&host, config(10));
    service.converge().unwrap();
    let control = service.control();
    let (ready_tx, ready_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        service.run(
            |_| panic!("callback panic"),
            move |_| {
                ready_tx.send(()).unwrap();
                Ok(())
            },
        )
    });
    synchronize(&control, &ready_rx);
    control.reload().unwrap();
    assert!(matches!(thread.join().unwrap(), Err(Error::ReloadPanicked)));
    host.with(|k| {
        k.tick();
        assert!(k.tunnel_socket(10).is_none());
        assert!(k.session_index(10, 110).is_none());
    });
}

/// spec: L6
#[test]
fn restart_callback_panic_returns_only_after_cleanup() {
    let host = Host::new();
    let mut service = start(&host, config(10));
    service.converge().unwrap();
    let control = service.control();
    let thread = std::thread::spawn(move || service.run(Ok, |_| panic!("restart panic")));
    control.restart().unwrap();
    assert!(matches!(
        thread.join().unwrap(),
        Err(Error::RestartPanicked)
    ));
    host.with(|k| {
        k.tick();
        assert!(k.tunnel_socket(10).is_none());
        assert!(k.session_index(10, 110).is_none());
    });
}

/// spec: L6, L7
#[test]
fn shutdown_does_not_wait_for_blocked_callback_or_apply_its_result() {
    let host = Host::new();
    let mut service = start(&host, config(10));
    service.converge().unwrap();
    let control = service.control();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (ready_tx, ready_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = service.run(
            move |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(config(20))
            },
            move |_| {
                ready_tx.send(()).unwrap();
                Ok(())
            },
        );
        done_tx.send(result).unwrap();
    });
    synchronize(&control, &ready_rx);
    control.reload().unwrap();
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    control.reload().unwrap();
    control.shutdown();
    assert!(
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_ok()
    );
    release_tx.send(()).unwrap();
    thread.join().unwrap();
    assert_eq!(control.config(), Config::new());
    host.with(|k| {
        k.tick();
        assert!(k.tunnel_socket(10).is_none());
        assert!(k.tunnel_socket(20).is_none());
    });
}

/// spec: L5
#[test]
fn converge_ignores_reloads_and_reports_conflicts_after_ten_attempts() {
    let host = Host::new();
    host.with(|k| {
        k.operator_replace_tunnel(10, 99);
    });
    let mut service = start(&host, config(10));
    let control = service.control();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        done_tx.send(service.converge()).unwrap();
        service
    });
    wait(|| control.config() == config(10));
    let deadline = Instant::now() + Duration::from_secs(5);
    let left_out = loop {
        if let Ok(result) = done_rx.try_recv() {
            break result.unwrap();
        }
        assert!(Instant::now() < deadline, "convergence did not finish");
        host.with(|k| k.advance(Duration::from_secs(1)));
        let _ = control.reload();
        std::thread::yield_now();
    };
    assert!(!left_out.is_empty());
    drop(thread.join().unwrap());
}

/// spec: L5, L9, R37, G14
#[test]
fn startup_failure_returns_exact_names_and_live_descriptors() {
    let (fd, _) = std::os::unix::net::UnixStream::pair().unwrap();
    let adopted = vec![AdoptedSocket::new("malformed t10", fd.into())];
    // No Tokio runtime: failure occurs before adoption, not by dropping inputs.
    let (error, returned) = match Runtime::with_kernel(Host::new(), Box::new(NoDns), adopted) {
        Ok(_) => panic!("expected startup failure"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::Other(_)), "{error}");
    assert_eq!(returned[0].name(), "malformed t10");
    assert_eq!(returned[0].tunnel_id(), None);
    assert!(returned[0].fd().try_clone().is_ok());
}

/// spec: R40, G9, G14, L9
#[test]
fn runtime_drop_closes_owned_sockets_without_ordered_session_deletion() {
    for retiring in [false, true] {
        engine().block_on(async {
            let host = Host::new();
            let mut runtime = Runtime::with_kernel(host.clone(), Box::new(NoDns), vec![])
                .map_err(|(e, _)| e)
                .unwrap();
            if retiring {
                runtime.set_store_capacity(1);
            }
            assert!(runtime.reconcile(config(10)));
            assert!(host.with(|k| k.session_index(10, 110).is_some()));
            if retiring {
                runtime.reconcile(Config::new());
                assert!(host.with(|k| k.tunnel_socket(10).is_some()));
            }
            host.with(|k| k.clear_ops());
            let control = runtime.control();
            drop(runtime);
            host.with(|k| {
                k.tick();
                assert!(k.session_index(10, 110).is_none());
                assert!(k.tunnel_socket(10).is_none());
                assert_eq!(
                    k.ops().iter().filter(|op| op.starts_with("close ")).count(),
                    1
                );
                assert!(!k.ops().iter().any(|op| op.starts_with("delete")));
            });
            assert!(control.reload().is_err());
        });
    }
}

/// spec: R42, G2, G14, L9
#[test]
fn overlapping_runtimes_conflict_and_the_nonowner_cannot_remove_the_owner() {
    engine().block_on(async {
        let host = Host::new();
        let mut owner = Runtime::with_kernel(host.clone(), Box::new(NoDns), vec![])
            .map_err(|(e, _)| e)
            .unwrap();
        assert!(owner.reconcile(config(10)));
        let original = host.with(|k| (k.tunnel_socket(10), k.session_index(10, 110)));
        let mut other = Runtime::with_kernel(host.clone(), Box::new(NoDns), vec![])
            .map_err(|(e, _)| e)
            .unwrap();
        assert!(!other.reconcile(config(10)));
        assert!(!other.ready());
        assert!(other.shutdown().unwrap());
        drop(other);
        assert_eq!(
            host.with(|k| (k.tunnel_socket(10), k.session_index(10, 110))),
            original
        );
        host.with(|k| k.clear_ops());
        assert!(owner.reconcile(config(10)));
        assert!(host.with(|k| k.ops().is_empty()));
        if !owner.shutdown().unwrap() {
            host.with(|k| k.tick());
            assert!(owner.shutdown().unwrap());
        }
        assert!(host.with(|k| k.tunnel_socket(10).is_none()));
    });
}

/// spec: L5, L8, L9, A2, G14
#[test]
fn tokio_service_run_converges_without_explicit_converge() {
    engine().block_on(async {
        let host = Host::new();
        let runtime = Runtime::with_kernel(host.clone(), Box::new(NoDns), vec![])
            .map_err(|(e, _)| e)
            .unwrap();
        let mut service = service::Service::with_runtime(config(10), runtime)
            .map_err(|(e, _)| e)
            .unwrap();
        let control = service.control();
        let observer = std::thread::spawn(move || {
            wait(|| host.with(|k| k.session_index(10, 110).is_some()));
            control.shutdown();
        });
        service.run(Ok, |_| Ok(())).await.unwrap();
        observer.join().unwrap();
    });
}

/// spec: L6, L8
#[test]
fn run_after_shutdown_reports_the_completed_cleanup() {
    let host = Host::new();
    let mut service = start(&host, config(10));
    service.converge().unwrap();
    let control = service.control();
    control.shutdown();
    service.run(Ok, |_| Ok(())).unwrap();
    assert_eq!(control.config(), Config::new());
}

/// spec: A6, A7, A13, A14, L6, L9
#[test]
fn subscriptions_drain_during_a_kernel_call_and_loss_during_resync_survives() {
    let host = Host::new();
    let mut service = start(&host, config(10));
    service.converge().unwrap();
    let control = service.control();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let before_dumps = host.3.load(Ordering::SeqCst);
    *host.1.lock().unwrap() = Some(Gate {
        entered: entered_tx,
        release: release_rx,
    });
    host.with(|k| {
        k.set_monitor_capacity(0);
        k.add_link("loss1", false);
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut queued = 0;
    while control.reload().is_ok() {
        queued += 1;
    }
    assert!(queued > 0 && queued <= rs_l2tpd::runtime::QUEUE_CAPACITY);
    let drained = host.2.load(Ordering::SeqCst);
    host.with(|k| {
        k.add_link("loss2", false);
    });
    // The owner is still blocked. Only the independent subscription task can
    // consume this notice and persist a second loss outside the full channel.
    wait(|| host.2.load(Ordering::SeqCst) > drained);
    release_tx.send(()).unwrap();
    wait(|| host.3.load(Ordering::SeqCst) >= before_dumps + 2);
    drop(service);
}

/// spec: L6, L7
#[test]
fn superseded_reload_is_discarded_and_the_latest_runs_next() {
    let host = Host::new();
    let mut service = start(&host, config(10));
    service.converge().unwrap();
    let control = service.control();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (ready_tx, ready_rx) = mpsc::channel();
    let calls_seen = Arc::new(AtomicUsize::new(0));
    let callback_calls = calls_seen.clone();
    let thread = std::thread::spawn(move || {
        let mut calls = 0;
        service.run(
            move |accepted| {
                calls += 1;
                callback_calls.fetch_add(1, Ordering::SeqCst);
                entered_tx.send((calls, accepted)).unwrap();
                if calls == 1 {
                    release_rx.recv().unwrap();
                }
                Ok(config(if calls == 1 { 20 } else { 30 }))
            },
            move |_| {
                ready_tx.send(()).unwrap();
                Ok(())
            },
        )
    });
    synchronize(&control, &ready_rx);
    control.reload().unwrap();
    assert_eq!(
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        (1, config(10))
    );
    control.reload().unwrap();
    control.reload().unwrap();
    release_tx.send(()).unwrap();
    assert_eq!(
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        (2, config(10))
    );
    wait(|| control.config() == config(30));
    control.shutdown();
    thread.join().unwrap().unwrap();
    assert_eq!(calls_seen.load(Ordering::SeqCst), 2);
}

/// spec: L3
#[test]
fn public_dependency_types_are_reexported() {
    let _: Option<service::Receiver<service::ControlEvent>> = None;
    let _: Option<blocking::Receiver<blocking::ControlEvent>> = None;
    let _: Option<rs_l2tpd::config::L2tpIfName> = None;
    let _: Option<rs_l2tpd::kernel::fake::Errno> = None;
    let _: Option<rs_l2tpd::Control> = None;
    let _: Option<rs_l2tpd::ControlEvent> = None;
}

/// spec: L5, L8, L12, L13
#[test]
fn blocking_service_exposes_host_requests_and_waits_for_processing_acknowledgement() {
    let host = Host::new();
    host.with(|k| k.set_bindv6only(true));
    let mut service = start(&host, config(10));
    service.set_store_capacity(1).unwrap();
    let mut requests = service.take_requests().unwrap().unwrap();
    assert!(service.take_requests().unwrap().is_none());
    let control = service.control();
    let (stored_tx, stored_rx) = mpsc::sync_channel(1);
    let host_thread = std::thread::spawn(move || {
        let mut stored = std::collections::BTreeMap::new();
        let mut seen = Vec::new();
        while let Some(event) = requests.blocking_recv() {
            match event {
                service::ControlEvent::WriteTunable {
                    id, name, value, ..
                } => {
                    assert_eq!((name, value), ("net.ipv6.bindv6only", "0"));
                    host.with(|k| k.set_bindv6only(false));
                    control.tunable_written_blocking(id, true).unwrap();
                    seen.push("write");
                }
                service::ControlEvent::StoreSocket { name, fd, .. } => {
                    stored.insert(name, fd);
                    seen.push("store");
                    stored_tx.send(()).unwrap();
                }
                service::ControlEvent::ForgetSocket { id, name, .. } => {
                    assert!(stored.remove(&name).is_some());
                    control.socket_forgotten_blocking(id, true).unwrap();
                    seen.push("forget");
                }
                _ => panic!("unexpected host request"),
            }
        }
        assert!(stored.is_empty());
        seen
    });
    service.converge().unwrap();
    stored_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(service.set_store_capacity(2).is_err());
    service.control().shutdown();
    service.run(Ok, |_| Ok(())).unwrap();
    drop(service);
    assert_eq!(host_thread.join().unwrap(), ["write", "store", "forget"]);
}

/// spec: L5, L8
#[test]
fn blocking_service_verifies_and_reuses_a_named_adopted_tunnel() {
    let host = Host::new();
    let fd = host.with(|kernel| {
        let socket = kernel.operator_replace_tunnel(10, 10);
        let fd = kernel.clone_fd(socket).unwrap();
        kernel.close(socket);
        kernel.clear_ops();
        fd
    });
    let mut service = blocking::Service::with_kernel(
        config(10),
        host.clone(),
        Box::new(NoDns),
        vec![AdoptedSocket::new("t10", fd)],
    )
    .map_err(|(e, _)| e)
    .unwrap();
    service.converge().unwrap();
    host.with(|kernel| {
        assert!(kernel.session_index(10, 110).is_some());
        assert!(
            !kernel
                .ops()
                .iter()
                .any(|op| op.starts_with("socket ") || op.starts_with("register "))
        );
    });
    drop(service);
    host.with(|kernel| {
        kernel.tick();
        assert!(kernel.tunnel_socket(10).is_none());
    });
}

/// spec: L7, A14, M14
#[test]
fn retry_timer_keeps_running_during_a_blocked_reload() {
    let host = Host::new();
    host.with(|kernel| {
        kernel.add_link("l2tp0", false);
    });
    let mut service = start(&host, config(10));
    service.converge().unwrap();
    let control = service.control();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    control.reload().unwrap();
    let thread = std::thread::spawn(move || {
        service.run(
            move |config| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(config)
            },
            |_| Ok(()),
        )
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let attempts = host.4.load(Ordering::SeqCst);
    host.with(|kernel| kernel.advance(Duration::from_secs(1)));
    // Restart waits for the callback, but its arrival wakes the owner to tick.
    control.restart().unwrap();
    wait(|| host.4.load(Ordering::SeqCst) > attempts);
    control.shutdown();
    assert!(thread.join().unwrap().is_ok());
    release_tx.send(()).unwrap();
}

/// spec: L7, L12
#[test]
fn tunable_completion_is_processed_during_a_blocked_reload() {
    let host = Host::new();
    let mut service = start(&host, config(10));
    let mut requests = service.take_requests().unwrap().unwrap();
    service.converge().unwrap();
    host.with(|kernel| kernel.set_bindv6only(true));
    let control = service.control();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    control.reload().unwrap();
    let thread = std::thread::spawn(move || {
        let mut calls = 0;
        service.run(
            move |_| {
                calls += 1;
                if calls == 2 {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                }
                Ok(config(20))
            },
            |_| Ok(()),
        )
    });
    let service::ControlEvent::WriteTunable { id, deadline, .. } =
        requests.blocking_recv().unwrap()
    else {
        panic!("expected tunable")
    };
    control.reload().unwrap();
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    host.with(|kernel| kernel.set_bindv6only(false));
    control.tunable_written_blocking(id, true).unwrap();
    wait(|| host.with(|kernel| kernel.session_index(20, 120).is_some()));
    host.with(|kernel| {
        assert!(kernel.now() < deadline);
        assert!(!kernel.only_v6(kernel.tunnel_socket(20).unwrap()).unwrap());
    });
    control.shutdown();
    assert!(thread.join().unwrap().is_ok());
    release_tx.send(()).unwrap();
}

/// spec: L7, L13
#[test]
fn withdrawal_completion_is_processed_during_a_blocked_reload() {
    let host = Host::new();
    let mut service = start(&host, config(10));
    service.set_store_capacity(1).unwrap();
    let mut requests = service.take_requests().unwrap().unwrap();
    service.converge().unwrap();
    let service::ControlEvent::StoreSocket { fd, .. } = requests.blocking_recv().unwrap() else {
        panic!("expected store")
    };
    let control = service.control();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    control.reload().unwrap();
    let thread = std::thread::spawn(move || {
        let mut calls = 0;
        service.run(
            move |_| {
                calls += 1;
                if calls == 2 {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                }
                Ok(config(20))
            },
            |_| Ok(()),
        )
    });
    let service::ControlEvent::ForgetSocket { id, deadline, name } =
        requests.blocking_recv().unwrap()
    else {
        panic!("expected withdrawal")
    };
    assert_eq!(name, "t10");
    control.reload().unwrap();
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    drop(fd);
    control.socket_forgotten_blocking(id, true).unwrap();
    wait(|| host.with(|kernel| kernel.tunnel_socket(10).is_none()));
    assert!(host.with(|kernel| kernel.now() < deadline));
    // Socket 20 was created while the capacity was occupied and is locally owned.
    control.shutdown();
    assert!(thread.join().unwrap().is_ok());
    release_tx.send(()).unwrap();
}

/// spec: L5, L6
#[test]
fn requests_between_converge_and_run_keep_their_order() {
    for restart_first in [false, true] {
        let host = Host::new();
        let mut service = start(&host, config(10));
        service.converge().unwrap();
        let control = service.control();
        if restart_first {
            control.restart().unwrap();
            control.reload().unwrap();
        } else {
            control.reload().unwrap();
            control.restart().unwrap();
        }
        control.restart().unwrap();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let reload_observed = observed.clone();
        let restart_observed = observed.clone();
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let mut restarts = 0;
            let result = service.run(
                move |accepted| {
                    assert_eq!(accepted, config(10));
                    reload_observed.lock().unwrap().push("reload");
                    Ok(accepted)
                },
                move |_| {
                    restart_observed.lock().unwrap().push("restart");
                    restarts += 1;
                    if restarts == 2 {
                        control.shutdown();
                    }
                    Ok(())
                },
            );
            done_tx.send(result).unwrap();
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        thread.join().unwrap();
        assert_eq!(
            *observed.lock().unwrap(),
            if restart_first {
                vec!["restart", "reload", "restart"]
            } else {
                vec!["reload", "restart", "restart"]
            }
        );
    }
}

/// spec: L6, L7, A6
#[test]
fn deferred_restarts_are_bounded_and_each_accepted_request_runs() {
    let host = Host::new();
    let mut service = start(&host, config(10));
    service.converge().unwrap();
    let control = service.control();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let processed = Arc::new(AtomicUsize::new(0));
    let restarts = processed.clone();
    control.reload().unwrap();
    let thread = std::thread::spawn(move || {
        service.run(
            move |config| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(config)
            },
            move |_| {
                restarts.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut accepted = 0;
    while control.restart().is_ok() {
        accepted += 1;
        assert!(accepted < rs_l2tpd::runtime::QUEUE_CAPACITY);
    }
    assert!(accepted > 0);
    assert_eq!(processed.load(Ordering::SeqCst), 0);
    release_tx.send(()).unwrap();
    wait(|| processed.load(Ordering::SeqCst) == accepted);
    control.shutdown();
    thread.join().unwrap().unwrap();
}

/// spec: L8, L13
#[test]
fn tokio_drop_returns_without_blocking_host_request_processing() {
    engine().block_on(async {
        let host = Host::new();
        let (finished_tx, finished_rx) = mpsc::sync_channel(1);
        *host.5.lock().unwrap() = Some(finished_tx);
        let runtime = Runtime::with_kernel(host.clone(), Box::new(NoDns), vec![])
            .map_err(|(e, _)| e)
            .unwrap();
        let mut service = service::Service::with_runtime(config(10), runtime)
            .map_err(|(e, _)| e)
            .unwrap();
        service.set_store_capacity(1).await.unwrap();
        let mut requests = service.take_requests().unwrap();
        service.converge().await.unwrap();
        let control = service.control();
        let before = Instant::now();
        drop(service);
        assert!(before.elapsed() < Duration::from_secs(1));
        // The same current-thread executor can now process the withdrawals.
        while let Some(event) = requests.recv().await {
            match event {
                service::ControlEvent::StoreSocket { fd, .. } => drop(fd),
                service::ControlEvent::ForgetSocket { id, .. } => {
                    control.socket_forgotten(id, true).await.unwrap()
                }
                _ => panic!("unexpected host request"),
            }
        }
        finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        host.with(|kernel| {
            kernel.tick();
            assert!(kernel.tunnel_socket(10).is_none());
            assert!(kernel.session_index(10, 110).is_none());
        });
    });
}

struct NestedDns(Arc<AtomicUsize>);
impl Resolve for NestedDns {
    fn watch(&mut self, _: Lookup) -> io::Result<()> {
        engine().block_on(async {});
        Ok(())
    }
    fn unwatch(&mut self, _: u64) {
        engine().block_on(async {});
    }
    fn poll(&mut self) -> Vec<(u64, Vec<IpAddr>)> {
        engine().block_on(async {});
        self.0.fetch_add(1, Ordering::SeqCst);
        vec![]
    }
    fn retry_discovery(&self, _: u64) -> bool {
        engine().block_on(async {});
        false
    }
    fn waiting(&self, _: u64) -> bool {
        engine().block_on(async {});
        false
    }
}

/// spec: L7, L8, A14
#[test]
fn spawn_blocking_callers_and_injected_callbacks_can_own_their_runtimes() {
    engine().block_on(async {
        tokio::task::spawn_blocking(|| {
            let host = Host::new();
            host.6.store(true, Ordering::SeqCst);
            let polls = Arc::new(AtomicUsize::new(0));
            let mut wanted = config(10);
            wanted
                .insert_tunnel(
                    "wan",
                    TunnelConfig::builder(10)
                        .remote_addr(rs_l2tpd::config::RemoteAddr::Host("peer.example".into()))
                        .ip_version(Family::V6)
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let mut service = blocking::Service::with_kernel(
                wanted.clone(),
                host.clone(),
                Box::new(NestedDns(polls.clone())),
                vec![],
            )
            .map_err(|(error, _)| error)
            .unwrap();
            service.set_store_capacity(0).unwrap();
            assert!(service.take_requests().unwrap().is_some());
            service.converge().unwrap();
            let control = service.control();
            assert_eq!(control.config(), wanted);
            control.tunable_written_blocking(0, false).unwrap();
            control.socket_forgotten_blocking(0, false).unwrap();
            host.with(|kernel| kernel.advance(Duration::from_secs(1)));
            control.reload().unwrap();
            control.restart().unwrap();
            let shutdown = control.clone();
            service
                .run(
                    |accepted| engine().block_on(async { Ok(accepted) }),
                    move |_| {
                        engine().block_on(async {
                            shutdown.shutdown();
                            Ok(())
                        })
                    },
                )
                .unwrap();
            assert!(polls.load(Ordering::SeqCst) > 0);
            assert_eq!(control.config(), Config::new());
            drop(service);

            // Drop before run also keeps the private subscription runtime alive.
            let mut service =
                blocking::Service::with_kernel(wanted, host, Box::new(NestedDns(polls)), vec![])
                    .map_err(|(error, _)| error)
                    .unwrap();
            service.converge().unwrap();
            drop(service);
        })
        .await
        .unwrap();
    });
}

/// spec: L5, L6
#[test]
fn reload_accepted_during_convergence_is_ignored_even_when_dequeued_after_readiness() {
    for direct in [false, true] {
        let host = Host::new();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let gate = if direct { &host.7 } else { &host.1 };
        *gate.lock().unwrap() = Some(Gate {
            entered: entered_tx,
            release: release_rx,
        });
        let mut wanted = config(10);
        let mut session = SessionConfig::builder("wan", 110, L2tpIfName::new("l2tp0").unwrap());
        if !direct {
            session = session.interface_hwaddr(HwAddr::new([2, 0, 0, 0, 0, 1]).unwrap());
        }
        wanted
            .insert_session("lan", session.build().unwrap())
            .unwrap();
        let mut service = start(&host, wanted);
        let control = service.control();
        let converging = std::thread::spawn(move || {
            service.converge().unwrap();
            service
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        control.reload().unwrap();
        release_tx.send(()).unwrap();
        let mut service = converging.join().unwrap();
        control.restart().unwrap();
        service
            .run(
                |_| panic!("convergence reload must be ignored"),
                move |_| {
                    control.shutdown();
                    Ok(())
                },
            )
            .unwrap();
    }
}

/// spec: L5, L9, G14
#[test]
fn panicking_kernel_initializer_returns_descriptors_to_the_caller() {
    let host = Host::new();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = host.0.lock().unwrap();
            panic!("poison the test kernel before subscription initialization");
        }))
        .is_err()
    );
    let engine = engine();
    let _entered = engine.enter();
    let (fd, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let original = fd.as_raw_fd();
    let (error, returned) = Runtime::with_kernel(
        host,
        Box::new(NoDns),
        vec![AdoptedSocket::new("unchanged input", fd.into())],
    )
    .err()
    .unwrap();
    assert_eq!(
        error.to_string(),
        "kernel subscription initializer panicked"
    );
    assert_eq!(returned.len(), 1);
    assert_eq!(returned[0].name(), "unchanged input");
    assert_eq!(returned[0].fd().as_raw_fd(), original);
    assert!(returned[0].fd().try_clone().is_ok());
}
