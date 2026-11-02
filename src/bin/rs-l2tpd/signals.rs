//! Coalescing signal collector and independent persistent shutdown (P12).
use nix::sys::signal::{SigSet, Signal};
use rs_l2tpd::Control;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[derive(Default)]
struct Pending {
    reload: bool,
    restart: bool,
    ready: bool,
    stopped: bool,
    control: Option<Control>,
}
struct Shared {
    pending: Mutex<Pending>,
    wake: Condvar,
    shutdown: AtomicBool,
    #[cfg(test)]
    full_retries: std::sync::atomic::AtomicUsize,
}
impl Shared {
    fn forward(&self) {
        let mut pending = self.pending.lock().unwrap();
        loop {
            if pending.stopped {
                break;
            }
            if self.shutdown.load(Ordering::Acquire) {
                if let Some(control) = &pending.control {
                    control.shutdown();
                }
            } else if let Some(control) = pending.control.clone() {
                if pending.reload && control.reload().is_ok() {
                    pending.reload = false;
                }
                if pending.restart && control.restart().is_ok() {
                    pending.restart = false;
                }
            }
            if pending.reload || pending.restart {
                #[cfg(test)]
                self.full_retries.fetch_add(1, Ordering::Release);
                pending = self
                    .wake
                    .wait_timeout(pending, Duration::from_millis(10))
                    .unwrap()
                    .0;
            } else {
                pending = self.wake.wait(pending).unwrap();
            }
        }
    }
    fn observe(&self, signal: Signal) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if pending.stopped {
            return false;
        }
        if self.shutdown.load(Ordering::Acquire) {
            if signal == Signal::SIGUSR2 {
                log::warn!("restart ignored during shutdown");
            }
            return true;
        }
        match signal {
            Signal::SIGTERM | Signal::SIGINT => {
                self.shutdown.store(true, Ordering::Release);
                pending.reload = false;
                pending.restart = false;
                if let Some(control) = &pending.control {
                    control.shutdown();
                }
            }
            Signal::SIGHUP if pending.ready => pending.reload = true,
            Signal::SIGUSR2 if pending.ready => pending.restart = true,
            Signal::SIGUSR2 => log::warn!("restart ignored before readiness"),
            _ => (),
        }
        self.wake.notify_all();
        true
    }
}
pub struct Signals {
    shared: Arc<Shared>,
    collector: Option<std::thread::JoinHandle<()>>,
    forwarder: Option<std::thread::JoinHandle<()>>,
}
fn set() -> SigSet {
    let mut set = SigSet::empty();
    for signal in [
        Signal::SIGHUP,
        Signal::SIGTERM,
        Signal::SIGINT,
        Signal::SIGUSR2,
    ] {
        set.add(signal);
    }
    set
}
// nix 0.30 misreads positive pthread errors; the approved libc exception stays here.
fn signal_result(result: libc::c_int) -> io::Result<()> {
    match result {
        0 => Ok(()),
        -1 => Err(io::Error::last_os_error()), // musl sigwait uses errno.
        error => Err(io::Error::from_raw_os_error(error)),
    }
}
fn wait(mask: &SigSet) -> io::Result<Signal> {
    let mut signal = 0;
    signal_result(unsafe { libc::sigwait(mask.as_ref(), &mut signal) })?;
    Signal::try_from(signal).map_err(io::Error::from)
}
impl Signals {
    // Before creating any library/host thread, so each inherits the blocked set.
    pub fn install() -> io::Result<Self> {
        prepare()?;
        let mask = set();
        let shared = Arc::new(Shared {
            pending: Mutex::new(Pending::default()),
            wake: Condvar::new(),
            shutdown: AtomicBool::new(false),
            #[cfg(test)]
            full_retries: Default::default(),
        });
        let collector_shared = shared.clone();
        let collector = std::thread::Builder::new()
            .name("l2tp-signals".into())
            .spawn(move || {
                loop {
                    let signal = match wait(&mask) {
                        Ok(signal) => signal,
                        Err(error) => {
                            log::error!("sigwait: {error}; shutting down");
                            collector_shared.observe(Signal::SIGTERM);
                            break;
                        }
                    };
                    if !collector_shared.observe(signal) {
                        break;
                    }
                }
            })?;
        let forward_shared = shared.clone();
        let forwarder = match std::thread::Builder::new()
            .name("l2tp-signal-forward".into())
            .spawn(move || {
                forward_shared.forward();
            }) {
            Ok(thread) => thread,
            Err(error) => {
                shared.pending.lock().unwrap().stopped = true;
                use std::os::unix::thread::JoinHandleExt;
                // kernel: kernel/signal.c do_tkill/do_sigtimedwait: thread-directed wake.
                unsafe {
                    libc::pthread_kill(collector.as_pthread_t() as libc::pthread_t, libc::SIGTERM);
                }
                let _ = collector.join();
                return Err(error);
            }
        };
        Ok(Self {
            shared,
            collector: Some(collector),
            forwarder: Some(forwarder),
        })
    }
    pub fn attach(&self, control: Control) {
        if self.stopping() {
            control.shutdown();
        }
        self.shared.pending.lock().unwrap().control = Some(control);
        self.shared.wake.notify_all();
    }
    pub fn ready(&self) {
        self.shared.pending.lock().unwrap().ready = true;
    }
    pub fn stopping(&self) -> bool {
        self.shared.shutdown.load(Ordering::Acquire)
    }
    pub fn retry(&self) {
        let pending = self.shared.pending.lock().unwrap();
        if !self.stopping() {
            let _ = self
                .shared
                .wake
                .wait_timeout(pending, Duration::from_secs(1));
        }
    }
}
pub fn prepare() -> io::Result<()> {
    signal_result(unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, set().as_ref(), std::ptr::null_mut())
    })?;
    // Ignored dispositions also survive exec, including an inherited SIGCHLD.
    unsafe {
        for signal in 1..=libc::SIGRTMAX() {
            if signal != libc::SIGKILL && signal != libc::SIGSTOP {
                libc::signal(signal, libc::SIG_DFL);
            }
        }
    }
    ignore_pipe()
}

pub(super) fn ignore_pipe() -> io::Result<()> {
    if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) } == libc::SIG_ERR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        self.shared.pending.lock().unwrap().stopped = true;
        self.shared.wake.notify_all();
        if let Some(thread) = self.collector.take() {
            use std::os::unix::thread::JoinHandleExt;
            // stopped is visible before this thread-directed, already blocked signal.
            unsafe {
                libc::pthread_kill(thread.as_pthread_t() as libc::pthread_t, libc::SIGTERM);
            }
            let _ = thread.join();
        }
        if let Some(thread) = self.forwarder.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(all(test, feature = "fake-kernel"))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use rs_l2tpd::kernel::fake::FakeKernel;
    use rs_l2tpd::reconciler::IphostResolve;
    use rs_l2tpd::{ControlEvent, Runtime};
    /// spec: P9 P12
    #[test]
    fn pending_requests_coalesce_and_shutdown_bypasses_a_full_fake_queue() {
        let engine = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _entered = engine.enter();
        let mut runtime = Runtime::with_kernel(
            FakeKernel::new(1),
            Box::new(IphostResolve::default()),
            vec![],
        )
        .unwrap();
        let control = runtime.control();
        let shared = Shared {
            pending: Mutex::new(Pending {
                control: Some(control.clone()),
                ..Pending::default()
            }),
            wake: Condvar::new(),
            shutdown: AtomicBool::new(false),
            full_retries: Default::default(),
        };
        shared.observe(Signal::SIGHUP);
        shared.observe(Signal::SIGUSR2);
        assert!(!shared.pending.lock().unwrap().reload);
        assert!(!shared.pending.lock().unwrap().restart);
        shared.pending.lock().unwrap().ready = true;
        for _ in 0..100 {
            shared.observe(Signal::SIGHUP);
            shared.observe(Signal::SIGUSR2);
        }
        assert!(shared.pending.lock().unwrap().reload);
        assert!(shared.pending.lock().unwrap().restart);
        for _ in 0..rs_l2tpd::runtime::QUEUE_CAPACITY {
            control.reload().unwrap();
        }
        assert!(control.reload().is_err());
        shared.observe(Signal::SIGTERM);
        assert!(matches!(
            engine.block_on(runtime.next_event()),
            ControlEvent::Shutdown
        ));
        assert!(!shared.pending.lock().unwrap().reload);
        assert!(!shared.pending.lock().unwrap().restart);
        shared.observe(Signal::SIGHUP);
        shared.observe(Signal::SIGUSR2);
        assert!(!shared.pending.lock().unwrap().reload);
        assert!(!shared.pending.lock().unwrap().restart);
        shared.pending.lock().unwrap().control = None;
        let signals = Signals {
            shared: Arc::new(shared),
            collector: None,
            forwarder: None,
        };
        let mut next = Runtime::with_kernel(
            FakeKernel::new(2),
            Box::new(IphostResolve::default()),
            vec![],
        )
        .unwrap();
        signals.attach(next.control());
        assert!(matches!(
            engine.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), next.next_event())
                    .await
                    .unwrap()
            }),
            ControlEvent::Shutdown
        ));
    }
}

#[cfg(all(test, feature = "fake-kernel"))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod forwarder_tests {
    use super::*;
    use rs_l2tpd::kernel::fake::FakeKernel;
    use rs_l2tpd::reconciler::IphostResolve;
    use rs_l2tpd::{ControlEvent, Runtime};
    /// spec: P12
    #[test]
    fn forwarder_retries_a_full_queue_and_delivers_after_capacity_returns() {
        for signal in [Signal::SIGHUP, Signal::SIGUSR2] {
            let engine = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _entered = engine.enter();
            let mut runtime = Runtime::with_kernel(
                FakeKernel::new(1),
                Box::new(IphostResolve::default()),
                vec![],
            )
            .unwrap();
            let control = runtime.control();
            for _ in 0..rs_l2tpd::runtime::QUEUE_CAPACITY {
                control.reload().unwrap();
            }
            let shared = Arc::new(Shared {
                pending: Mutex::new(Pending {
                    control: Some(control),
                    ready: true,
                    ..Pending::default()
                }),
                wake: Condvar::new(),
                shutdown: AtomicBool::new(false),
                full_retries: Default::default(),
            });
            shared.observe(signal);
            let forward = shared.clone();
            let thread = std::thread::spawn(move || forward.forward());
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while shared.full_retries.load(Ordering::Acquire) == 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "forwarder did not retry the full queue"
                );
                std::thread::yield_now();
            }
            {
                let pending = shared.pending.lock().unwrap();
                assert_eq!(pending.reload, signal == Signal::SIGHUP);
                assert_eq!(pending.restart, signal == Signal::SIGUSR2);
            }
            engine.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    for _ in 0..rs_l2tpd::runtime::QUEUE_CAPACITY {
                        let event = runtime.next_event().await;
                        assert!(matches!(event, ControlEvent::Reload { .. }));
                        runtime.handle_event(event).unwrap();
                    }
                    let delivered = runtime.next_event().await;
                    match signal {
                        Signal::SIGHUP => assert!(matches!(delivered, ControlEvent::Reload { .. })),
                        Signal::SIGUSR2 => assert!(matches!(delivered, ControlEvent::Restart)),
                        _ => unreachable!(),
                    }
                })
                .await
                .unwrap();
            });
            {
                let pending = shared.pending.lock().unwrap();
                assert!(!pending.reload && !pending.restart);
            }
            shared.pending.lock().unwrap().stopped = true;
            shared.wake.notify_all();
            thread.join().unwrap();
            assert!(!shared.observe(Signal::SIGTERM));
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod libc_tests {
    use super::*;

    /// spec: P12, P16
    #[test]
    fn drop_joins_present_workers_and_tolerates_absent_workers() {
        for collector in [false, true] {
            for forwarder in [false, true] {
                let shared = Arc::new(Shared {
                    pending: Mutex::new(Pending::default()),
                    wake: Condvar::new(),
                    shutdown: AtomicBool::new(false),
                    full_retries: Default::default(),
                });
                let collector = collector.then(|| {
                    let (ready, started) = std::sync::mpsc::sync_channel(1);
                    let thread = std::thread::spawn(move || {
                        let mask = set();
                        mask.thread_block().unwrap();
                        ready.send(()).unwrap();
                        assert_eq!(wait(&mask).unwrap(), Signal::SIGTERM);
                    });
                    started.recv_timeout(Duration::from_secs(5)).unwrap();
                    thread
                });
                let forwarder = forwarder.then(|| {
                    let shared = shared.clone();
                    std::thread::spawn(move || shared.forward())
                });
                drop(Signals {
                    shared: shared.clone(),
                    collector,
                    forwarder,
                });
                assert!(shared.pending.lock().unwrap().stopped);
            }
        }
    }

    /// spec: P4, P12, P16, G14
    #[test]
    #[ignore = "exact cgroup pids.max of 2 or 3; run only this test in a disposable container or guest"]
    fn thread_spawn_failures_leave_no_signal_threads() {
        let expected = std::env::var("RS_L2TPD_SIGNAL_TASK_LIMIT")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert!([2, 3].contains(&expected));
        let group = std::env::var_os("RS_L2TPD_SIGNAL_TASK_CGROUP")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| "/sys/fs/cgroup".into());
        assert_eq!(
            std::fs::read_to_string(group.join("pids.max"))
                .unwrap()
                .trim(),
            expected.to_string()
        );
        let tasks = || std::fs::read_dir("/proc/self/task").unwrap().count();
        assert_eq!(
            tasks(),
            2,
            "fixture requires only libtest's main and worker threads"
        );
        let error = Signals::install()
            .err()
            .expect("task limit allowed both signal threads");
        assert_eq!(error.raw_os_error(), Some(libc::EAGAIN));
        assert_eq!(
            tasks(),
            2,
            "failed installation left a signal thread behind"
        );
        assert_eq!(
            std::fs::read_to_string(group.join("pids.peak"))
                .unwrap()
                .trim(),
            expected.to_string(),
            "fixture did not reach the selected failure stage"
        );
        println!("SIGNAL_TASK_LIMIT_CHECKED={expected} tasks=2");
    }

    /// spec: P4 P12 P16
    #[test]
    fn signal_errors_use_the_return_code_or_errno_as_required() {
        nix::errno::Errno::EACCES.set();
        assert!(signal_result(0).is_ok());
        assert_eq!(
            signal_result(libc::EIO).unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(
            signal_result(-1).unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
    }

    /// spec: P4 P12 P16
    #[test]
    fn blocked_signals_and_wait_failures_are_checked_in_subprocesses() {
        const CHILD: &str = "RS_L2TPD_TEST_LIBC_SIGNALS";
        if let Ok(case) = std::env::var(CHILD) {
            if case == "mask-error" {
                crate::syscall_fault::refuse(&[libc::SYS_rt_sigprocmask], libc::EIO);
                assert_eq!(prepare().unwrap_err().raw_os_error(), Some(libc::EIO));
                return;
            }
            prepare().unwrap();
            let current = SigSet::thread_get_mask().unwrap();
            for signal in [
                Signal::SIGHUP,
                Signal::SIGTERM,
                Signal::SIGINT,
                Signal::SIGUSR2,
            ] {
                assert!(current.contains(signal));
                if case == "delivery" {
                    assert_eq!(
                        unsafe { libc::pthread_kill(libc::pthread_self(), signal as libc::c_int) },
                        0
                    );
                    assert_eq!(wait(&set()).unwrap(), signal);
                }
            }
            assert!(!current.contains(Signal::SIGUSR1));
            if case == "wait-error" || case == "collector-error" {
                crate::syscall_fault::refuse(&[libc::SYS_rt_sigtimedwait], libc::EIO);
                if case == "wait-error" {
                    assert_eq!(wait(&set()).unwrap_err().raw_os_error(), Some(libc::EIO));
                } else {
                    crate::logger::init(true);
                    let signals = Signals::install().unwrap();
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    while !signals.stopping() {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "collector did not request shutdown"
                        );
                        std::thread::yield_now();
                    }
                    drop(signals);
                    println!("COLLECTOR_ERROR_SHUTDOWN=1");
                }
            }
            return;
        }
        for case in ["delivery", "mask-error", "wait-error", "collector-error"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "signals::libc_tests::blocked_signals_and_wait_failures_are_checked_in_subprocesses",
                    "--nocapture",
                ])
                .env(CHILD, case)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{case}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            if case == "collector-error" {
                assert!(
                    String::from_utf8_lossy(&output.stdout).contains("COLLECTOR_ERROR_SHUTDOWN=1")
                );
                assert!(String::from_utf8_lossy(&output.stderr).contains("sigwait:"));
            }
            println!("LIBC_SIGNAL_CHECKED={case}");
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod pipe_error_tests {
    use super::*;

    /// spec: P4, P12, P26
    #[test]
    fn sigpipe_disposition_errors_are_returned_before_startup_or_exec() {
        const CHILD: &str = "PHASE6_CHECKED_SIGPIPE";
        if let Some(case) = std::env::var_os(CHILD) {
            #[cfg(coverage_nightly)]
            crate::syscall_fault::keep_profile_output();
            crate::syscall_fault::on_exec_argument(
                libc::SYS_rt_sigaction,
                0,
                libc::SIGPIPE as u32,
                libc::EIO,
            )()
            .unwrap();
            let error = if case == "direct" {
                ignore_pipe()
            } else {
                prepare()
            }
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
            println!(
                "SIGPIPE_DISPOSITION_REFUSAL_CHECKED={}",
                case.to_string_lossy()
            );
            return;
        }
        for case in ["direct", "prepare"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "signals::pipe_error_tests::sigpipe_disposition_errors_are_returned_before_startup_or_exec", "--nocapture"])
                .env(CHILD, case).output().unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains("SIGPIPE_DISPOSITION_REFUSAL_CHECKED=")
            );
        }
    }
}
