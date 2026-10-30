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
                    let signal = match mask.wait() {
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
    set().thread_set_mask()?;
    // Ignored dispositions also survive exec, including an inherited SIGCHLD.
    unsafe {
        for signal in 1..=libc::SIGRTMAX() {
            if signal != libc::SIGKILL && signal != libc::SIGSTOP {
                libc::signal(signal, libc::SIG_DFL);
            }
        }
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    Ok(())
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
    }
}

#[cfg(all(test, feature = "fake-kernel"))]
mod forwarder_tests {
    use super::*;
    use rs_l2tpd::kernel::fake::FakeKernel;
    use rs_l2tpd::reconciler::IphostResolve;
    use rs_l2tpd::{ControlEvent, Runtime};
    /// spec: P12
    #[test]
    fn forwarder_retries_a_full_queue_and_delivers_after_capacity_returns() {
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
        shared.observe(Signal::SIGUSR2);
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
        assert!(shared.pending.lock().unwrap().restart);
        engine.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                for _ in 0..rs_l2tpd::runtime::QUEUE_CAPACITY {
                    let event = runtime.next_event().await;
                    assert!(matches!(event, ControlEvent::Reload { .. }));
                    runtime.handle_event(event).unwrap();
                }
                assert!(matches!(runtime.next_event().await, ControlEvent::Restart));
            })
            .await
            .unwrap();
        });
        assert!(!shared.pending.lock().unwrap().restart);
        shared.pending.lock().unwrap().stopped = true;
        shared.wake.notify_all();
        thread.join().unwrap();
        assert!(!shared.observe(Signal::SIGTERM));
    }
}
