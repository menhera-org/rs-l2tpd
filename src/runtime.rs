//! Program-driven reconciliation (L9–L13). Construct within a Tokio runtime;
//! subscription tasks run there while the owner performs synchronous kernel work.
//! Forward every [`Runtime::next_event`] result to [`Runtime::handle_event`].
//! Inspect host requests before forwarding them and answer through [`Control`].
//!
//! ```no_run
//! # async fn example() -> rs_l2tpd::Result<()> {
//! use rs_l2tpd::{Runtime, config::Config};
//! let mut runtime = Runtime::new(vec![]).map_err(|(e, _)| e)?;
//! runtime.reconcile(Config::new());
//! runtime.control().shutdown();
//! let event = runtime.next_event().await;
//! runtime.handle_event(event)?;
//! while !runtime.shutdown()? {
//!     let event = runtime.next_event().await;
//!     runtime.handle_event(event)?;
//! }
//! # Ok(()) }
//! ```

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::os::fd::OwnedFd;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

pub use crate::kernel::{Notice, Subscription};
pub use crate::reconciler::Source;
pub use tokio::sync::mpsc::Receiver;

use crate::config::Config;
use crate::kernel::{Kernel, linux::LinuxKernel};
use crate::reconciler::{IphostResolve, Reconciler, Request, Resolve};
use crate::{Error, Result};

#[cfg(test)]
mod tests;

/// The single input queue's capacity (A6).
pub const QUEUE_CAPACITY: usize = 1024;

/// A descriptor with its exact inherited store name. The parsed identifier is
/// available only for the canonical spelling; it is not verification.
#[derive(Debug)]
pub struct AdoptedSocket {
    name: String,
    fd: OwnedFd,
}

impl AdoptedSocket {
    /// Retains even a malformed name for subsequent withdrawal.
    pub fn new(name: impl Into<String>, fd: OwnedFd) -> Self {
        Self {
            name: name.into(),
            fd,
        }
    }
    /// The exact store name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The inherited descriptor, still unverified.
    pub fn fd(&self) -> &OwnedFd {
        &self.fd
    }
    /// The canonical name's identifier, if valid.
    pub fn tunnel_id(&self) -> Option<u32> {
        self.name
            .strip_prefix('t')
            .and_then(|id| id.parse::<u32>().ok())
            .filter(|id| *id != 0 && self.name == format!("t{id}"))
    }
    /// Returns ownership and the unchanged name.
    pub fn into_parts(self) -> (String, OwnedFd) {
        (self.name, self.fd)
    }
}

/// Startup failures return every unconsumed adopted descriptor to the caller.
pub type StartResult<T> = std::result::Result<T, (Error, Vec<AdoptedSocket>)>;

/// An input or host request. Embedders must forward unknown future variants too.
///
/// ```compile_fail,E0004
/// use rs_l2tpd::ControlEvent;
/// fn dispatch(event: ControlEvent) {
///     // Even listing all current variants requires a wildcard outside the crate.
///     match event {
///         ControlEvent::Kernel { .. } | ControlEvent::ResolverAnswers |
///         ControlEvent::Tick | ControlEvent::Reload { .. } |
///         ControlEvent::Shutdown | ControlEvent::Restart |
///         ControlEvent::WriteTunable { .. } | ControlEvent::StoreSocket { .. } |
///         ControlEvent::ForgetSocket { .. } | ControlEvent::TunableWritten { .. } |
///         ControlEvent::SocketForgotten { .. } | ControlEvent::Service(_) => {}
///     }
/// }
/// ```
#[non_exhaustive]
pub enum ControlEvent {
    /// A notice from one of the independently drained subscriptions.
    Kernel {
        /// Its source.
        source: Source,
        /// The notice.
        notice: Notice,
    },
    /// Reserved for resolver notifications; treated as [`Self::Tick`]. Current
    /// resolver workers retain their answers for polling by the policy timer.
    ResolverAnswers,
    /// Run due timers.
    Tick,
    /// Reload through the service callback.
    Reload {
        /// Acceptance generation, used to discard superseded callbacks.
        generation: u64,
    },
    /// Orderly shutdown.
    Shutdown,
    /// Invoke the restart callback with owned tunnel duplicates.
    Restart,
    /// The program must write a tunable and report the processing outcome.
    WriteTunable {
        /// Tunable name.
        name: &'static str,
        /// Requested value.
        value: &'static str,
        /// Request incarnation.
        id: u64,
        /// Absolute deadline.
        deadline: Instant,
    },
    /// Submit this duplicate to the descriptor store.
    StoreSocket {
        /// Exact reserved name.
        name: String,
        /// Tunnel identifier.
        tunnel_id: u32,
        /// Owned duplicate.
        fd: OwnedFd,
    },
    /// Withdraw the exact store name, then acknowledge a processing barrier.
    ForgetSocket {
        /// Exact name, including invalid inherited names.
        name: String,
        /// Request incarnation.
        id: u64,
        /// Absolute deadline.
        deadline: Instant,
    },
    /// A tunable completion; use [`Control::tunable_written`].
    TunableWritten {
        /// Incarnation.
        id: u64,
        /// Processing succeeded.
        success: bool,
    },
    /// A store withdrawal completion; use [`Control::socket_forgotten`].
    SocketForgotten {
        /// Incarnation.
        id: u64,
        /// Manager processing was confirmed.
        processed: bool,
    },
    #[doc(hidden)]
    Service(crate::service::Operation),
}

pub(crate) struct Shared {
    pub shutdown: AtomicBool,
    wake: tokio::sync::Notify,
    loss: [AtomicBool; 2],
    pub generation: AtomicU64,
    acceptance: Mutex<()>,
    config: Mutex<Config>,
    requests: tokio::sync::Semaphore,
    admitted: AtomicUsize,
}

/// Cloneable, thread-safe requests. Shutdown has a persistent path outside the
/// bounded queue; the other methods report a closed/full queue as an error.
#[derive(Clone)]
pub struct Control {
    pub(crate) tx: tokio::sync::mpsc::Sender<ControlEvent>,
    pub(crate) shared: Arc<Shared>,
}

impl Control {
    /// Requests a reload without waiting for queue space.
    ///
    /// Every accepted reload or restart holds one of the queue's admission
    /// slots until it is processed: by the service, or, for a program driving
    /// [`Runtime`] itself, by forwarding the `Reload`/`Restart` event to
    /// [`Runtime::handle_event`] as L10 requires. A program that withholds
    /// those events exhausts the slots, after which this method and
    /// [`Self::restart`] fail until the program forwards them.
    pub fn reload(&self) -> Result<()> {
        let _order = self.shared.acceptance.lock().unwrap();
        let request = self
            .shared
            .requests
            .try_acquire()
            .map_err(|e| Error::Other(e.to_string()))?;
        let permit = self
            .tx
            .try_reserve()
            .map_err(|e| Error::Other(e.to_string()))?;
        let generation = self.shared.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.shared.admitted.fetch_add(1, Ordering::AcqRel);
        request.forget();
        permit.send(ControlEvent::Reload { generation });
        Ok(())
    }
    /// Waits for queue space, without blocking the calling thread.
    pub async fn reload_wait(&self) -> Result<()> {
        // Reserve outside the admission lock: waiting must not block try_send.
        let request = self
            .shared
            .requests
            .acquire()
            .await
            .map_err(|e| Error::Other(e.to_string()))?;
        let permit = self
            .tx
            .reserve()
            .await
            .map_err(|e| Error::Other(e.to_string()))?;
        let _order = self.shared.acceptance.lock().unwrap();
        let generation = self.shared.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.shared.admitted.fetch_add(1, Ordering::AcqRel);
        request.forget();
        permit.send(ControlEvent::Reload { generation });
        Ok(())
    }
    /// Persistent, idempotent, and independent of queue capacity.
    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::Release);
        self.shared.wake.notify_one();
    }
    /// Requests a restart; fails rather than waiting if the queue is full.
    pub fn restart(&self) -> Result<()> {
        let _order = self.shared.acceptance.lock().unwrap();
        let request = self
            .shared
            .requests
            .try_acquire()
            .map_err(|e| Error::Other(e.to_string()))?;
        let permit = self
            .tx
            .try_reserve()
            .map_err(|e| Error::Other(e.to_string()))?;
        self.shared.admitted.fetch_add(1, Ordering::AcqRel);
        request.forget();
        permit.send(ControlEvent::Restart);
        Ok(())
    }
    /// A snapshot of the accepted configuration.
    pub fn config(&self) -> Config {
        self.shared.config.lock().unwrap().clone()
    }
    /// Reports the tunable write's outcome, waiting for queue space.
    pub async fn tunable_written(&self, id: u64, success: bool) -> Result<()> {
        self.send(ControlEvent::TunableWritten { id, success })
            .await
    }
    /// Reports a manager processing barrier, not merely a datagram send.
    pub async fn socket_forgotten(&self, id: u64, processed: bool) -> Result<()> {
        self.send(ControlEvent::SocketForgotten { id, processed })
            .await
    }
    /// Blocking tunable completion from a synchronous thread, including
    /// `tokio::task::spawn_blocking`. Async workers use [`Self::tunable_written`].
    pub fn tunable_written_blocking(&self, id: u64, success: bool) -> Result<()> {
        self.send_blocking(ControlEvent::TunableWritten { id, success })
    }
    /// Blocking processing-barrier completion, also usable in `spawn_blocking`.
    /// Async workers use [`Self::socket_forgotten`].
    pub fn socket_forgotten_blocking(&self, id: u64, processed: bool) -> Result<()> {
        self.send_blocking(ControlEvent::SocketForgotten { id, processed })
    }
    fn send_blocking(&self, event: ControlEvent) -> Result<()> {
        self.tx
            .blocking_send(event)
            .map_err(|e| Error::Other(e.to_string()))
    }
    pub(crate) fn request_processed(&self) {
        // Direct Runtime users can also forward manually constructed events.
        let mut count = self.shared.admitted.load(Ordering::Acquire);
        while count != 0 {
            match self.shared.admitted.compare_exchange_weak(
                count,
                count - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.shared.requests.add_permits(1);
                    break;
                }
                Err(current) => count = current,
            }
        }
    }
    pub(crate) async fn send(&self, event: ControlEvent) -> Result<()> {
        self.tx
            .send(event)
            .await
            .map_err(|e| Error::Other(e.to_string()))
    }
}

/// The kernel owner and event dispatcher. Synchronous methods belong on a
/// dedicated thread; watchers remain on the runtime used during construction.
pub struct Runtime<K: Kernel = LinuxKernel> {
    reconciler: Reconciler<K>,
    control: Control,
    rx: Receiver<ControlEvent>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    outgoing: VecDeque<ControlEvent>,
    stopping: Option<Instant>,
}

impl Runtime<LinuxKernel> {
    /// Opens the kernel interfaces immediately. Requires a running Tokio
    /// runtime. Startup errors retain adopted inputs for a caller retry.
    pub fn new(adopted: Vec<AdoptedSocket>) -> StartResult<Self> {
        match LinuxKernel::new() {
            Ok(kernel) => Self::with_kernel(kernel, Box::new(IphostResolve::default()), adopted),
            Err(e) => Err((e.into(), adopted)),
        }
    }
}

impl<K: Kernel + 'static> Runtime<K> {
    pub(crate) fn into_adopted(mut self) -> Vec<AdoptedSocket> {
        self.reconciler
            .take_inherited()
            .into_iter()
            .map(|(name, fd)| AdoptedSocket::new(name, fd))
            .collect()
    }
    /// Uses an already opened kernel and resolver, including a fake for tests.
    pub fn with_kernel(
        mut kernel: K,
        resolver: Box<dyn Resolve>,
        adopted: Vec<AdoptedSocket>,
    ) -> StartResult<Self> {
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle,
            Err(error) => return Err((Error::Other(error.to_string()), adopted)),
        };
        // Injected blocking implementations may build their own runtimes,
        // including while the caller constructs this runtime from an async task.
        let opened = std::thread::Builder::new()
            .name("l2tp-subscriptions".into())
            .spawn(move || -> std::io::Result<_> {
                let monitor = kernel.monitor()?;
                let l2tp = kernel.l2tp_events()?;
                Ok((kernel, monitor, l2tp))
            });
        let (kernel, monitor, l2tp) = match opened {
            Ok(thread) => match thread.join() {
                Ok(Ok(opened)) => opened,
                Ok(Err(error)) => return Err((error.into(), adopted)),
                Err(_) => {
                    return Err((
                        Error::Other("kernel subscription initializer panicked".into()),
                        adopted,
                    ));
                }
            },
            Err(error) => return Err((error.into(), adopted)),
        };
        let (tx, rx) = tokio::sync::mpsc::channel(QUEUE_CAPACITY);
        let shared = Arc::new(Shared {
            shutdown: AtomicBool::new(false),
            wake: tokio::sync::Notify::new(),
            loss: [AtomicBool::new(false), AtomicBool::new(false)],
            generation: AtomicU64::new(0),
            acceptance: Mutex::new(()),
            config: Mutex::new(Config::new()),
            requests: tokio::sync::Semaphore::new(QUEUE_CAPACITY),
            admitted: AtomicUsize::new(0),
        });
        let control = Control { tx, shared };
        let mut reconciler = Reconciler::new(kernel, resolver);
        for socket in adopted {
            let (name, fd) = socket.into_parts();
            reconciler.inherit(name, fd);
        }
        let mut tasks = Vec::new();
        for (i, mut feed) in [monitor, l2tp].into_iter().enumerate() {
            let control = control.clone();
            tasks.push(handle.spawn(async move {
                loop {
                    let notice = poll_fn(|cx| feed.poll_notice(cx)).await;
                    let source = if i == 0 {
                        Source::Monitor
                    } else {
                        Source::L2tp
                    };
                    let lost = matches!(notice, Notice::Loss);
                    if lost
                        || control
                            .tx
                            .try_send(ControlEvent::Kernel { source, notice })
                            .is_err()
                    {
                        if control.tx.is_closed() {
                            break;
                        }
                        control.shared.loss[i].store(true, Ordering::Release);
                        control.shared.wake.notify_one();
                    }
                    tokio::task::yield_now().await;
                }
            }));
        }
        Ok(Self {
            reconciler,
            control,
            rx,
            tasks,
            outgoing: VecDeque::new(),
            stopping: None,
        })
    }
    /// A handle for requests and host completions.
    pub fn control(&self) -> Control {
        self.control.clone()
    }
    /// Announces store capacity before reconciliation; zero means local ownership.
    /// Inherited names remain tracked at any capacity.
    pub fn set_store_capacity(&mut self, capacity: usize) {
        self.reconciler.set_store_capacity(capacity);
    }
    pub(crate) fn store_refused(&mut self, name: &str) {
        self.reconciler.store_refused(name);
    }
    /// Applies configuration; `true` means every requested change was applied.
    pub fn reconcile(&mut self, config: Config) -> bool {
        if self.stopping.is_some() || self.control.shared.shutdown.load(Ordering::Acquire) {
            return false;
        }
        let applied = self.reconciler.reconcile(config);
        *self.control.shared.config.lock().unwrap() = self.reconciler.accepted().clone();
        self.collect_requests();
        applied
    }
    /// Whether every eligible entry exists, regardless of connectivity.
    pub fn ready(&self) -> bool {
        self.reconciler.ready()
    }
    pub(crate) fn applied(&self) -> bool {
        self.reconciler.applied()
    }
    /// Entries omitted after the bounded conflict retry.
    pub fn left_out(&self) -> Vec<String> {
        self.reconciler.left_out()
    }
    /// Duplicates sockets without changing or tearing down any interface.
    pub fn restart_sockets(&self) -> Result<Vec<AdoptedSocket>> {
        Ok(self
            .reconciler
            .restart_sockets()?
            .into_iter()
            .map(|(name, fd)| AdoptedSocket::new(name, fd))
            .collect())
    }
    /// Prepares a wait on the owner thread, before entering `block_on`; only
    /// the returned future runs asynchronously. Persistent shutdown/loss is checked before dequeue;
    /// swapping each loss flag before resync preserves a concurrent second loss.
    pub fn next_event(&mut self) -> impl Future<Output = ControlEvent> + '_ {
        let now = self.reconciler.kernel().now();
        let deadline = if self.stopping.is_some() {
            self.stopping
                .into_iter()
                .chain(self.reconciler.shutdown_deadline())
                .min()
        } else {
            self.reconciler.next_deadline()
        };
        let wake_at =
            deadline.map(|deadline| Instant::now() + deadline.saturating_duration_since(now));
        self.wait_event(wake_at)
    }

    async fn wait_event(&mut self, wake_at: Option<Instant>) -> ControlEvent {
        let shared = self.control.shared.clone();
        loop {
            let notified = shared.wake.notified();
            let mut notified = pin!(notified);
            if self.stopping.is_none() && shared.shutdown.load(Ordering::Acquire) {
                return ControlEvent::Shutdown;
            }
            if let Some(event) = self.outgoing.pop_front() {
                return event;
            }
            for (i, source) in [Source::Monitor, Source::L2tp].into_iter().enumerate() {
                if shared.loss[i].swap(false, Ordering::AcqRel) {
                    return ControlEvent::Kernel {
                        source,
                        notice: Notice::Loss,
                    };
                }
            }
            // An always-ready receiver can complete block_on without polling
            // Tokio's timer driver. Due policy work must still make progress.
            if wake_at.is_some_and(|deadline| deadline <= Instant::now()) {
                return ControlEvent::Tick;
            }
            let mut timer = pin!(async {
                if let Some(deadline) = wake_at {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                } else {
                    std::future::pending::<()>().await;
                }
            });
            let event = poll_fn(|cx| {
                if notified.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
                if timer.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Some(ControlEvent::Tick));
                }
                self.rx
                    .poll_recv(cx)
                    .map(|event| Some(event.unwrap_or(ControlEvent::Shutdown)))
            })
            .await;
            if let Some(event) = event {
                return event;
            }
        }
    }
    /// Dispatches all variants. Host requests themselves are observations:
    /// forwarding never writes a tunable or speaks a descriptor-store protocol.
    pub fn handle_event(&mut self, event: ControlEvent) -> Result<()> {
        match event {
            ControlEvent::Kernel { source, notice } if self.stopping.is_none() => {
                self.reconciler.handle(source, notice)
            }
            ControlEvent::Tick | ControlEvent::ResolverAnswers if self.stopping.is_none() => {
                self.reconciler.tick()
            }
            ControlEvent::TunableWritten { id, success } if self.stopping.is_none() => {
                self.reconciler.tunable_written(id, success)
            }
            ControlEvent::SocketForgotten { id, processed } => {
                self.reconciler.socket_forgotten(id, processed)
            }
            ControlEvent::Shutdown => {
                self.control.shutdown();
                return self.shutdown().map(|_| ());
            }
            ControlEvent::Reload { .. } | ControlEvent::Restart => self.control.request_processed(),
            _ => {}
        }
        self.collect_requests();
        if self.stopping.is_some() {
            self.shutdown()?;
        }
        Ok(())
    }
    /// Performs an orderly shutdown step. While `Ok(false)`, keep forwarding
    /// events and calling this method. Withdrawal gets two seconds, followed by
    /// the separate two-second kernel deletion window. Residual references are
    /// reported as an error.
    pub fn shutdown(&mut self) -> Result<bool> {
        let now = self.reconciler.kernel().now();
        let deadline = *self.stopping.get_or_insert(now + Duration::from_secs(4));
        for event in std::mem::take(&mut self.outgoing) {
            match event {
                ControlEvent::StoreSocket { name, .. } => self.store_refused(&name),
                ControlEvent::WriteTunable { .. } => {}
                event => self.outgoing.push_back(event),
            }
        }
        let complete = self.reconciler.shutdown();
        *self.control.shared.config.lock().unwrap() = self.reconciler.accepted().clone();
        self.collect_requests();
        let deleted = self.reconciler.shutdown_deletions()?;
        if complete && deleted {
            Ok(true)
        } else if now >= deadline {
            Err(Error::Other(
                "kernel or descriptor-store cleanup incomplete".into(),
            ))
        } else {
            Ok(false)
        }
    }
    fn collect_requests(&mut self) {
        self.outgoing
            .extend(
                self.reconciler
                    .take_requests()
                    .into_iter()
                    .map(|request| match request {
                        Request::WriteBindv6only { id, deadline } => ControlEvent::WriteTunable {
                            name: "net.ipv6.bindv6only",
                            value: "0",
                            id,
                            deadline,
                        },
                        Request::StoreSocket {
                            name,
                            tunnel_id,
                            fd,
                        } => ControlEvent::StoreSocket {
                            name,
                            tunnel_id,
                            fd,
                        },
                        Request::ForgetSocket { name, id, deadline } => {
                            ControlEvent::ForgetSocket { name, id, deadline }
                        }
                    }),
            );
    }
}

impl<K: Kernel> Drop for Runtime<K> {
    fn drop(&mut self) {
        self.control.shared.requests.close();
        for task in &self.tasks {
            task.abort();
        }
    }
}
