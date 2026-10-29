//! Tokio service (L5–L7). Subscriptions use the caller's runtime; synchronous
//! reconciliation runs on a dedicated thread.
//!
//! ```no_run
//! # async fn example() -> rs_l2tpd::Result<()> {
//! use rs_l2tpd::{config::Config, service::Service};
//! let mut service = Service::new(Config::new(), vec![]).map_err(|(e, _)| e)?;
//! service.converge().await?;
//! let control = service.control();
//! // A signal adapter or another task can use this handle.
//! control.shutdown();
//! service.run(Ok, |_| Ok(())).await?;
//! # Ok(()) }
//! ```

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

pub use crate::runtime::{AdoptedSocket, Control, ControlEvent, Receiver, StartResult};

use crate::config::Config;
use crate::kernel::Kernel;
use crate::runtime::{QUEUE_CAPACITY, Runtime};
use crate::{Error, Result};

type Reload = Box<dyn FnMut(Config) -> Result<Config> + Send>;
type Restart = Box<dyn FnMut(Vec<AdoptedSocket>) -> Result<()> + Send>;

enum Action {
    Converge(tokio::sync::oneshot::Sender<Result<Vec<String>>>),
    Run(Reload, Restart),
    StoreCapacity(usize, tokio::sync::oneshot::Sender<Result<()>>),
}

/// Internal service command, forwarded unchanged by event-loop embedders.
#[doc(hidden)]
pub struct Operation(Action);

/// A Tokio-facing service. Dropping requests shutdown and joins the owner;
/// explicit `run` reports cleanup errors. Callbacks must own their captured data.
pub struct Service {
    control: Control,
    thread: Option<std::thread::JoinHandle<()>>,
    requests: Option<Receiver<ControlEvent>>,
    forward: Arc<AtomicBool>,
    completion: Option<tokio::sync::oneshot::Receiver<Result<()>>>,
}

impl Service {
    /// Opens all kernel interfaces immediately; no startup retry is hidden.
    pub fn new(config: Config, adopted: Vec<AdoptedSocket>) -> StartResult<Self> {
        Self::with_runtime(config, Runtime::new(adopted)?)
    }

    /// Uses an opened runtime, including a fake kernel. Set its store capacity
    /// before passing it here.
    pub fn with_runtime<K: Kernel + 'static>(
        config: Config,
        runtime: Runtime<K>,
    ) -> StartResult<Self> {
        let control = runtime.control();
        let (host_tx, host_rx) = tokio::sync::mpsc::channel(QUEUE_CAPACITY);
        let forward = Arc::new(AtomicBool::new(false));
        // Retain startup ownership outside the closure until spawning succeeds.
        let slot = Arc::new(Mutex::new(Some(runtime)));
        let worker_slot = slot.clone();
        let worker_forward = forward.clone();
        let (complete_tx, complete_rx) = tokio::sync::oneshot::channel();
        let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
        let thread = match std::thread::Builder::new()
            .name("l2tp-reconciler".into())
            .spawn(move || {
                let engine = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(engine) => engine,
                    Err(error) => {
                        let _ = startup_tx.send(Err(Error::from(error)));
                        return;
                    }
                };
                let runtime = worker_slot.lock().unwrap().take().unwrap();
                let _ = startup_tx.send(Ok(()));
                let result = worker(engine, runtime, config, host_tx, worker_forward);
                let _ = complete_tx.send(result);
            }) {
            Ok(thread) => thread,
            Err(error) => {
                return Err((
                    error.into(),
                    slot.lock().unwrap().take().unwrap().into_adopted(),
                ));
            }
        };
        if let Err(error) = startup_rx
            .recv()
            .unwrap_or_else(|error| Err(Error::Other(error.to_string())))
        {
            let _ = thread.join();
            let adopted = slot
                .lock()
                .unwrap()
                .take()
                .map(Runtime::into_adopted)
                .unwrap_or_default();
            return Err((error, adopted));
        }
        Ok(Self {
            control,
            thread: Some(thread),
            requests: Some(host_rx),
            forward,
            completion: Some(complete_rx),
        })
    }

    /// A cloneable handle usable from any thread.
    pub fn control(&self) -> Control {
        self.control.clone()
    }

    /// Announces optional descriptor-store capacity before convergence.
    pub async fn set_store_capacity(&mut self, capacity: usize) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.control
            .send(ControlEvent::Service(Operation(Action::StoreCapacity(
                capacity, tx,
            ))))
            .await?;
        rx.await
            .map_err(|_| Error::Other("service stopped".into()))?
    }

    /// Enables host integration, once, before convergence. Drain this bounded
    /// receiver and answer tunable/withdrawal requests through `Control`.
    /// Without it tunable writes are refused and a nonexistent store is
    /// acknowledged immediately. A full receiver reports unavailable storage;
    /// handshake deadlines still bound cleanup.
    pub fn take_requests(&mut self) -> Option<Receiver<ControlEvent>> {
        let requests = self.requests.take();
        if requests.is_some() {
            self.forward.store(true, Ordering::Release);
        }
        requests
    }

    /// Waits until every eligible object exists, handling events but ignoring
    /// reload requests. Shutdown also releases this wait.
    pub async fn converge(&mut self) -> Result<Vec<String>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self
            .control
            .send(ControlEvent::Service(Operation(Action::Converge(tx))))
            .await
            .is_err()
            && self.control.shared.shutdown.load(Ordering::Acquire)
        {
            return Ok(vec![]);
        }
        match rx.await {
            Ok(result) => result,
            Err(_) if self.control.shared.shutdown.load(Ordering::Acquire) => Ok(vec![]),
            Err(_) => Err(Error::Other("service stopped".into())),
        }
    }

    /// Converges if needed, then serves requests until shutdown. Reloads run
    /// off-thread; a blocked callback never holds up shutdown. Restart receives
    /// duplicate tunnel descriptors and resumes normal operation if it returns.
    pub async fn run(
        &mut self,
        reload: impl FnMut(Config) -> Result<Config> + Send + 'static,
        restart: impl FnMut(Vec<AdoptedSocket>) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        let rx = self
            .completion
            .take()
            .ok_or_else(|| Error::Other("run already completed".into()))?;
        let _ = self
            .control
            .send(ControlEvent::Service(Operation(Action::Run(
                Box::new(reload),
                Box::new(restart),
            ))))
            .await;
        rx.await
            .map_err(|_| Error::Other("service stopped".into()))?
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.control.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn host_request<K: Kernel + 'static>(
    runtime: &mut Runtime<K>,
    event: ControlEvent,
    host: &tokio::sync::mpsc::Sender<ControlEvent>,
    forward: bool,
) {
    if forward {
        if host.try_send(event).is_err() {
            log::warn!("host request receiver unavailable; handshake deadline remains in force");
        }
    } else {
        let answer = match event {
            ControlEvent::WriteTunable { id, .. } => {
                ControlEvent::TunableWritten { id, success: false }
            }
            ControlEvent::ForgetSocket { id, .. } => ControlEvent::SocketForgotten {
                id,
                processed: true,
            },
            _ => return,
        };
        let _ = runtime.handle_event(answer);
    }
}

fn worker<K: Kernel + 'static>(
    engine: tokio::runtime::Runtime,
    mut runtime: Runtime<K>,
    config: Config,
    host: tokio::sync::mpsc::Sender<ControlEvent>,
    forward: Arc<AtomicBool>,
) -> Result<()> {
    let control = runtime.control();
    let mut started = false;
    let mut converged = false;
    let mut convergence: Option<tokio::sync::oneshot::Sender<Result<Vec<String>>>> = None;
    let mut serving: Option<(Reload, Restart)> = None;
    let mut failure = None;
    loop {
        if control.shared.shutdown.load(Ordering::Acquire) {
            match runtime.shutdown() {
                Ok(true) => break,
                Err(error) => {
                    failure.get_or_insert(error);
                    break;
                }
                Ok(false) => {}
            }
        }
        if started && !converged && runtime.ready() {
            converged = true;
            if let Some(tx) = convergence.take() {
                let _ = tx.send(Ok(runtime.left_out()));
            }
        }
        let event = engine.block_on(runtime.next_event());
        match event {
            ControlEvent::Service(Operation(action))
                if !control.shared.shutdown.load(Ordering::Acquire) =>
            {
                match action {
                    Action::StoreCapacity(capacity, tx) => {
                        let result = if started {
                            Err(Error::Other("set store capacity before convergence".into()))
                        } else {
                            runtime.set_store_capacity(capacity);
                            Ok(())
                        };
                        let _ = tx.send(result);
                        continue;
                    }
                    Action::Converge(tx) => {
                        if converged {
                            let _ = tx.send(Ok(runtime.left_out()));
                        } else {
                            convergence = Some(tx);
                        }
                    }
                    Action::Run(reload, restart) => {
                        serving = Some((reload, restart));
                    }
                }
                if !started {
                    runtime.reconcile(config.clone());
                    started = true;
                }
            }
            ControlEvent::Reload { generation }
                if converged
                    && serving.is_some()
                    && !control.shared.shutdown.load(Ordering::Acquire) =>
            {
                if generation != control.shared.generation.load(Ordering::Acquire) {
                    continue;
                }
                let (mut reload, restart) = serving.take().unwrap();
                let accepted = control.config();
                let (answer_tx, mut answer_rx) = tokio::sync::oneshot::channel();
                let spawned = std::thread::Builder::new()
                    .name("l2tp-reload".into())
                    .spawn(move || {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            reload(accepted)
                        }));
                        let _ = answer_tx.send((reload, result));
                    });
                if let Err(error) = spawned {
                    failure = Some(error.into());
                    serving = Some((Box::new(Ok), restart));
                    control.shutdown();
                    continue;
                }
                let answer = engine.block_on(async {
                    let mut cancelled = pin!(control.cancelled());
                    poll_fn(|cx| {
                        if cancelled.as_mut().poll(cx).is_ready() {
                            return Poll::Ready(None);
                        }
                        std::pin::Pin::new(&mut answer_rx).poll(cx).map(Some)
                    })
                    .await
                });
                match answer {
                    Some(Ok((reload, result))) => {
                        serving = Some((reload, restart));
                        match result {
                            Err(_) => {
                                failure = Some(Error::ReloadPanicked);
                                control.shutdown();
                            }
                            Ok(Err(error)) => log::error!(
                                "reload failed; retaining accepted configuration: {error}"
                            ),
                            Ok(Ok(config))
                                if generation
                                    == control.shared.generation.load(Ordering::Acquire) =>
                            {
                                runtime.reconcile(config);
                            }
                            _ => {}
                        }
                    }
                    _ => {
                        serving = Some((Box::new(Ok), restart));
                        control.shutdown();
                    }
                }
            }
            ControlEvent::Restart
                if converged
                    && serving.is_some()
                    && !control.shared.shutdown.load(Ordering::Acquire) =>
            {
                let (_, restart) = serving.as_mut().unwrap();
                match runtime.restart_sockets().and_then(restart) {
                    Ok(()) => log::warn!("restart callback returned; resuming"),
                    Err(error) => log::warn!("restart failed; resuming: {error}"),
                }
            }
            event @ (ControlEvent::WriteTunable { .. }
            | ControlEvent::StoreSocket { .. }
            | ControlEvent::ForgetSocket { .. }) => {
                host_request(&mut runtime, event, &host, forward.load(Ordering::Acquire));
            }
            event => {
                if let Err(error) = runtime.handle_event(event) {
                    failure.get_or_insert(error);
                    control.shutdown();
                }
            }
        }
    }
    if let Some(tx) = convergence {
        let _ = tx.send(Ok(runtime.left_out()));
    }
    failure.map_or(Ok(()), Err)
}
