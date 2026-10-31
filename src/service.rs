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

use std::collections::VecDeque;
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
    Reloaded {
        generation: u64,
        reload: Reload,
        result: Result<Result<Config>>,
    },
}

/// Internal service command, forwarded unchanged by event-loop embedders.
#[doc(hidden)]
pub struct Operation(Action);

/// A Tokio-facing service. Drop only requests shutdown; it does not wait for
/// cleanup. Shut down through `run` to await cleanup and observe failures while
/// the caller's runtime continues draining subscriptions and host requests.
/// Callbacks must own their captured data.
pub struct Service {
    control: Control,
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

    pub(crate) async fn shutdown_and_wait(&mut self) -> Result<()> {
        self.control.shutdown();
        if let Some(completion) = self.completion.take() {
            completion
                .await
                .map_err(|_| Error::Other("service stopped".into()))?
        } else {
            Ok(())
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.control.shutdown();
    }
}

fn host_request<K: Kernel + 'static>(
    runtime: &mut Runtime<K>,
    event: ControlEvent,
    host: &tokio::sync::mpsc::Sender<ControlEvent>,
    forward: bool,
) {
    if forward {
        if let Err(error) = host.try_send(event) {
            match error.into_inner() {
                ControlEvent::StoreSocket { name, .. } => runtime.store_refused(&name),
                _ => log::warn!(
                    "host request receiver unavailable; handshake deadline remains in force"
                ),
            }
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
            ControlEvent::StoreSocket { name, .. } => {
                runtime.store_refused(&name);
                return;
            }
            _ => return,
        };
        let _ = runtime.handle_event(answer);
    }
}

enum OperatorRequest {
    Reload(u64),
    Restart,
}

struct Callbacks {
    reload: Option<Reload>,
    restart: Restart,
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
    let mut convergence_generation = 0;
    let mut convergence: Option<tokio::sync::oneshot::Sender<Result<Vec<String>>>> = None;
    let mut serving: Option<Callbacks> = None;
    let mut in_flight = None;
    let mut reload_pending = false;
    // Admission slots stay reserved until processing, bounding this deferral
    // queue as well as preserving every accepted restart's position.
    let mut pending = VecDeque::new();
    let mut poll_background = false;
    let callback_panicked = Arc::new(AtomicBool::new(false));
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
            // Ignore reloads accepted during convergence even if a kernel
            // operation kept them queued until after readiness.
            convergence_generation = control.shared.generation.load(Ordering::Acquire);
            if let Some(tx) = convergence.take() {
                let _ = tx.send(Ok(runtime.left_out()));
            }
        }
        if reload_pending && runtime.applied() && !control.shared.shutdown.load(Ordering::Acquire) {
            log::info!("reload completed");
            reload_pending = false;
        }
        let pending_ready = converged
            && in_flight.is_none()
            && serving.is_some()
            && !pending.is_empty()
            && !control.shared.shutdown.load(Ordering::Acquire);
        if !poll_background
            && pending_ready
            && in_flight.is_none()
            && !control.shared.shutdown.load(Ordering::Acquire)
            && let Some(callbacks) = serving.as_mut()
            && let Some(request) = pending.pop_front()
        {
            match request {
                OperatorRequest::Reload(generation) => {
                    if generation != control.shared.generation.load(Ordering::Acquire) {
                        control.request_processed();
                        continue;
                    }
                    let mut reload = callbacks.reload.take().unwrap();
                    let accepted = control.config();
                    let returned = control.clone();
                    let panicked = callback_panicked.clone();
                    let spawned = std::thread::Builder::new()
                        .name("l2tp-reload".into())
                        .spawn(move || {
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    reload(accepted)
                                }))
                                .map_err(|_| Error::ReloadPanicked);
                            // A completion queued during shutdown may not be
                            // dequeued before cleanup ends. Preserve its panic.
                            if result.is_err() {
                                panicked.store(true, Ordering::Release);
                                returned.shutdown();
                            }
                            let _ = returned.tx.blocking_send(ControlEvent::Service(Operation(
                                Action::Reloaded {
                                    generation,
                                    reload,
                                    result,
                                },
                            )));
                        });
                    match spawned {
                        Ok(_) => in_flight = Some(generation),
                        Err(error) => {
                            control.request_processed();
                            failure = Some(error.into());
                            control.shutdown();
                        }
                    }
                }
                OperatorRequest::Restart => {
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        runtime.restart_sockets().and_then(&mut callbacks.restart)
                    }));
                    match outcome {
                        Ok(Ok(())) => log::warn!("restart callback returned; resuming"),
                        Ok(Err(error)) => log::warn!("restart failed; resuming: {error}"),
                        Err(_) => {
                            failure = Some(Error::RestartPanicked);
                            control.shutdown();
                        }
                    }
                    control.request_processed();
                }
            }
            poll_background = true;
            continue;
        }
        // Interleave policy and host work with deferred operator requests;
        // neither a full input queue nor a long restart backlog may starve the other.
        let event = if pending_ready {
            let mut next = pin!(runtime.next_event());
            engine.block_on(poll_fn(|cx| {
                Poll::Ready(match next.as_mut().poll(cx) {
                    Poll::Ready(event) => Some(event),
                    Poll::Pending => None,
                })
            }))
        } else {
            Some(engine.block_on(runtime.next_event()))
        };
        poll_background = false;
        let Some(event) = event else {
            continue;
        };
        match event {
            ControlEvent::Service(Operation(Action::Reloaded {
                generation,
                reload,
                result,
            })) => {
                in_flight = None;
                control.request_processed();
                if let Some(callbacks) = serving.as_mut() {
                    callbacks.reload = Some(reload);
                }
                match result {
                    Err(error) => {
                        failure = Some(error);
                        control.shutdown();
                    }
                    Ok(Err(error)) => {
                        log::error!("reload failed; retaining accepted configuration: {error}")
                    }
                    Ok(Ok(config))
                        if !control.shared.shutdown.load(Ordering::Acquire)
                            && generation == control.shared.generation.load(Ordering::Acquire) =>
                    {
                        runtime.reconcile(config);
                        reload_pending = true;
                    }
                    _ => {}
                }
            }
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
                        serving = Some(Callbacks {
                            reload: Some(reload),
                            restart,
                        });
                    }
                    Action::Reloaded { .. } => unreachable!("handled above"),
                }
                if !started {
                    runtime.reconcile(config.clone());
                    started = true;
                }
            }
            ControlEvent::Reload { generation }
                if converged
                    && generation > convergence_generation
                    && !control.shared.shutdown.load(Ordering::Acquire) =>
            {
                pending.retain(|request| {
                    if matches!(request, OperatorRequest::Reload(_)) {
                        control.request_processed();
                        false
                    } else {
                        true
                    }
                });
                pending.push_back(OperatorRequest::Reload(generation));
            }
            ControlEvent::Restart if !control.shared.shutdown.load(Ordering::Acquire) => {
                pending.push_back(OperatorRequest::Restart);
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
    if callback_panicked.load(Ordering::Acquire) {
        return Err(Error::ReloadPanicked);
    }
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::config::{Family, TunnelConfig};
    use crate::kernel::fake::FakeKernel;
    use crate::reconciler::IphostResolve;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Waker};

    fn engine() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }
    fn config() -> Config {
        let mut config = Config::new();
        config
            .insert_tunnel(
                "a",
                TunnelConfig::builder(10)
                    .ip_version(Family::V6)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        config
    }
    fn runtime(adopted: Vec<AdoptedSocket>) -> Runtime<FakeKernel> {
        Runtime::with_kernel(
            FakeKernel::new(42),
            Box::new(IphostResolve::default()),
            adopted,
        )
        .map_err(|(error, _)| error)
        .unwrap()
    }

    /// spec: L5, L7, L9, G14
    #[test]
    fn abandoned_replies_report_stopped_service_and_shutdown_releases_waiters() {
        engine().block_on(async {
            for shutdown in [false, true] {
                let mut runtime = runtime(vec![]);
                let mut service = Service {
                    control: runtime.control(),
                    requests: None,
                    forward: Arc::new(AtomicBool::new(false)),
                    completion: None,
                };
                let mut converge = pin!(service.converge());
                assert!(converge.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
                let event = runtime.next_event().await;
                assert!(matches!(event, ControlEvent::Service(Operation(Action::Converge(_)))));
                if shutdown { runtime.control().shutdown(); }
                drop(event);
                let result = converge.await;
                if shutdown {
                    assert!(result.unwrap().is_empty());
                } else {
                    assert!(matches!(result, Err(Error::Other(message)) if message == "service stopped"));
                }
            }
            let mut runtime = runtime(vec![]);
            let mut service = Service {
                control: runtime.control(),
                requests: None,
                forward: Arc::new(AtomicBool::new(false)),
                completion: None,
            };
            {
                let mut capacity = pin!(service.set_store_capacity(3));
                assert!(capacity.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
                let event = runtime.next_event().await;
                assert!(matches!(event, ControlEvent::Service(Operation(Action::StoreCapacity(3, _)))));
                drop(event);
                assert!(matches!(capacity.await, Err(Error::Other(message)) if message == "service stopped"));
            }
            let (tx, rx) = tokio::sync::oneshot::channel();
            drop(tx);
            service.completion = Some(rx);
            assert!(matches!(service.run(Ok, |_| Ok(())).await, Err(Error::Other(message)) if message == "service stopped"));
            assert!(matches!(service.run(Ok, |_| Ok(())).await, Err(Error::Other(message)) if message == "run already completed"));
            let (tx, rx) = tokio::sync::oneshot::channel();
            drop(tx);
            service.completion = Some(rx);
            assert!(matches!(service.shutdown_and_wait().await, Err(Error::Other(message)) if message == "service stopped"));
            assert!(service.shutdown_and_wait().await.is_ok());
        });
    }

    /// spec: L13
    #[test]
    fn refused_host_delivery_releases_capacity_and_needs_no_withdrawal() {
        engine().block_on(async {
            for unavailable in ["full", "closed", "disabled"] {
                let mut runtime = runtime(vec![]);
                runtime.set_store_capacity(1);
                let (host, mut receiver) = tokio::sync::mpsc::channel(1);
                if unavailable == "full" {
                    assert!(host.try_send(ControlEvent::Tick).is_ok());
                }
                if unavailable == "closed" {
                    receiver.close();
                }
                runtime.reconcile(config());
                let event = runtime.next_event().await;
                assert!(matches!(
                    event,
                    ControlEvent::StoreSocket { tunnel_id: 10, .. }
                ));
                host_request(&mut runtime, event, &host, unavailable != "disabled");
                assert!(runtime.ready(), "storage must not gate readiness");

                let mut wanted = config();
                wanted
                    .insert_tunnel(
                        "b",
                        TunnelConfig::builder(20)
                            .ip_version(Family::V6)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                runtime.reconcile(wanted);
                let event = runtime.next_event().await;
                assert!(
                    matches!(event, ControlEvent::StoreSocket { tunnel_id: 20, .. }),
                    "refusal must release the capacity slot"
                );
                host_request(&mut runtime, event, &host, unavailable != "disabled");
                assert!(!runtime.shutdown().unwrap()); // asynchronous kernel close
                let mut next = pin!(runtime.next_event());
                assert!(
                    next.as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending(),
                    "a refused submission must not emit ForgetSocket"
                );
            }
        });
    }

    /// spec: L5, L7, G14
    #[test]
    fn run_without_a_convergence_waiter_reaches_readiness_before_restart() {
        engine().block_on(async {
            let mut wanted = Config::new();
            wanted.set_host(crate::config::HostConfig::new().with_fix_bindv6only(false));
            let mut service = Service::with_runtime(wanted, runtime(vec![]))
                .map_err(|(error, _)| error)
                .unwrap();
            let control = service.control();
            let stopped = control.clone();
            let called = Arc::new(AtomicBool::new(false));
            let observed = called.clone();
            let mut running = pin!(service.run(Ok, move |sockets| {
                assert!(sockets.is_empty());
                assert!(!stopped.config().host().fix_bindv6only());
                observed.store(true, Ordering::Release);
                stopped.shutdown();
                Ok(())
            }));
            assert!(
                running
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            control.send(ControlEvent::Restart).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), running)
                .await
                .unwrap()
                .unwrap();
            assert!(called.load(Ordering::Acquire));
        });
    }

    /// spec: L7
    #[test]
    fn panic_completion_during_shutdown_is_reported_after_cleanup() {
        engine().block_on(async {
            let (fd, _) = std::os::unix::net::UnixStream::pair().unwrap();
            let mut runtime = runtime(vec![AdoptedSocket::new("malformed", fd.into())]);
            runtime.set_store_capacity(1);
            let mut service = Service::with_runtime(Config::new(), runtime)
                .map_err(|(error, _)| error)
                .unwrap();
            let mut requests = service.take_requests().unwrap();
            service.converge().await.unwrap();
            let ControlEvent::ForgetSocket { id, .. } = requests.recv().await.unwrap() else {
                panic!("expected withdrawal")
            };
            let control = service.control();
            control.shutdown();
            // The callback result arrives after shutdown began, while cleanup
            // waits for a processing acknowledgement. It must not be discarded.
            control
                .send(ControlEvent::Service(Operation(Action::Reloaded {
                    generation: 1,
                    reload: Box::new(Ok),
                    result: Err(Error::ReloadPanicked),
                })))
                .await
                .unwrap();
            control.socket_forgotten(id, true).await.unwrap();
            assert!(matches!(
                service.run(Ok, |_| Ok(())).await,
                Err(Error::ReloadPanicked)
            ));
            assert_eq!(control.config(), Config::new());
        });
    }
}
