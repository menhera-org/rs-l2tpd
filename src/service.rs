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
        if let Err(error) = startup(startup_rx).and_then(std::convert::identity) {
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

pub(crate) fn startup<T>(receiver: std::sync::mpsc::Receiver<T>) -> Result<T> {
    receiver
        .recv()
        .map_err(|error| Error::Other(error.to_string()))
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
        if !poll_background
            && converged
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
        let pending_ready = converged
            && in_flight.is_none()
            && serving.is_some()
            && !pending.is_empty()
            && !control.shared.shutdown.load(Ordering::Acquire);
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
            ControlEvent::Service(Operation(Action::StoreCapacity(capacity, tx)))
                if !control.shared.shutdown.load(Ordering::Acquire) =>
            {
                let result = if started {
                    Err(Error::Other("set store capacity before convergence".into()))
                } else {
                    runtime.set_store_capacity(capacity);
                    Ok(())
                };
                let _ = tx.send(result);
            }
            ControlEvent::Service(Operation(Action::Converge(tx)))
                if !control.shared.shutdown.load(Ordering::Acquire) =>
            {
                if converged {
                    let _ = tx.send(Ok(runtime.left_out()));
                } else {
                    convergence = Some(tx);
                }
                if !started {
                    runtime.reconcile(config.clone());
                    started = true;
                }
            }
            ControlEvent::Service(Operation(Action::Run(reload, restart)))
                if !control.shared.shutdown.load(Ordering::Acquire) =>
            {
                serving = Some(Callbacks {
                    reload: Some(reload),
                    restart,
                });
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

    /// spec: L8, L9, G14
    #[test]
    fn a_closed_startup_channel_returns_the_receive_error() {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<()>(1);
        drop(sender);
        assert!(matches!(startup(receiver), Err(Error::Other(message))
            if message == std::sync::mpsc::RecvError.to_string()));
    }

    /// spec: L5, L7, L9, G14
    #[test]
    fn a_closed_command_queue_reports_failure_until_shutdown_is_requested() {
        engine().block_on(async {
            for shutdown in [false, true] {
                let runtime = runtime(vec![]);
                let mut control = runtime.control();
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                drop(rx);
                control.tx = tx;
                if shutdown {
                    control.shutdown();
                }
                let mut service = Service {
                    control,
                    requests: None,
                    forward: Arc::new(AtomicBool::new(false)),
                    completion: None,
                };
                let result = service.converge().await;
                if shutdown {
                    assert!(result.unwrap().is_empty());
                } else {
                    assert!(
                        matches!(result, Err(Error::Other(message)) if message == "service stopped")
                    );
                }
            }
        });
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

    /// spec: L7, L10, M4, G20
    #[test]
    fn reload_completions_during_shutdown_preserve_cleanup_and_configuration() {
        engine().block_on(async {
            for result in [
                Err(Error::ReloadPanicked),
                Ok(Err(Error::Other("controlled reload refusal".into()))),
                Ok(Ok(config())),
            ] {
                let panicked = result.is_err();
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
                control
                    .send(ControlEvent::Service(Operation(Action::Reloaded {
                        generation: 1,
                        reload: Box::new(Ok),
                        result,
                    })))
                    .await
                    .unwrap();
                control.socket_forgotten(id, true).await.unwrap();
                let result = service.run(Ok, |_| Ok(())).await;
                if panicked {
                    assert!(matches!(result, Err(Error::ReloadPanicked)));
                } else {
                    result.unwrap();
                }
                assert_eq!(control.config(), Config::new());
            }
        });
    }

    /// spec: L5, L6, L9, L13, G20
    #[test]
    fn shutdown_between_dequeue_and_dispatch_cancels_queued_service_commands() {
        struct NoLookup;
        impl crate::reconciler::Resolve for NoLookup {
            fn watch(&mut self, _: crate::reconciler::Lookup) -> std::io::Result<()> {
                panic!("shutdown command started DNS work");
            }
            fn unwatch(&mut self, _: u64) {}
            fn poll(&mut self) -> Vec<(u64, Vec<std::net::IpAddr>)> {
                vec![]
            }
        }
        struct StopOnWake(Control, AtomicBool);
        impl std::task::Wake for StopOnWake {
            fn wake(self: Arc<Self>) {
                self.1.store(true, Ordering::Release);
                self.0.shutdown();
            }
        }
        for case in ["capacity", "converge", "run"] {
            let engine = engine();
            let runtime = {
                let _entered = engine.enter();
                Runtime::with_kernel(FakeKernel::new(42), Box::new(NoLookup), vec![])
                    .map_err(|(error, _)| error)
                    .unwrap()
            };
            let control = runtime.control();
            let (capacity, mut capacity_reply) = tokio::sync::oneshot::channel();
            let (convergence, mut convergence_reply) = tokio::sync::oneshot::channel();
            let command = match case {
                "capacity" => Action::StoreCapacity(1, capacity),
                "converge" => Action::Converge(convergence),
                "run" => Action::Run(Box::new(Ok), Box::new(|_| Ok(()))),
                _ => unreachable!(),
            };
            assert!(
                control
                    .tx
                    .try_send(ControlEvent::Service(Operation(command)))
                    .is_ok()
            );
            for _ in 1..QUEUE_CAPACITY {
                assert!(control.tx.try_send(ControlEvent::Tick).is_ok());
            }
            let stop = Arc::new(StopOnWake(control.clone(), AtomicBool::new(false)));
            let waker = Waker::from(stop.clone());
            let mut waiting = pin!(control.send(ControlEvent::Tick));
            assert!(
                waiting
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            assert!(!stop.1.load(Ordering::Acquire));
            let mut wanted = Config::new();
            wanted.set_host(crate::config::HostConfig::new().with_fix_bindv6only(false));
            wanted
                .insert_tunnel(
                    "a",
                    TunnelConfig::builder(10)
                        .ip_version(Family::V6)
                        .remote_addr(crate::config::RemoteAddr::Host("peer.example".into()))
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let (host, _requests) = tokio::sync::mpsc::channel(1);
            worker(
                engine,
                runtime,
                wanted,
                host,
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
            assert!(
                stop.1.load(Ordering::Acquire),
                "dequeue did not wake the blocked sender"
            );
            assert_eq!(control.config(), Config::new());
            match case {
                "capacity" => assert!(matches!(
                    capacity_reply.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Closed)
                )),
                "converge" => assert!(matches!(
                    convergence_reply.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Closed)
                )),
                "run" => {}
                _ => unreachable!(),
            }
        }
    }

    /// spec: L5, L8, L13, P14
    #[test]
    fn store_capacity_is_acknowledged_only_before_convergence() {
        engine().block_on(async {
            let mut service = Service::with_runtime(Config::new(), runtime(vec![]))
                .map_err(|(error, _)| error)
                .unwrap();
            service.set_store_capacity(1).await.unwrap();
            assert!(service.converge().await.unwrap().is_empty());
            assert!(matches!(service.set_store_capacity(2).await,
                Err(Error::Other(message)) if message == "set store capacity before convergence"));
            service.shutdown_and_wait().await.unwrap();
        });
    }

    /// spec: L7, L10, A15, E24, G23
    #[test]
    fn superseded_deferred_reload_returns_its_admission_slot() {
        engine().block_on(async {
            let mut wanted = Config::new();
            wanted.set_host(crate::config::HostConfig::new().with_fix_bindv6only(false));
            let mut service = Service::with_runtime(wanted, runtime(vec![]))
                .map_err(|(error, _)| error)
                .unwrap();
            service.converge().await.unwrap();
            let control = service.control();
            control.restart().unwrap();
            control.reload().unwrap();
            control.restart().unwrap();
            let requests = control.clone();
            let called = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = called.clone();
            let reloads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let reloaded = reloads.clone();
            let stop = control.clone();
            let running = service.run(
                move |config| {
                    assert_eq!(reloaded.fetch_add(1, Ordering::AcqRel), 0);
                    assert!(!config.host().fix_bindv6only());
                    stop.shutdown();
                    Ok(config)
                },
                move |sockets| {
                    assert!(sockets.is_empty());
                    match observed.fetch_add(1, Ordering::AcqRel) {
                        0 => {
                            // One background event precedes the newer, accepted reload.
                            assert!(requests.tx.try_send(ControlEvent::Tick).is_ok());
                            requests.reload().unwrap();
                        }
                        1 => {
                            // This restart and the newer reload still hold slots.
                            for _ in 2..QUEUE_CAPACITY {
                                requests.restart().unwrap();
                            }
                            assert!(requests.restart().is_err());
                        }
                        _ => panic!("restart after shutdown"),
                    }
                    Ok(())
                },
            );
            tokio::time::timeout(std::time::Duration::from_secs(5), running)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(called.load(Ordering::Acquire), 2);
            assert_eq!(reloads.load(Ordering::Acquire), 1);
        });
    }

    /// spec: L7, L10, A15, E24, G14
    #[test]
    fn ready_background_failure_precedes_the_next_deferred_restart() {
        engine().block_on(async {
            let mut wanted = Config::new();
            wanted.set_host(crate::config::HostConfig::new().with_fix_bindv6only(false));
            let mut service = Service::with_runtime(wanted, runtime(vec![]))
                .map_err(|(error, _)| error)
                .unwrap();
            service.converge().await.unwrap();
            let control = service.control();
            control.restart().unwrap();
            control.restart().unwrap();
            let called = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = called.clone();
            let running = service.run(Ok, move |sockets| {
                assert!(sockets.is_empty());
                assert_eq!(observed.fetch_add(1, Ordering::AcqRel), 0);
                assert!(
                    control
                        .tx
                        .try_send(ControlEvent::Failed(Error::Other(
                            "background fixture failed".into()
                        )))
                        .is_ok()
                );
                Ok(())
            });
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), running)
                .await
                .unwrap();
            assert!(matches!(result, Err(Error::Other(message))
                if message == "background fixture failed"));
            assert_eq!(called.load(Ordering::Acquire), 1);
        });
    }

    /// spec: L13, P14, G20
    #[test]
    fn unforwarded_withdrawal_completes_the_manager_barrier() {
        engine().block_on(async {
            let (fd, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
            let mut runtime = runtime(vec![AdoptedSocket::new("invalid inherited name", fd.into())]);
            runtime.set_store_capacity(1);
            runtime.reconcile(Config::new());
            let event = tokio::time::timeout(std::time::Duration::from_secs(1), runtime.next_event()).await.unwrap();
            assert!(matches!(&event, ControlEvent::ForgetSocket { name, .. } if name == "invalid inherited name"));
            let (host, mut receiver) = tokio::sync::mpsc::channel(1);
            host_request(&mut runtime, event, &host, false);
            assert!(matches!(receiver.try_recv(), Err(tokio::sync::mpsc::error::TryRecvError::Empty)));
            assert!(runtime.shutdown().unwrap(), "the disabled host must complete its withdrawal barrier");
        });
    }

    /// spec: L12, G14, T26
    #[test]
    fn lost_host_delivery_waits_for_the_original_tunable_completion() {
        engine().block_on(async {
            for closed in [false, true] {
                let mut kernel = FakeKernel::new(42);
                kernel.bindv6only = true;
                let began = kernel.now();
                let mut runtime = Runtime::with_kernel(
                    kernel,
                    Box::new(IphostResolve::default()),
                    vec![],
                )
                .map_err(|(error, _)| error)
                .unwrap();
                let wanted = config();
                assert!(!runtime.reconcile(wanted.clone()));
                let event = runtime.next_event().await;
                let ControlEvent::WriteTunable { id, deadline, .. } = &event else {
                    panic!("expected the original tunable handshake");
                };
                let id = *id;
                assert_eq!(*deadline - began, std::time::Duration::from_secs(5));
                let (host, mut receiver) = tokio::sync::mpsc::channel(1);
                if closed {
                    receiver.close();
                } else {
                    assert!(host.try_send(ControlEvent::Tick).is_ok());
                }
                host_request(&mut runtime, event, &host, true);
                assert!(!runtime.ready(), "lost delivery must not complete the handshake");
                {
                    let mut next = pin!(runtime.next_event());
                    assert!(next.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
                }
                host_request(&mut runtime, ControlEvent::Shutdown, &host, false);
                assert_eq!(runtime.control().config(), wanted, "an unrelated host event must be ignored");
                runtime.control().tunable_written(id, false).await.unwrap();
                let event = runtime.next_event().await;
                assert!(matches!(event, ControlEvent::TunableWritten { id: received, success: false } if received == id));
                runtime.handle_event(event).unwrap();
                assert!(runtime.ready(), "the original completion must still enable fallback");
            }
        });
    }
}
