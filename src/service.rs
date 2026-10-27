//! The daemon without its process management: apply a configuration, keep
//! it applied, reload on request and shut down on request.
//!
//! [`Service`] is asynchronous and must be created and driven inside a Tokio
//! runtime. [`crate::blocking::Service`] wraps it for programs that do not
//! use Tokio. Neither does any I/O beyond the kernel interfaces: the
//! configuration is handed in as a [`Config`] and reloaded through a
//! callback, and reload and shutdown are requested through a [`Control`]
//! handle, which the embedding program drives from its signal handlers or
//! wherever else such requests come from.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use log::{info, warn};
use tokio::sync::{mpsc, watch};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::runtime::{ControlEvent, Runtime};

/// Capacity of the control channel. Kernel events arrive in bursts; the
/// embedding program's requests are rare.
const CONTROL_QUEUE: usize = 256;
const RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// How [`Service::converge`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Startup {
    /// The initial configuration is fully applied.
    Converged,
    /// A shutdown was requested first; everything created so far has been
    /// removed again and the service should not be run.
    ShutdownRequested,
}

/// The configuration the service is converging to, shared with [`Control`].
#[derive(Debug, Clone, Default)]
struct SharedConfig(Arc<RwLock<Config>>);

impl SharedConfig {
    fn new(config: Config) -> Self {
        Self(Arc::new(RwLock::new(config)))
    }

    fn get(&self) -> Config {
        match self.0.read() {
            Ok(config) => config.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn set(&self, config: Config) {
        match self.0.write() {
            Ok(mut current) => *current = config,
            Err(poisoned) => *poisoned.into_inner() = config,
        }
    }
}

/// A handle for requesting a reload or a shutdown from any thread, and for
/// reading the configuration currently being applied.
///
/// The synchronous methods never wait for channel capacity. Reloads can
/// fail if the event queue is full; [`reload_wait`](Self::reload_wait)
/// waits for capacity instead. Shutdown has its own persistent notification
/// and cannot be lost when the event queue is full.
#[derive(Debug, Clone)]
pub struct Control {
    tx: mpsc::Sender<ControlEvent>,
    shutdown_tx: watch::Sender<bool>,
    config: SharedConfig,
}

impl Control {
    /// The configuration the service is applying or has applied: the
    /// initial one until a reload succeeds in loading a new one.
    pub fn config(&self) -> Config {
        self.config.get()
    }

    fn send(&self, event: ControlEvent) -> Result<()> {
        self.tx.try_send(event).map_err(|e| match e {
            mpsc::error::TrySendError::Full(event) => {
                Error::Other(format!("control queue is full; dropped {event:?}"))
            }
            mpsc::error::TrySendError::Closed(event) => {
                Error::Other(format!("service has stopped; dropped {event:?}"))
            }
        })
    }

    /// Asks the service to obtain a fresh configuration and apply it.
    pub fn reload(&self) -> Result<()> {
        self.send(ControlEvent::ReloadRequested)
    }

    /// Queues a reload, waiting for capacity if the event queue is full.
    ///
    /// Use this when the request must be delivered, for example when
    /// forwarding a daemon's SIGHUP signal. Fails only if the service stops.
    pub async fn reload_wait(&self) -> Result<()> {
        self.tx
            .send(ControlEvent::ReloadRequested)
            .await
            .map_err(|_| Error::Other("service has stopped; dropped reload request".to_string()))
    }

    /// Asks the service to remove every tunnel and session and stop.
    /// This request persists independently of the event queue's capacity.
    pub fn shutdown(&self) -> Result<()> {
        self.shutdown_tx
            .send(true)
            .map_err(|_| Error::Other("service has stopped; dropped shutdown request".to_string()))
    }
}

/// The daemon's event loop around a [`Runtime`].
///
/// Create it with an initial [`Config`], let [`converge`](Self::converge)
/// apply it (retrying transient kernel failures), then [`run`](Self::run)
/// until a shutdown is requested through the [`Control`] handle.
pub struct Service {
    runtime: Runtime,
    config: SharedConfig,
    control_tx: mpsc::Sender<ControlEvent>,
    control_rx: mpsc::Receiver<ControlEvent>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl Service {
    /// Opens the kernel interfaces and starts the watchers. Nothing is
    /// applied until [`converge`](Self::converge).
    pub async fn new(initial_config: Config) -> Result<Self> {
        let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let runtime = Runtime::new(control_tx.clone()).await?;
        Ok(Self {
            runtime,
            config: SharedConfig::new(initial_config),
            control_tx,
            control_rx,
            shutdown_tx,
            shutdown_rx,
        })
    }

    /// A handle for requesting reloads and shutdowns and for reading the
    /// current configuration.
    pub fn control(&self) -> Control {
        Control {
            tx: self.control_tx.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            config: self.config.clone(),
        }
    }

    /// The configuration the service is applying or has applied.
    pub fn config(&self) -> Config {
        self.config.get()
    }

    /// Applies the initial configuration, retrying every second until the
    /// kernel state matches it or a shutdown is requested. Reload requests
    /// are ignored until then; kernel and DNS events are handled, so that a
    /// reconnect retry or a bind interface appearing during a slow startup
    /// is not lost.
    pub async fn converge(&mut self) -> Result<Startup> {
        let config = self.config.get();
        loop {
            if *self.shutdown_rx.borrow() {
                info!("shutdown requested while waiting for initial configuration");
                self.runtime.shutdown().await?;
                return Ok(Startup::ShutdownRequested);
            }
            match self.runtime.reconcile(&config).await {
                Ok(()) if !*self.shutdown_rx.borrow() => return Ok(Startup::Converged),
                Ok(()) => continue,
                Err(e) => warn!("initial configuration apply failed; will retry: {}", e),
            }

            tokio::select! {
                _ = self.shutdown_rx.changed() => {}
                _ = tokio::time::sleep(RETRY_INTERVAL) => {}
                event = self.control_rx.recv() => match event {
                    Some(ControlEvent::ShutdownRequested) | None => {
                        info!("shutdown requested while waiting for initial configuration");
                        self.runtime.shutdown().await?;
                        return Ok(Startup::ShutdownRequested);
                    }
                    Some(ControlEvent::ReloadRequested) => {}
                    Some(event) => self.dispatch_runtime_event(event).await,
                }
            }
        }
    }

    /// Hands a DNS, interface or address event to the runtime. Reload and
    /// shutdown requests are the caller's to handle.
    async fn dispatch_runtime_event(&mut self, event: ControlEvent) {
        match event {
            ControlEvent::DnsChanged { tunnel_id } => {
                self.runtime.handle_dns_change(tunnel_id).await;
            }
            ControlEvent::InterfaceChanged { if_name } => {
                self.runtime.handle_interface_change(if_name.as_ref()).await;
            }
            ControlEvent::InterfaceRemoved { if_index } => {
                self.runtime.handle_interface_removed(if_index).await;
            }
            ControlEvent::LocalAddressChanged { if_index } => {
                self.runtime.handle_local_address_change(if_index).await;
            }
            ControlEvent::LocalAddressFamilyChanged {
                if_index,
                ip_version,
            } => {
                self.runtime
                    .handle_local_address_family_change(if_index, ip_version)
                    .await;
            }
            ControlEvent::ReconnectRequested { if_index } => {
                self.runtime.handle_reconnect_request(if_index).await;
            }
            ControlEvent::VrfChanged { if_index } => {
                self.runtime.handle_vrf_change(if_index).await;
            }
            ControlEvent::DiscardRouteChanged => {
                self.runtime.handle_discard_route_change().await;
            }
            ControlEvent::NetworkResyncRequested => {
                self.runtime.handle_network_resync().await;
            }
            ControlEvent::ReloadRequested | ControlEvent::ShutdownRequested => {}
        }
    }

    /// Runs until a shutdown is requested, then removes everything.
    ///
    /// `reload` is called, on a blocking-capable thread, whenever a reload
    /// is requested; it returns the configuration to apply next. A reload
    /// that fails to load is logged and ignored. A configuration that
    /// cannot be fully applied is retried every second until it is.
    pub async fn run<F>(mut self, mut reload: F) -> Result<()>
    where
        F: FnMut() -> Result<Config> + Send + 'static,
    {
        let mut reconcile_pending = false;
        let mut retry_interval = tokio::time::interval(RETRY_INTERVAL);
        retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut config = self.config.get();

        loop {
            if *self.shutdown_rx.borrow() {
                info!("shutdown requested");
                break;
            }
            let event = tokio::select! {
                _ = self.shutdown_rx.changed() => continue,
                _ = retry_interval.tick(), if reconcile_pending => {
                    match self.runtime.reconcile(&config).await {
                        Ok(()) => {
                            reconcile_pending = false;
                            info!("configuration convergence completed");
                        }
                        Err(e) => warn!("configuration apply still pending; will retry: {}", e),
                    }
                    continue;
                }
                event = self.control_rx.recv() => event,
            };

            let Some(event) = event else {
                warn!("control channel closed");
                break;
            };

            match event {
                ControlEvent::ReloadRequested => {
                    info!("reload requested: loading configuration");
                    let loaded = tokio::task::spawn_blocking(move || {
                        let loaded = reload();
                        (loaded, reload)
                    })
                    .await;
                    let new_config = match loaded {
                        Ok((loaded, returned)) => {
                            reload = returned;
                            match loaded {
                                Ok(config) => config,
                                Err(e) => {
                                    warn!("failed to load configuration: {}", e);
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            // The loader panicked; it is gone with the task.
                            return Err(Error::Other(format!("configuration loader failed: {e}")));
                        }
                    };

                    self.config.set(new_config.clone());
                    config = new_config;
                    match self.runtime.reconcile(&config).await {
                        Ok(()) => {
                            reconcile_pending = false;
                            info!("configuration reload completed");
                        }
                        Err(e) => {
                            reconcile_pending = true;
                            warn!("failed to apply reloaded configuration; will retry: {}", e);
                        }
                    }
                }
                ControlEvent::ShutdownRequested => {
                    info!("shutdown requested");
                    break;
                }
                event => self.dispatch_runtime_event(event).await,
            }
        }

        self.runtime.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Service {
        let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Service {
            runtime: crate::runtime::test_runtime(control_tx.clone()),
            config: SharedConfig::new(Config::new()),
            control_tx,
            control_rx,
            shutdown_tx,
            shutdown_rx,
        }
    }

    fn fill_queue(control: &Control) {
        for _ in 0..CONTROL_QUEUE {
            control.reload().unwrap();
        }
        assert!(control.reload().is_err());
    }

    #[tokio::test]
    async fn shutdown_survives_a_full_queue_before_run() {
        let service = service();
        let control = service.control();
        fill_queue(&control);
        control.shutdown().unwrap();
        // Repeated signals leave shutdown requested.
        control.shutdown().unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            service.run(|| panic!("shutdown must take precedence over queued reloads")),
        )
        .await
        .expect("shutdown must not wait for queue capacity")
        .unwrap();
        assert!(control.shutdown().is_err());
        assert!(control.reload_wait().await.is_err());
    }

    #[tokio::test]
    async fn shutdown_survives_a_full_queue_before_converge() {
        let mut service = service();
        let control = service.control();
        fill_queue(&control);
        control.shutdown().unwrap();
        assert_eq!(
            service.converge().await.unwrap(),
            Startup::ShutdownRequested
        );
    }

    #[tokio::test]
    async fn shutdown_wakes_an_idle_service() {
        let service = service();
        let control = service.control();
        let task = tokio::spawn(service.run(|| Ok(Config::new())));
        tokio::task::yield_now().await;
        control.shutdown().unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("shutdown must wake the event loop")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn reliable_reload_waits_for_queue_capacity() {
        let mut service = service();
        let control = service.control();
        fill_queue(&control);
        let request = control.reload_wait();
        tokio::pin!(request);
        assert!(futures_util::poll!(request.as_mut()).is_pending());
        assert!(matches!(
            service.control_rx.recv().await,
            Some(ControlEvent::ReloadRequested)
        ));
        request.await.unwrap();
        assert_eq!(service.control_rx.len(), CONTROL_QUEUE);
    }
}
