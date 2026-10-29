//! Blocking service, including when called from within another Tokio runtime.
//! Its private runtime keeps subscriptions draining on a separate thread (L8).
//!
//! ```no_run
//! # fn example() -> rs_l2tpd::Result<()> {
//! use rs_l2tpd::{blocking::Service, config::Config};
//! let mut service = Service::new(Config::new(), vec![]).map_err(|(e, _)| e)?;
//! service.converge()?;
//! service.control().shutdown();
//! service.run(Ok, |_| Ok(()))?;
//! # Ok(()) }
//! ```

use std::sync::{Arc, Mutex, mpsc};

use crate::config::Config;
use crate::kernel::{Kernel, linux::LinuxKernel};
use crate::reconciler::{IphostResolve, Resolve};
pub use crate::runtime::{AdoptedSocket, Control, ControlEvent, Receiver, StartResult};
use crate::{Error, Result};

type Reply<T> = mpsc::SyncSender<Result<T>>;
type Reload = Box<dyn FnMut(Config) -> Result<Config> + Send>;
type Restart = Box<dyn FnMut(Vec<AdoptedSocket>) -> Result<()> + Send>;

enum Command {
    Converge(Reply<Vec<String>>),
    Run(Reload, Restart, Reply<()>),
    Requests(Reply<Option<Receiver<ControlEvent>>>),
    StoreCapacity(usize, Reply<()>),
}

/// Owns its subscription runtime and reconciler threads. Drop performs orderly
/// shutdown even before `run`; use `run` to observe cleanup failures.
pub struct Service {
    control: Control,
    commands: Option<tokio::sync::mpsc::Sender<Command>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Service {
    /// Opens kernel interfaces immediately on the private runtime.
    pub fn new(config: Config, adopted: Vec<AdoptedSocket>) -> StartResult<Self> {
        Self::open(config, adopted, || {
            Ok((
                LinuxKernel::new()?,
                Box::new(IphostResolve::default()) as Box<dyn Resolve>,
            ))
        })
    }

    /// Uses a supplied kernel and resolver, also suitable for isolated tests.
    pub fn with_kernel<K: Kernel + 'static>(
        config: Config,
        kernel: K,
        resolver: Box<dyn Resolve>,
        adopted: Vec<AdoptedSocket>,
    ) -> StartResult<Self> {
        Self::open(config, adopted, move || Ok((kernel, resolver)))
    }

    fn open<K: Kernel + 'static>(
        config: Config,
        adopted: Vec<AdoptedSocket>,
        open: impl FnOnce() -> Result<(K, Box<dyn Resolve>)> + Send + 'static,
    ) -> StartResult<Self> {
        let slot = Arc::new(Mutex::new(Some(adopted)));
        let worker_slot = slot.clone();
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let (commands, mut rx) = tokio::sync::mpsc::channel(1);
        let thread = match std::thread::Builder::new()
            .name("l2tp-blocking".into())
            .spawn(move || {
                let engine = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(engine) => engine,
                    Err(error) => {
                        let _ = startup_tx.send(Err((
                            Error::from(error),
                            worker_slot.lock().unwrap().take().unwrap(),
                        )));
                        return;
                    }
                };
                engine.block_on(async move {
                    let adopted = worker_slot.lock().unwrap().take().unwrap();
                    let runtime = match open() {
                        Ok((kernel, resolver)) => {
                            crate::runtime::Runtime::with_kernel(kernel, resolver, adopted)
                        }
                        Err(error) => Err((error, adopted)),
                    };
                    let mut service = match runtime
                        .and_then(|runtime| crate::service::Service::with_runtime(config, runtime))
                    {
                        Ok(service) => service,
                        Err(error) => {
                            let _ = startup_tx.send(Err(error));
                            return;
                        }
                    };
                    if startup_tx.send(Ok(service.control())).is_err() {
                        return;
                    }
                    while let Some(command) = rx.recv().await {
                        match command {
                            Command::Converge(tx) => {
                                let _ = tx.send(service.converge().await);
                            }
                            Command::Run(reload, restart, tx) => {
                                let _ = tx.send(service.run(reload, restart).await);
                            }
                            Command::Requests(tx) => {
                                let _ = tx.send(Ok(service.take_requests()));
                            }
                            Command::StoreCapacity(capacity, tx) => {
                                let _ = tx.send(service.set_store_capacity(capacity).await);
                            }
                        }
                    }
                });
            }) {
            Ok(thread) => thread,
            Err(error) => return Err((error.into(), slot.lock().unwrap().take().unwrap())),
        };
        match startup_rx.recv() {
            Ok(Ok(control)) => Ok(Self {
                control,
                commands: Some(commands),
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(error) => {
                let _ = thread.join();
                Err((Error::Other(error.to_string()), vec![]))
            }
        }
    }

    /// A thread-safe control handle.
    pub fn control(&self) -> Control {
        self.control.clone()
    }
    /// Announces optional descriptor-store capacity before convergence.
    pub fn set_store_capacity(&mut self, capacity: usize) -> Result<()> {
        self.request(|tx| Command::StoreCapacity(capacity, tx))
    }
    /// Enables host integration once, before convergence.
    pub fn take_requests(&mut self) -> Result<Option<Receiver<ControlEvent>>> {
        self.request(Command::Requests)
    }
    /// Waits for readiness, ignoring reload requests.
    pub fn converge(&mut self) -> Result<Vec<String>> {
        self.request(Command::Converge)
    }
    /// Runs until shutdown; callbacks have the same contract as the Tokio service.
    pub fn run(
        &mut self,
        reload: impl FnMut(Config) -> Result<Config> + Send + 'static,
        restart: impl FnMut(Vec<AdoptedSocket>) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        self.request(|tx| Command::Run(Box::new(reload), Box::new(restart), tx))
    }
    fn request<T>(&self, command: impl FnOnce(Reply<T>) -> Command) -> Result<T> {
        let (tx, rx) = mpsc::sync_channel(1);
        // try_send is sufficient: &mut self serializes the public methods.
        self.commands
            .as_ref()
            .unwrap()
            .try_send(command(tx))
            .map_err(|e| Error::Other(e.to_string()))?;
        rx.recv().map_err(|e| Error::Other(e.to_string()))?
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.control.shutdown();
        self.commands.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
