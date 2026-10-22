//! A blocking facade over [`crate::service::Service`] for programs that do
//! not use Tokio.
//!
//! The service runs on a dedicated thread with a multi-threaded Tokio
//! runtime of its own. The blocking methods hand work to that thread and
//! wait for the answer, so they never block inside a caller's runtime and
//! can be called from anywhere, including from within another Tokio runtime.

use std::sync::mpsc;
use std::thread::JoinHandle;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::service;

pub use crate::service::{Control, Startup};

type Reload = Box<dyn FnMut() -> Result<Config> + Send + 'static>;

enum Command {
    Converge(mpsc::SyncSender<Result<Startup>>),
    Run(Reload, mpsc::SyncSender<Result<()>>),
}

fn stopped() -> Error {
    Error::Other("the service thread has stopped".to_string())
}

/// The daemon's event loop, driven from a thread of its own.
///
/// See [`service::Service`] for the semantics of each method; this type
/// only moves them across threads.
pub struct Service {
    commands: Option<mpsc::Sender<Command>>,
    control: Control,
    thread: Option<JoinHandle<()>>,
}

impl Service {
    /// Starts the service thread and its runtime and opens the kernel
    /// interfaces. Nothing is applied until [`converge`](Self::converge).
    pub fn new(initial_config: Config) -> Result<Self> {
        let (commands, command_rx) = mpsc::channel::<Command>();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<Control>>(1);

        let thread = std::thread::Builder::new()
            .name("rs-l2tpd-service".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_name("rs-l2tpd-worker")
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(e) => {
                        let _ = ready_tx.send(Err(Error::Other(format!(
                            "failed to create the service runtime: {e}"
                        ))));
                        return;
                    }
                };
                let mut service = match runtime.block_on(service::Service::new(initial_config)) {
                    Ok(service) => service,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                if ready_tx.send(Ok(service.control())).is_err() {
                    return;
                }

                for command in command_rx {
                    match command {
                        Command::Converge(reply) => {
                            let _ = reply.send(runtime.block_on(service.converge()));
                        }
                        Command::Run(reload, reply) => {
                            let _ = reply.send(runtime.block_on(service.run(reload)));
                            return;
                        }
                    }
                }
                // Dropped without running: tear down inside the runtime, as
                // the handles expect.
                runtime.block_on(async move { drop(service) });
            })
            .map_err(|e| Error::Other(format!("failed to spawn the service thread: {e}")))?;

        let control = match ready_rx.recv() {
            Ok(Ok(control)) => control,
            Ok(Err(e)) => {
                let _ = thread.join();
                return Err(e);
            }
            Err(_) => {
                let _ = thread.join();
                return Err(stopped());
            }
        };

        Ok(Self {
            commands: Some(commands),
            control,
            thread: Some(thread),
        })
    }

    /// A handle for requesting reloads and shutdowns from any thread, and
    /// for reading the current configuration.
    pub fn control(&self) -> Control {
        self.control.clone()
    }

    /// The configuration the service is applying or has applied.
    pub fn config(&self) -> Config {
        self.control.config()
    }

    /// Applies the initial configuration, retrying until it is applied or
    /// a shutdown is requested; blocks until then.
    pub fn converge(&mut self) -> Result<Startup> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.commands
            .as_ref()
            .ok_or_else(stopped)?
            .send(Command::Converge(reply_tx))
            .map_err(|_| stopped())?;
        reply_rx.recv().map_err(|_| stopped())?
    }

    /// Runs until a shutdown is requested, then removes everything; blocks
    /// until then. `reload` provides the configuration for each reload.
    pub fn run<F>(mut self, reload: F) -> Result<()>
    where
        F: FnMut() -> Result<Config> + Send + 'static,
    {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.commands
            .take()
            .ok_or_else(stopped)?
            .send(Command::Run(Box::new(reload), reply_tx))
            .map_err(|_| stopped())?;
        let result = reply_rx.recv().map_err(|_| stopped())?;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        result
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        // Closing the command channel ends the thread's loop.
        self.commands.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
