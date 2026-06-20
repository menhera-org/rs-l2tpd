pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod runtime;
pub(crate) mod state;

use clap::{ArgAction, Parser};
use config::{Config, PartialConfig};
use error::{Error, Result};
use log::{error, info, warn};
use runtime::{ControlEvent, Runtime};
use tokio::sync::{mpsc, RwLock};

use std::fs;
use std::path::{Path, PathBuf};
#[cfg(feature = "setup")]
use std::process::Command;
use std::sync::Arc;

/// This is the path to the main configuration file.
pub(crate) const CONFIG_FILE_PATH: &str = env!("CONFIG_FILE_PATH");

/// This is where configuration overrides (filenames ending in .toml) live.
pub(crate) const CONFIG_DIR_PATH: &str = env!("CONFIG_DIR_PATH");

#[cfg(feature = "setup")]
const INSTALL_BINARY_PATH: &str = "/usr/local/bin/rs-l2tpd";
#[cfg(feature = "setup")]
const INSTALL_SYSTEMD_UNIT_PATH: &str = "/usr/local/lib/systemd/system/rs-l2tpd.service";
const DEFAULT_PIDFILE_PATH: &str = "/run/rs-l2tpd.pid";

#[derive(Debug, Parser)]
#[command(version, disable_help_flag = false, disable_version_flag = false)]
struct Args {
    /// Increase log verbosity.
    #[arg(short, long, action = ArgAction::SetTrue)]
    verbose: bool,

    /// Validate and print the merged configuration, then exit.
    #[arg(short = 'c', long, action = ArgAction::SetTrue)]
    check: bool,

    /// Write the daemon PID to this file after initial readiness.
    #[arg(short = 'p', long, default_value = DEFAULT_PIDFILE_PATH)]
    pidfile: PathBuf,

    /// Install this binary and a systemd unit under /usr/local and enable the service.
    #[cfg(feature = "setup")]
    #[arg(long, action = ArgAction::SetTrue)]
    setup: bool,
}

#[cfg(unix)]
mod unix_daemon {
    use crate::error::{Error, Result};

    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    const READY: u8 = b'R';
    const FAILED: u8 = b'F';

    pub(crate) struct ReadinessNotifier {
        fd: Option<libc::c_int>,
    }

    impl ReadinessNotifier {
        fn new(fd: libc::c_int) -> Self {
            Self { fd: Some(fd) }
        }

        pub(crate) fn signal_ready(&mut self) -> Result<()> {
            self.write_message(READY)
        }

        pub(crate) fn signal_failure(&mut self) {
            let _ = self.write_message(FAILED);
        }

        fn write_message(&mut self, message: u8) -> Result<()> {
            let Some(fd) = self.fd.take() else {
                return Ok(());
            };
            let buf = [message];
            let result = loop {
                // SAFETY: fd is owned by this notifier and buf points to one valid byte.
                let written = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
                if written == 1 {
                    break Ok(());
                }
                if written < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    break Err(Error::Other(format!(
                        "failed to notify startup parent: {e}"
                    )));
                }
                break Err(Error::Other(
                    "failed to notify startup parent: short write".to_string(),
                ));
            };
            close_fd(fd);
            result
        }
    }

    impl Drop for ReadinessNotifier {
        fn drop(&mut self) {
            if let Some(fd) = self.fd.take() {
                close_fd(fd);
            }
        }
    }

    pub(crate) fn daemonize() -> Result<ReadinessNotifier> {
        let mut pipe_fds = [0 as libc::c_int; 2];
        // SAFETY: pipe_fds points to two valid c_int slots.
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(Error::Other(format!(
                "failed to create readiness pipe: {}",
                io::Error::last_os_error()
            )));
        }

        // SAFETY: fork is called before the Tokio runtime is created.
        match unsafe { libc::fork() } {
            -1 => {
                close_fd(pipe_fds[0]);
                close_fd(pipe_fds[1]);
                Err(Error::Other(format!(
                    "first fork failed: {}",
                    io::Error::last_os_error()
                )))
            }
            0 => {
                close_fd(pipe_fds[0]);
                // SAFETY: setsid has no Rust-side invariants.
                if unsafe { libc::setsid() } < 0 {
                    signal_failure_and_exit(pipe_fds[1]);
                }

                // SAFETY: second fork is still before the Tokio runtime is created.
                match unsafe { libc::fork() } {
                    -1 => signal_failure_and_exit(pipe_fds[1]),
                    0 => {
                        // SAFETY: setting a process umask has no Rust-side invariants.
                        unsafe {
                            libc::umask(0);
                        }
                        Ok(ReadinessNotifier::new(pipe_fds[1]))
                    }
                    _pid => {
                        // SAFETY: the intermediate child must not continue Rust control flow.
                        unsafe { libc::_exit(0) };
                    }
                }
            }
            _pid => {
                close_fd(pipe_fds[1]);
                let status = wait_for_readiness(pipe_fds[0]);
                close_fd(pipe_fds[0]);
                std::process::exit(status);
            }
        }
    }

    #[cfg(feature = "setup")]
    pub(crate) fn effective_uid() -> u32 {
        // SAFETY: geteuid has no safety preconditions.
        unsafe { libc::geteuid() as u32 }
    }

    pub(crate) fn write_pid_file(path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                Error::Other(format!(
                    "failed to create pidfile directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        // SAFETY: getpid has no safety preconditions.
        let pid = unsafe { libc::getpid() };
        fs::write(path, format!("{pid}\n"))
            .map_err(|e| Error::Other(format!("failed to write pidfile {}: {e}", path.display())))
    }

    pub(crate) fn remove_pid_file(path: PathBuf) {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => log::warn!("failed to remove pidfile {}: {}", path.display(), e),
        }
    }

    fn wait_for_readiness(fd: libc::c_int) -> i32 {
        let mut buf = [0_u8; 1];
        loop {
            // SAFETY: fd is a valid read end here and buf points to one writable byte.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n == 1 {
                return if buf[0] == READY { 0 } else { 1 };
            }
            if n == 0 {
                return 1;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return 1;
            }
        }
    }

    fn signal_failure_and_exit(fd: libc::c_int) -> ! {
        let buf = [FAILED];
        // SAFETY: fd is the readiness pipe write end and buf points to one valid byte.
        unsafe {
            let _ = libc::write(fd, buf.as_ptr().cast(), buf.len());
            let _ = libc::close(fd);
            libc::_exit(1);
        }
    }

    fn close_fd(fd: libc::c_int) {
        // SAFETY: closing an fd is safe; errors are intentionally ignored for cleanup.
        unsafe {
            let _ = libc::close(fd);
        }
    }
}

fn list_toml_files_at(file: &Path, dir: &Path) -> Result<Vec<PathBuf>> {
    let mut dropins = Vec::new();

    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                let path = entry
                    .map_err(|e| Error::Other(format!("failed to read directory entry: {e}")))?
                    .path();
                let is_toml = path
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("toml"))
                    .unwrap_or(false);
                if path.is_file() && is_toml {
                    dropins.push(path);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // directory does not exist -> not an error
        }
        Err(e) => return Err(Error::Other(e.to_string())),
    }

    dropins.sort(); // lexicographic order among drop-ins only

    let mut files = Vec::with_capacity(dropins.len() + 1);
    if file.is_file() {
        files.push(file.to_path_buf());
    }
    files.extend(dropins);
    Ok(files)
}

fn list_toml_files() -> Result<Vec<PathBuf>> {
    list_toml_files_at(Path::new(CONFIG_FILE_PATH), Path::new(CONFIG_DIR_PATH))
}

fn load_config_blocking() -> Result<Config> {
    let mut partial = PartialConfig::default();

    let config_paths = list_toml_files()?;
    for path in &config_paths {
        let other = PartialConfig::from_path(path)?;
        partial.merge(other);
    }

    Config::from_partial(partial)
}

#[cfg(unix)]
fn install_signal_handlers(control_tx: mpsc::Sender<ControlEvent>) -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut hup = signal(SignalKind::hangup())
        .map_err(|e| Error::Other(format!("failed to install SIGHUP handler: {e}")))?;
    let hup_tx = control_tx.clone();
    tokio::spawn(async move {
        loop {
            if hup.recv().await.is_none() {
                break;
            }
            if hup_tx.send(ControlEvent::ReloadRequested).await.is_err() {
                break;
            }
        }
    });

    let mut term = signal(SignalKind::terminate())
        .map_err(|e| Error::Other(format!("failed to install SIGTERM handler: {e}")))?;
    let mut int = signal(SignalKind::interrupt())
        .map_err(|e| Error::Other(format!("failed to install SIGINT handler: {e}")))?;
    tokio::spawn(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        let _ = control_tx.send(ControlEvent::ShutdownRequested).await;
    });

    Ok(())
}

#[cfg(not(unix))]
fn install_signal_handlers(_control_tx: mpsc::Sender<ControlEvent>) -> Result<()> {
    Err(Error::Other(
        "this daemon requires unix signal support".to_string(),
    ))
}

#[cfg(feature = "setup")]
#[cfg(unix)]
fn ensure_root_uid() -> Result<()> {
    if unix_daemon::effective_uid() != 0 {
        return Err(Error::Other(
            "--setup requires root privileges (expected effective UID 0)".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "setup")]
#[cfg(not(unix))]
fn ensure_root_uid() -> Result<()> {
    Err(Error::Other(
        "--setup is only supported on unix systems".to_string(),
    ))
}

#[cfg(feature = "setup")]
fn create_empty_file(path: &Path) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    if path.exists() {
        return Err(Error::Other(format!(
            "expected file path is not a regular file: {}",
            path.display()
        )));
    }
    std::fs::File::create(path)
        .map(|_| ())
        .map_err(|e| Error::Other(format!("failed to create {}: {e}", path.display())))
}

#[cfg(feature = "setup")]
fn run_command_checked(cmd: &mut Command, description: &str) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| Error::Other(format!("failed to execute {description}: {e}")))?;
    if !status.success() {
        return Err(Error::Other(format!(
            "{description} failed with exit status {status}"
        )));
    }
    Ok(())
}

#[cfg(feature = "setup")]
fn systemd_unit_text() -> String {
    format!(
        "[Unit]\nDescription=rs-l2tpd daemon\n\n[Service]\nType=forking\nPIDFile={DEFAULT_PIDFILE_PATH}\nExecStart={INSTALL_BINARY_PATH}\nExecReload=/bin/kill -HUP $MAINPID\nRestart=on-failure\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

#[cfg(feature = "setup")]
#[cfg(target_os = "linux")]
fn run_setup() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    ensure_root_uid()?;

    let current_exe = std::fs::read_link("/proc/self/exe")
        .or_else(|_| std::env::current_exe())
        .map_err(|e| Error::Other(format!("failed to resolve current executable path: {e}")))?;

    let install_binary = Path::new(INSTALL_BINARY_PATH);
    if let Some(parent) = install_binary.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::Other(format!(
                "failed to create install directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    std::fs::copy(&current_exe, install_binary).map_err(|e| {
        Error::Other(format!(
            "failed to copy {} to {}: {e}",
            current_exe.display(),
            install_binary.display()
        ))
    })?;
    std::fs::set_permissions(install_binary, std::fs::Permissions::from_mode(0o755)).map_err(
        |e| {
            Error::Other(format!(
                "failed to set executable permissions on {}: {e}",
                install_binary.display()
            ))
        },
    )?;
    info!("installed binary at {}", install_binary.display());

    let service_file = Path::new(INSTALL_SYSTEMD_UNIT_PATH);
    if let Some(parent) = service_file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::Other(format!(
                "failed to create systemd directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    std::fs::write(service_file, systemd_unit_text()).map_err(|e| {
        Error::Other(format!(
            "failed to write systemd service unit {}: {e}",
            service_file.display()
        ))
    })?;
    info!("installed systemd unit at {}", service_file.display());

    let config_file = Path::new(CONFIG_FILE_PATH);
    if let Some(parent) = config_file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::Other(format!(
                "failed to create config directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    create_empty_file(config_file)?;
    std::fs::create_dir_all(CONFIG_DIR_PATH).map_err(|e| {
        Error::Other(format!(
            "failed to create config drop-in directory {}: {e}",
            CONFIG_DIR_PATH
        ))
    })?;
    info!(
        "ensured config file {} and drop-in directory {}",
        CONFIG_FILE_PATH, CONFIG_DIR_PATH
    );

    run_command_checked(
        Command::new("systemctl").arg("daemon-reload"),
        "systemctl daemon-reload",
    )?;
    run_command_checked(
        Command::new("systemctl")
            .arg("enable")
            .arg("--now")
            .arg("rs-l2tpd"),
        "systemctl enable --now rs-l2tpd",
    )?;
    info!("systemd service enabled and started");

    Ok(())
}

#[cfg(feature = "setup")]
#[cfg(not(target_os = "linux"))]
fn run_setup() -> Result<()> {
    Err(Error::Other(
        "--setup is currently supported only on Linux systems".to_string(),
    ))
}

fn main() -> Result<()> {
    std::env::set_current_dir("/")
        .map_err(|e| Error::Other(format!("failed to change directory to /: {e}")))?;

    let args = Args::parse();

    let level = if args.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::new()
        .filter_level(level)
        .try_init()
        .map_err(|e| Error::Other(e.to_string()))?;

    #[cfg(feature = "setup")]
    if args.setup {
        run_setup()?;
        return Ok(());
    }

    let initial_config = load_config_blocking()?;
    if args.check {
        let rendered = toml::to_string_pretty(&initial_config)
            .map_err(|e| Error::Other(format!("failed to render config as TOML: {e}")))?;
        println!("{rendered}");
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        return Err(Error::Other(
            "daemonization is only supported on unix systems".to_string(),
        ));
    }

    #[cfg(unix)]
    let readiness = unix_daemon::daemonize()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Other(format!("failed to create Tokio runtime: {e}")))?;

    #[cfg(unix)]
    runtime.block_on(run_daemon(initial_config, args.pidfile, readiness))
}

async fn run_daemon(
    initial_config: Config,
    pidfile: PathBuf,
    #[cfg(unix)] mut readiness: unix_daemon::ReadinessNotifier,
) -> Result<()> {
    let state = Arc::new(state::State::new().await?);
    let config = Arc::new(RwLock::new(initial_config.clone()));
    let (control_tx, mut control_rx) = mpsc::channel(256);

    install_signal_handlers(control_tx.clone())?;

    let mut runtime = Runtime::new(Arc::clone(&state), control_tx.clone());
    if let Err(e) = runtime.reconcile(&initial_config).await {
        #[cfg(unix)]
        readiness.signal_failure();
        return Err(e);
    }

    #[cfg(unix)]
    {
        if let Err(e) = unix_daemon::write_pid_file(&pidfile) {
            readiness.signal_failure();
            return Err(e);
        }
        if let Err(e) = readiness.signal_ready() {
            let _ = runtime.shutdown().await;
            unix_daemon::remove_pid_file(pidfile);
            return Err(e);
        }
    }

    info!("initial configuration applied");

    loop {
        let Some(event) = control_rx.recv().await else {
            warn!("control channel closed");
            break;
        };

        match event {
            ControlEvent::ReloadRequested => {
                info!("received SIGHUP: reloading configuration");
                let loaded = tokio::task::spawn_blocking(load_config_blocking).await;
                let new_config = match loaded {
                    Ok(Ok(config)) => config,
                    Ok(Err(e)) => {
                        warn!("failed to load configuration: {}", e);
                        continue;
                    }
                    Err(e) => {
                        warn!("config loader task failed: {}", e);
                        continue;
                    }
                };

                match runtime.reconcile(&new_config).await {
                    Ok(()) => {
                        *config.write().await = new_config;
                        info!("configuration reload completed");
                    }
                    Err(e) => {
                        warn!("failed to apply reloaded configuration: {}", e);
                    }
                }
            }
            ControlEvent::ShutdownRequested => {
                info!("shutdown requested");
                if let Err(e) = runtime.shutdown().await {
                    error!("shutdown cleanup failed: {}", e);
                }
                break;
            }
            ControlEvent::DnsChanged { tunnel_id } => {
                runtime.handle_dns_change(tunnel_id).await;
            }
            ControlEvent::InterfaceChanged { if_name } => {
                runtime.handle_interface_change(if_name.as_deref()).await;
            }
        }
    }

    if let Err(e) = runtime.shutdown().await {
        warn!("final cleanup failed: {}", e);
    }

    #[cfg(unix)]
    unix_daemon::remove_pid_file(pidfile);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::list_toml_files_at;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock monotonic")
            .as_nanos();
        path.push(format!(
            "rs-l2tpd-tests-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn list_toml_files_at_keeps_main_when_dropin_dir_missing() {
        let temp_dir = unique_temp_dir("config-main");
        let main_file = temp_dir.join("rs-l2tpd.toml");
        let dropin_dir = temp_dir.join("rs-l2tpd.toml.d");

        fs::write(&main_file, b"[tunnels]\n").expect("write main config");
        let files = list_toml_files_at(&main_file, &dropin_dir).expect("list files");

        assert_eq!(files, vec![main_file.clone()]);
        fs::remove_dir_all(temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn list_toml_files_at_sorts_and_filters() {
        let temp_dir = unique_temp_dir("config-sort");
        let main_file = temp_dir.join("rs-l2tpd.toml");
        let dropin_dir = temp_dir.join("rs-l2tpd.toml.d");

        fs::create_dir_all(&dropin_dir).expect("create dropin dir");
        fs::write(&main_file, b"[tunnels]\n").expect("write main config");
        fs::write(dropin_dir.join("20-extra.toml"), b"[tunnels]\n").expect("write dropin");
        fs::write(dropin_dir.join("10-base.toml"), b"[tunnels]\n").expect("write dropin");
        fs::write(dropin_dir.join("README.txt"), b"ignore\n").expect("write non toml");

        let files = list_toml_files_at(&main_file, &dropin_dir).expect("list files");

        let expected = vec![
            main_file.clone(),
            dropin_dir.join("10-base.toml"),
            dropin_dir.join("20-extra.toml"),
        ];
        assert_eq!(files, expected);

        fs::remove_dir_all(temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn list_toml_files_at_keeps_main_precedence_over_lexicographic_order() {
        let temp_dir = unique_temp_dir("config-precedence");
        let main_file = temp_dir.join("zz-main.toml");
        let dropin_dir = temp_dir.join("aa-dropins");

        fs::create_dir_all(&dropin_dir).expect("create dropin dir");
        fs::write(&main_file, b"[tunnels]\n").expect("write main config");
        fs::write(dropin_dir.join("00-first.toml"), b"[tunnels]\n").expect("write dropin");

        let files = list_toml_files_at(&main_file, &dropin_dir).expect("list files");
        let expected = vec![main_file.clone(), dropin_dir.join("00-first.toml")];
        assert_eq!(files, expected);

        fs::remove_dir_all(temp_dir).expect("cleanup temp dir");
    }
}
