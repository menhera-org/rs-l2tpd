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

#[derive(Debug, Parser)]
#[command(version, disable_help_flag = false, disable_version_flag = false)]
struct Args {
    /// Increase log verbosity.
    #[arg(short, long, action = ArgAction::SetTrue)]
    verbose: bool,

    /// Validate and print the merged configuration, then exit.
    #[arg(short = 'c', long, action = ArgAction::SetTrue)]
    check: bool,

    /// Install this binary and a systemd unit under /usr/local and enable the service.
    #[cfg(feature = "setup")]
    #[arg(long, action = ArgAction::SetTrue)]
    setup: bool,
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
    // SAFETY: libc::geteuid has no safety preconditions and does not dereference pointers.
    if unsafe { libc::geteuid() } != 0 {
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
        "[Unit]\nDescription=rs-l2tpd daemon\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={INSTALL_BINARY_PATH}\nExecReload=/bin/kill -HUP $MAINPID\nRestart=on-failure\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

#[cfg(feature = "setup")]
#[cfg(target_os = "linux")]
fn run_setup() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    ensure_root_uid()?;

    let current_exe = std::env::current_exe()
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

#[tokio::main]
async fn main() -> Result<()> {
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

    let state = Arc::new(state::State::new().await?);
    let config = Arc::new(RwLock::new(initial_config.clone()));
    let (control_tx, mut control_rx) = mpsc::channel(256);

    install_signal_handlers(control_tx.clone())?;

    let mut runtime = Runtime::new(Arc::clone(&state), control_tx.clone());
    runtime.reconcile(&initial_config).await?;
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
        }
    }

    if let Err(e) = runtime.shutdown().await {
        warn!("final cleanup failed: {}", e);
    }

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
