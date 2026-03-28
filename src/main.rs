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
use std::sync::Arc;

/// This is the path to the main configuration file.
pub(crate) const CONFIG_FILE_PATH: &str = env!("CONFIG_FILE_PATH");

/// This is where configuration overrides (filenames ending in .toml) live.
pub(crate) const CONFIG_DIR_PATH: &str = env!("CONFIG_DIR_PATH");

#[derive(Debug, Parser)]
#[command(version, disable_help_flag = false, disable_version_flag = false)]
struct Args {
    /// Increase log verbosity.
    #[arg(short, long, action = ArgAction::SetTrue)]
    verbose: bool,

    /// Validate and print the merged configuration, then exit.
    #[arg(short = 'c', long, action = ArgAction::SetTrue)]
    check: bool,
}

fn list_toml_files_at(file: &Path, dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if file.is_file() {
        files.push(file.to_path_buf());
    }

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
                    files.push(path);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // directory does not exist -> not an error
        }
        Err(e) => return Err(Error::Other(e.to_string())),
    }

    files.sort(); // lexicographic order (important for drop-ins)
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
fn install_signal_handlers(control_tx: mpsc::UnboundedSender<ControlEvent>) -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut hup = signal(SignalKind::hangup())
        .map_err(|e| Error::Other(format!("failed to install SIGHUP handler: {e}")))?;
    let hup_tx = control_tx.clone();
    tokio::spawn(async move {
        loop {
            if hup.recv().await.is_none() {
                break;
            }
            if hup_tx.send(ControlEvent::ReloadRequested).is_err() {
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
        let _ = control_tx.send(ControlEvent::ShutdownRequested);
    });

    Ok(())
}

#[cfg(not(unix))]
fn install_signal_handlers(_control_tx: mpsc::UnboundedSender<ControlEvent>) -> Result<()> {
    Err(Error::Other(
        "this daemon requires unix signal support".to_string(),
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

    let initial_config = load_config_blocking()?;
    if args.check {
        let rendered = toml::to_string_pretty(&initial_config)
            .map_err(|e| Error::Other(format!("failed to render config as TOML: {e}")))?;
        println!("{rendered}");
        return Ok(());
    }

    let state = Arc::new(state::State::new().await?);
    let config = Arc::new(RwLock::new(initial_config.clone()));
    let (control_tx, mut control_rx) = mpsc::unbounded_channel();

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
}
