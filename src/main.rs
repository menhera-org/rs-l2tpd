
pub(crate) mod error;
pub(crate) mod config;
pub(crate) mod state;

use error::*;
use config::*;
use tokio::sync::RwLock;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// This is the path to the main configuration file.
pub(crate) const CONFIG_FILE_PATH: &'static str = env!("CONFIG_FILE_PATH");

/// This is where configuration overrides (filenames ending in .toml) live.
pub(crate) const CONFIG_DIR_PATH: &'static str = env!("CONFIG_DIR_PATH");

fn list_toml_files() -> Result<Vec<PathBuf>> {
    let file = Path::new(CONFIG_FILE_PATH);
    let dir = Path::new(CONFIG_DIR_PATH);

    let mut files = Vec::new();
    if file.is_file() {
        files.push(file.to_path_buf());
    }

    files.extend(match fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .and_then(|s| s.to_str())
                        .map(|ext| ext.eq_ignore_ascii_case("toml"))
                        .unwrap_or(false)
            }),

        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // directory does not exist → not an error
            return Ok(Vec::new());
        }

        Err(e) => return Err(Error::Other(e.to_string())),
    });

    files.sort(); // lexicographic order (important for drop-ins)

    Ok(files)
}

fn load_config_blocking() -> Result<Config> {
    let mut partial = PartialConfig::default();

    let config_paths = list_toml_files()?;
    for path in &config_paths {
        let other = PartialConfig::from_path(path)?;
        partial.merge(other);
    }

    let config = Config::from_partial(partial)?;

    Ok(config)
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = load_config_blocking()?;
    let config = Arc::new(RwLock::new(config));


    Ok(())
}
