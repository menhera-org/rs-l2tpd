//! File discovery, per-document parsing and merging (C1–C4).
use rs_l2tpd::config::{Config, Effect, PartialConfig, Problem};
use rs_l2tpd::{Error, Result};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub struct Loaded {
    pub partial: PartialConfig,
    pub errors: Vec<String>,
}
// A missing pathname is removal; a dangling symlink is a failed lookup.
fn present(path: &Path) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // ENOENT can also mean a dangling link in a parent component.
            for ancestor in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
                match fs::symlink_metadata(ancestor) {
                    Ok(_) => return fs::metadata(ancestor).map(|_| ancestor == path),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e),
                }
            }
            Ok(false)
        }
        Err(e) => Err(e),
    }
}
pub fn load(main: &Path, directory: &Path) -> Loaded {
    let mut loaded = Loaded {
        partial: PartialConfig::new(),
        errors: vec![],
    };
    loaded.read(main);
    let entries = match present(directory).and_then(|yes| {
        if yes {
            fs::read_dir(directory).map(Some)
        } else {
            Ok(None)
        }
    }) {
        Ok(Some(entries)) => entries,
        Ok(None) => return loaded,
        Err(e) => {
            loaded.errors.push(format!("{}: {e}", directory.display()));
            return loaded;
        }
    };
    let mut paths = vec![];
    for entry in entries {
        match entry {
            Ok(entry) => {
                let name = entry.file_name();
                let bytes = name.as_bytes();
                if !bytes.starts_with(b".")
                    && bytes.len() >= 5
                    && bytes[bytes.len() - 5..].eq_ignore_ascii_case(b".toml")
                {
                    paths.push(entry.path());
                }
            }
            Err(e) => loaded.errors.push(format!("{}: {e}", directory.display())),
        }
    }
    paths.sort_by(|a, b| {
        a.file_name()
            .unwrap()
            .as_bytes()
            .cmp(b.file_name().unwrap().as_bytes())
    });
    for path in paths {
        loaded.read(&path);
    }
    loaded
}
impl Loaded {
    fn read(&mut self, path: &Path) {
        let result = (|| -> std::result::Result<Option<PartialConfig>, String> {
            if !present(path).map_err(|e| e.to_string())? {
                return Ok(None);
            }
            let text = match fs::read_to_string(path) {
                Ok(text) => text,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    if !present(path).map_err(|e| e.to_string())? {
                        return Ok(None);
                    }
                    return Err(e.to_string());
                }
                Err(e) => return Err(e.to_string()),
            };
            // TOML diagnostics include source excerpts, which could expose cookies.
            let mut partial: PartialConfig =
                toml::from_str(&text).map_err(|e: toml::de::Error| match e.span() {
                    Some(span) => format!("invalid TOML document at byte {}", span.start),
                    None => "invalid TOML document".into(),
                })?;
            partial.set_source(path);
            Ok(Some(partial))
        })();
        match result {
            Ok(Some(partial)) => self.partial.merge(partial),
            Ok(None) => (),
            Err(error) => self.errors.push(format!("{}: {error}", path.display())),
        }
    }
}
pub fn report(config: &Config, problems: &[Problem], reload: bool) {
    use rs_l2tpd::config::{EntryKind, ProblemKind};
    for problem in problems {
        let identifiers = match problem.kind() {
            ProblemKind::Entry {
                kind: EntryKind::Tunnel,
                name,
                ..
            } => config
                .tunnels()
                .get(name)
                .map(|t| format!(" tunnel_id={}", t.tunnel_id())),
            ProblemKind::Entry {
                kind: EntryKind::Session,
                name,
                ..
            } => config
                .sessions()
                .get(name)
                .map(|s| format!(" session_id={}", s.session_id())),
            _ => None,
        }
        .unwrap_or_default();
        if problem.effect() == Effect::Refused || (!reload && problem.effect() == Effect::LeftOut) {
            log::error!("{problem}{identifiers}");
        } else {
            log::warn!("{problem}{identifiers}");
        }
    }
}
pub fn reload(main: &Path, directory: &Path, previous: Config) -> Result<Config> {
    let loaded = load(main, directory);
    if !loaded.errors.is_empty() {
        for error in loaded.errors {
            log::error!("{error}; reload refused");
        }
        return Err(Error::InvalidConfig(
            "file problems; previous configuration retained".into(),
        ));
    }
    match loaded.partial.into_config_with_previous(&previous) {
        Ok((config, problems)) => {
            report(&config, &problems, true);
            Ok(config)
        }
        Err(problems) => {
            report(&previous, &problems, true);
            Err(Error::InvalidConfig(
                "reload refused; previous configuration retained".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::Dir;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    /// spec: C1 C2 C3 C4 P13
    #[test]
    fn discovery_merging_and_reload_refusal() {
        let dir = Dir::new();
        let main = dir.path().join("main");
        let dropins = dir.path().join("dropins");
        assert!(load(&main, &dropins).errors.is_empty());
        fs::create_dir(&dropins).unwrap();
        fs::write(&main, "[tunnels.a]\ntunnel_id=1\nremote_addr='192.0.2.1'").unwrap();
        fs::write(
            dropins.join("Z.ToMl"),
            "[tunnels.a]\nremote_addr='192.0.2.2'",
        )
        .unwrap();
        fs::write(
            dropins.join(std::ffi::OsString::from_vec(b"\xff.toml".to_vec())),
            "[tunnels.a]\nremote_addr='192.0.2.3'",
        )
        .unwrap();
        fs::write(dropins.join(".hidden.toml"), "invalid").unwrap();
        fs::write(dropins.join("ignored"), "invalid").unwrap();
        let (config, problems) = load(&main, &dropins).partial.into_config_lenient();
        assert!(problems.is_empty());
        assert!(toml::to_string(&config).unwrap().contains("192.0.2.3"));
        fs::remove_file(&main).unwrap();
        assert!(load(&main, &dropins).errors.is_empty());
        symlink("gone", &main).unwrap();
        assert_eq!(load(&main, &dropins).errors.len(), 1);
        assert!(reload(&main, &dropins, config).is_err());
        fs::remove_file(&main).unwrap();
        symlink("main", &main).unwrap();
        assert_eq!(load(&main, &dropins).errors.len(), 1);
        let broken = dir.path().join("broken");
        symlink(dir.path().join("gone"), &broken).unwrap();
        assert_eq!(load(&broken.join("main"), &dropins).errors.len(), 1);
        assert_eq!(
            load(&dir.path().join("absent"), &broken.join("dropins"))
                .errors
                .len(),
            1
        );
    }
    /// spec: C3 C4 O5
    #[test]
    fn failed_documents_are_omitted_and_diagnostics_redact_input() {
        let dir = Dir::new();
        let main = dir.path().join("main");
        fs::write(&main, "[sessions.a]\ncookie = secret-cookie").unwrap();
        let loaded = load(&main, dir.path());
        assert_eq!(loaded.errors.len(), 1);
        assert!(!loaded.errors[0].contains("secret-cookie"));
        fs::write(&main, "[tunnels.a]\ntunnel_id='wrong'").unwrap();
        assert!(!load(&main, dir.path()).errors.is_empty());
        fs::remove_file(&main).unwrap();
        fs::create_dir(&main).unwrap();
        assert!(!load(&main, dir.path()).errors.is_empty());
    }
}

#[cfg(test)]
mod filesystem_tests {
    use super::*;
    use crate::testdir::Dir;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::process::CommandExt;
    /// spec: C1 C3 C4 P13
    #[test]
    fn followed_links_and_absence_on_reload() {
        let dir = Dir::new();
        let actual = dir.path().join("actual");
        fs::write(&actual, "[tunnels.a]\ntunnel_id=1\nremote_addr='192.0.2.1'").unwrap();
        let main = dir.path().join("main");
        symlink(&actual, &main).unwrap();
        let target = dir.path().join("target");
        fs::create_dir(&target).unwrap();
        let dropins = dir.path().join("dropins");
        symlink(&target, &dropins).unwrap();
        let (previous, problems) = load(&main, &dropins).partial.into_config_lenient();
        assert!(problems.is_empty());
        assert_eq!(previous.tunnels().len(), 1);
        fs::remove_file(main.clone()).unwrap();
        fs::remove_file(dropins.clone()).unwrap();
        assert!(
            reload(&main, &dropins, previous)
                .unwrap()
                .tunnels()
                .is_empty()
        );
    }
    /// spec: C3
    #[test]
    fn permission_child() {
        let Some(base) = std::env::var_os("CONFIG_PERMISSION_BASE") else {
            return;
        };
        let base = Path::new(&base);
        let loaded = load(&base.join("main"), &base.join("unlistable"));
        assert_eq!(loaded.errors.len(), 2);
        let loaded = load(&base.join("uninspectable/main"), &base.join("absent"));
        assert_eq!(loaded.errors.len(), 1);
    }
    /// spec: C3
    #[test]
    #[ignore = "root in an isolated container, drops child uid"]
    fn permission_errors_name_unreadable_unlistable_and_uninspectable_paths() {
        let dir = Dir::new();
        fs::write(dir.path().join("main"), "").unwrap();
        fs::create_dir(dir.path().join("unlistable")).unwrap();
        fs::create_dir(dir.path().join("uninspectable")).unwrap();
        for (name, mode) in [
            ("main", 0o000),
            ("unlistable", 0o100),
            ("uninspectable", 0o000),
        ] {
            fs::set_permissions(dir.path().join(name), fs::Permissions::from_mode(mode)).unwrap();
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "files::filesystem_tests::permission_child",
                "--nocapture",
            ])
            .env("CONFIG_PERMISSION_BASE", dir.path())
            .uid(65534)
            .gid(65534)
            .status()
            .unwrap();
        assert!(status.success());
    }
}
