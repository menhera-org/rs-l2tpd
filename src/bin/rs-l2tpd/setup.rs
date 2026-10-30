//! Bounded optional installer, sharing the package's unit template.
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
#[cfg(feature = "setup-systemd")]
use std::process::Command;

const TEMPLATE: &str = include_str!("../../../contrib/rs-l2tpd.service.in");
const LEGACY: &str = include_str!("../../../contrib/rs-l2tpd.service.legacy");
pub fn unit(binary: &str) -> String {
    TEMPLATE.replace("@BINARY@", binary)
}
fn atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    fs::create_dir_all(path.parent().unwrap())?;
    if fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    let mut random = [0; 8];
    getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
    let temporary = path.with_file_name(format!(".rs-l2tpd-{:016x}", u64::from_ne_bytes(random)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(path.parent().unwrap())?.sync_all()
    })();
    let _ = fs::remove_file(temporary);
    result
}
fn install_files(prefix: &Path, executable: &Path) -> bool {
    let mut success = true;
    let mut step = |name: &str, result: io::Result<()>| match result {
        Ok(()) => println!("{name}: done"),
        Err(e) => {
            eprintln!("{name}: {e}");
            success = false;
        }
    };
    step(
        "binary",
        fs::read(executable)
            .and_then(|bytes| atomic(&prefix.join("usr/local/sbin/rs-l2tpd"), &bytes, 0o755)),
    );
    let rendered = unit("/usr/local/sbin/rs-l2tpd");
    let path = prefix.join("etc/systemd/system/rs-l2tpd.service");
    let result = match fs::read(&path) {
        Ok(existing) if existing != rendered.as_bytes() && existing != LEGACY.as_bytes() => {
            println!("unit: preserved operator-edited or unknown unit");
            Ok(())
        }
        Ok(_) => atomic(&path, rendered.as_bytes(), 0o644),
        Err(e) if e.kind() == io::ErrorKind::NotFound => atomic(&path, rendered.as_bytes(), 0o644),
        Err(e) => Err(e),
    };
    step("unit", result);
    step(
        "configuration directory",
        fs::create_dir_all(prefix.join("etc/rs-l2tpd.toml.d")),
    );
    step(
        "configuration",
        (|| {
            let path = prefix.join("etc/rs-l2tpd.toml");
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.set_permissions(fs::Permissions::from_mode(0o644))?;
                    file.write_all(include_bytes!("../../../contrib/rs-l2tpd.toml"))?;
                    file.sync_all()
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    println!("configuration: preserved existing file");
                    Ok(())
                }
                Err(e) => Err(e),
            }
        })(),
    );
    success
}
#[cfg(feature = "setup-systemd")]
fn systemctl(arguments: &[&str]) -> io::Result<bool> {
    Ok(Command::new("systemctl")
        .arg("--no-pager")
        .args(arguments)
        .status()?
        .success())
}
#[cfg(feature = "setup-systemd")]
pub fn run(prefix: Option<&Path>, executable: &Path) -> u8 {
    if prefix.is_none() && unsafe { libc::geteuid() } != 0 {
        log::error!("--setup-systemd requires root (or --prefix for tests)");
        return 1;
    }
    let enabled = if prefix.is_none() {
        match systemctl(&["--quiet", "is-enabled", "rs-l2tpd.service"]) {
            Ok(enabled) => enabled,
            Err(error) => {
                log::error!("systemctl is-enabled: {error}");
                return 1;
            }
        }
    } else {
        false
    };
    let success = install_files(prefix.unwrap_or(Path::new("/")), executable);
    if prefix.is_some() {
        return u8::from(!success);
    }
    let reload = systemctl(&["daemon-reload"]).unwrap_or_else(|error| {
        log::error!("daemon-reload: {error}");
        false
    });
    if !reload {
        log::error!("daemon-reload failed");
    }
    let start = if !enabled && success && reload {
        systemctl(&["--now", "enable", "rs-l2tpd.service"]).unwrap_or_else(|error| {
            log::error!("enable --now: {error}");
            false
        })
    } else {
        true
    };
    println!("systemd: existing services are never restarted");
    u8::from(!success || !reload || !start)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::Dir;
    use std::os::unix::fs::MetadataExt;
    /// spec: P21 P27
    #[test]
    fn parses_required_unit_keys_and_install_paths() {
        for binary in ["/usr/local/sbin/rs-l2tpd", "/usr/sbin/rs-l2tpd"] {
            let text = unit(binary);
            let pairs: Vec<_> = text.lines().filter_map(|l| l.split_once('=')).collect();
            for (key, value) in [
                ("Type", "forking"),
                ("Before", "network-online.target"),
                ("RequiredBy", "network-online.target"),
                ("PIDFile", "/run/rs-l2tpd/rs-l2tpd.pid"),
                ("TimeoutStartSec", "infinity"),
                ("Restart", "on-failure"),
                ("NotifyAccess", "all"),
                ("NoNewPrivileges", "yes"),
                ("ProtectSystem", "strict"),
                ("ProtectHome", "yes"),
                ("PrivateTmp", "yes"),
                (
                    "RestrictAddressFamilies",
                    "AF_UNIX AF_NETLINK AF_INET AF_INET6",
                ),
                (
                    "CapabilityBoundingSet",
                    "CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE",
                ),
                (
                    "AmbientCapabilities",
                    "CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE",
                ),
                (
                    "ReadWritePaths",
                    "/run/rs-l2tpd -/proc/sys/net/ipv6/bindv6only",
                ),
            ] {
                assert!(pairs.contains(&(key, value)), "{key}");
            }
            assert!(text.contains(&format!("ExecStart={binary} --pid-file ")));
            assert!(
                pairs
                    .iter()
                    .any(|(key, value)| *key == "FileDescriptorStoreMax"
                        && value.parse::<u32>().unwrap() >= 65536)
            );
            for (key, value) in pairs {
                if ["After", "Requires", "Wants", "Requisite", "BindsTo"].contains(&key) {
                    assert!(
                        !value.contains("network-online.target") && !value.contains("wait-online")
                    );
                }
            }
        }
    }
    /// spec: P27
    #[test]
    fn atomic_idempotent_and_preserves_edits_and_configuration() {
        let dir = Dir::new();
        let source = dir.path().join("source");
        fs::write(&source, "first").unwrap();
        assert!(install_files(dir.path(), &source));
        let binary = dir.path().join("usr/local/sbin/rs-l2tpd");
        let held = fs::File::open(&binary).unwrap();
        fs::write(&source, "second").unwrap();
        assert!(install_files(dir.path(), &source));
        assert_ne!(
            held.metadata().unwrap().ino(),
            fs::metadata(&binary).unwrap().ino()
        );
        let inode = fs::metadata(&binary).unwrap().ino();
        assert!(install_files(dir.path(), &source));
        assert_eq!(inode, fs::metadata(&binary).unwrap().ino());
        let config = dir.path().join("etc/rs-l2tpd.toml");
        fs::write(&config, "# operator").unwrap();
        let path = dir.path().join("etc/systemd/system/rs-l2tpd.service");
        for old in [
            LEGACY.to_owned(),
            format!("{LEGACY}# edit\n"),
            "unknown unit".into(),
        ] {
            fs::write(&path, &old).unwrap();
            assert!(install_files(dir.path(), &source));
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                if old == LEGACY {
                    unit("/usr/local/sbin/rs-l2tpd")
                } else {
                    old
                }
            );
            assert_eq!(fs::read_to_string(&config).unwrap(), "# operator");
        }
    }
}
