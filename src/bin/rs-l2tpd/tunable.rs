//! The only host setting the daemon writes (P25).
use std::io;
pub fn write(name: &str, value: &str, deadline: std::time::Instant) -> bool {
    if name != "net.ipv6.bindv6only" || value != "0" || std::time::Instant::now() >= deadline {
        return false;
    }
    // The reconciler reports a failed handshake once (P25/O3).
    set(std::path::Path::new("/proc/sys/net/ipv6/bindv6only")).is_ok()
}
fn set(path: &std::path::Path) -> io::Result<()> {
    let previous = std::fs::read_to_string(path)?;
    if previous.trim() != "0" {
        std::fs::write(path, b"0\n")?;
        log::warn!(
            "net.ipv6.bindv6only set to 0 (previous value {})",
            previous.trim()
        );
    }
    Ok(())
}
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    /// spec: P25, L12
    #[test]
    fn unsupported_or_expired_writes_are_refused() {
        let now = std::time::Instant::now();
        let future = now + std::time::Duration::from_secs(5);
        for (name, value, deadline) in [
            ("net.ipv4.ip_forward", "0", future),
            ("net.ipv6.bindv6only", "1", future),
            ("net.ipv6.bindv6only", "0", now),
        ] {
            assert!(!super::write(name, value, deadline), "{name}={value}");
        }
    }

    /// spec: P25
    #[test]
    fn writes_only_when_needed() {
        let dir = crate::testdir::Dir::new();
        let path = dir.path().join("value");
        std::fs::write(&path, "1\n").unwrap();
        super::set(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "0\n");
        let stamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1);
        std::fs::File::open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(stamp))
            .unwrap();
        super::set(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), stamp);
        assert!(super::set(&dir.path().join("absent")).is_err());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod namespace_tests {
    /// spec: P25, L12, K11, G10
    #[test]
    #[ignore = "isolated network namespace with CAP_NET_ADMIN and writable namespace sysctls"]
    fn whitelisted_writes_apply_only_to_the_callers_network_namespace() {
        let path = "/proc/sys/net/ipv6/bindv6only";
        let original = std::fs::read_to_string(path).unwrap();
        let namespace = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        for initial in ["1\n", "0\n"] {
            std::fs::write(path, initial).unwrap();
            assert!(super::write(
                "net.ipv6.bindv6only",
                "0",
                std::time::Instant::now() + std::time::Duration::from_secs(3),
            ));
            assert_eq!(std::fs::read_to_string(path).unwrap(), "0\n");
        }
        nix::sched::setns(namespace, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), original);
    }
}
