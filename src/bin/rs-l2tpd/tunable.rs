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
    /// spec: P25
    #[test]
    fn writes_only_when_needed() {
        let dir = crate::testdir::Dir::new();
        let path = dir.path().join("value");
        std::fs::write(&path, "1\n").unwrap();
        super::set(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "0\n");
        super::set(&path).unwrap();
        assert!(super::set(&dir.path().join("absent")).is_err());
    }
}
