//! Effective capabilities through capget, without procfs (R49).
use std::io;
#[repr(C)]
struct Header {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
pub fn effective() -> io::Result<u64> {
    let mut header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(data[0].effective as u64 | ((data[1].effective as u64) << 32))
}
pub fn report() {
    match effective() {
        Ok(bits) => {
            for (bit, name, consequence) in [
                (
                    12,
                    "CAP_NET_ADMIN",
                    "tunnel, session and device operations may fail",
                ),
                (
                    13,
                    "CAP_NET_RAW",
                    "device binding and raw router discovery may fail",
                ),
                (
                    10,
                    "CAP_NET_BIND_SERVICE",
                    "DHCPv6 port 546 may be unavailable",
                ),
            ] {
                if bits & (1 << bit) == 0 {
                    log::warn!("missing {name}: {consequence}");
                }
            }
        }
        Err(error) => log::warn!("capget: {error}"),
    }
}
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    /// spec: R49, P23, G1
    #[test]
    fn capget_refusal_preserves_the_errno_and_reports_the_failure() {
        const CHILD: &str = "RS_L2TPD_TEST_CAPGET_REFUSAL";
        if std::env::var_os(CHILD).is_some() {
            crate::logger::init(false);
            crate::syscall_fault::refuse(&[nix::libc::SYS_capget], nix::libc::EPERM);
            assert_eq!(
                super::effective().unwrap_err().raw_os_error(),
                Some(nix::libc::EPERM)
            );
            super::report();
            println!("CAPGET_REFUSAL_VERIFIED");
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "caps::tests::capget_refusal_preserves_the_errno_and_reports_the_failure",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("CAPGET_REFUSAL_VERIFIED")
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("capget: Operation not permitted"),
            "{stderr}"
        );
    }

    /// spec: R49 P23
    #[test]
    fn effective_set_without_proc() {
        assert!(super::effective().is_ok());
    }
}
