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
mod tests {
    /// spec: R49 P23
    #[test]
    fn effective_set_without_proc() {
        assert!(super::effective().is_ok());
    }
}
