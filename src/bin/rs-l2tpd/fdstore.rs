//! Native descriptor-store datagrams, barriers and initial handover (P14).
use nix::sys::socket::{ControlMessage, MsgFlags, UnixAddr, sendmsg};
use rs_l2tpd::{AdoptedSocket, Control, ControlEvent};
use std::ffi::OsString;
use std::io::{self, IoSlice, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
use std::time::{Duration, Instant};

pub struct Store {
    socket: UnixDatagram,
    address: UnixAddr,
}
impl Store {
    pub fn new(path: &std::ffi::OsStr) -> io::Result<Self> {
        let bytes = path.as_bytes();
        let address = if let Some(name) = bytes.strip_prefix(b"@") {
            UnixAddr::new_abstract(name)?
        } else {
            UnixAddr::new(std::path::Path::new(path))?
        };
        let socket = UnixDatagram::unbound()?;
        // kernel: net/unix/af_unix.c unix_dgram_connect; reject unusable stores at startup (P14).
        nix::sys::socket::connect(socket.as_raw_fd(), &address)?;
        Ok(Self { socket, address })
    }
    fn send(&self, text: &str, fd: Option<i32>) -> io::Result<()> {
        let fds = fd.into_iter().collect::<Vec<_>>();
        let rights = [ControlMessage::ScmRights(&fds)];
        sendmsg(
            self.socket.as_raw_fd(),
            &[IoSlice::new(text.as_bytes())],
            if fds.is_empty() { &[] } else { &rights },
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
            Some(&self.address),
        )?;
        Ok(())
    }
    pub fn store(&self, name: &str, fd: &OwnedFd) -> io::Result<()> {
        valid_name(name)?;
        self.send(&format!("FDSTORE=1\nFDNAME={name}"), Some(fd.as_raw_fd()))
    }
    pub fn forget(&self, name: &str, deadline: Instant) -> io::Result<()> {
        valid_name(name)?;
        self.send(&format!("FDSTOREREMOVE=1\nFDNAME={name}"), None)?;
        self.barrier(deadline)
    }
    fn barrier(&self, deadline: Instant) -> io::Result<()> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut read = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fds[0]) });
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        self.send("BARRIER=1", Some(write.as_raw_fd()))?;
        drop(write);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "descriptor-store processing barrier",
                ));
            }
            let mut poll = libc::pollfd {
                fd: read.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            let result = unsafe {
                libc::poll(
                    &mut poll,
                    1,
                    left.as_millis().min(i32::MAX as u128).max(1) as i32,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                continue;
            }
            match read.read(&mut [0]) {
                Ok(0) => return Ok(()),
                Ok(_) => return Err(io::Error::other("invalid barrier response")),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}
fn valid_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name.bytes().any(|b| b == b':' || b.is_ascii_control()) {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unusable inherited descriptor-store name",
        ))
    } else {
        Ok(())
    }
}
pub struct Inherited {
    pub sockets: Vec<AdoptedSocket>,
    pub notify: Option<OsString>,
    pub capacity: usize,
}
// Must precede file/socket opens, and runs only on the initial single thread.
pub fn inherit() -> io::Result<Inherited> {
    let pid = std::process::id();
    let listen_pid = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    let count = if listen_pid == Some(pid) {
        std::env::var("LISTEN_FDS")
            .ok()
            .map(|v| v.parse::<i32>())
            .transpose()
            .map_err(|_| io::Error::other("invalid LISTEN_FDS"))?
            .unwrap_or(0)
    } else {
        0
    };
    if !(0..=1_048_573).contains(&count) {
        return Err(io::Error::other("invalid LISTEN_FDS count"));
    }
    let names = std::env::var("LISTEN_FDNAMES").unwrap_or_default();
    let names: Vec<_> = if count == 0 {
        vec![]
    } else {
        names.split(':').collect()
    };
    let invalid = names.len() != count as usize || names.iter().any(|s| valid_name(s).is_err());
    close_from(3 + count as u32)?;
    // Environment mutation is confined to startup, before threads exist.
    unsafe {
        for key in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
            std::env::remove_var(key);
        }
    }
    let mut sockets = vec![];
    for fd in 3..3 + count {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::other(
                "announced descriptor is not open; store cleanup cannot be confirmed",
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        if !invalid {
            sockets.push(AdoptedSocket::new(names[(fd.as_raw_fd() - 3) as usize], fd));
        }
    }
    if invalid {
        return Err(io::Error::other(
            "malformed descriptor handover: names unavailable; store cleanup cannot be confirmed",
        ));
    }
    Ok(Inherited {
        sockets,
        notify: std::env::var_os("NOTIFY_SOCKET"),
        capacity: std::env::var("FDSTORE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
    })
}
fn close_from(first: u32) -> io::Result<()> {
    // Linux fs/open.c close_range: no procfs or per-descriptor loop on this path.
    if unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0u32) } == 0 {
        return Ok(());
    }
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // The hard limit covers descriptors opened before a soft-limit reduction.
    let limit = unsafe { limit.assume_init() }.rlim_max.min(i32::MAX as u64);
    close_individually(first, limit, Instant::now() + Duration::from_secs(1))
}

fn close_individually(first: u32, limit: u64, deadline: Instant) -> io::Result<()> {
    for fd in first as u64..limit {
        // A filtering container may refuse close_range and set an enormous limit.
        // Fail startup rather than hang or continue with unclosed descriptors.
        if (fd - first as u64).is_multiple_of(1024) && Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "closing inherited descriptors",
            ));
        }
        unsafe {
            libc::close(fd as i32);
        }
    }
    Ok(())
}
pub fn worker(
    mut requests: rs_l2tpd::runtime::Receiver<ControlEvent>,
    control: Control,
    store: Option<Store>,
) -> io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("l2tp-host".into())
        .spawn(move || {
            while let Some(event) = requests.blocking_recv() {
                match event {
                    ControlEvent::WriteTunable {
                        name,
                        value,
                        id,
                        deadline,
                    } => {
                        let success = super::tunable::write(name, value, deadline);
                        let _ = control.tunable_written_blocking(id, success);
                    }
                    ControlEvent::StoreSocket { name, fd, .. } => {
                        if let Some(store) = &store
                            && let Err(error) = store.store(&name, &fd)
                        {
                            log::warn!("descriptor store {name}: {error}");
                        }
                    }
                    ControlEvent::ForgetSocket { name, id, deadline } => {
                        let processed = match &store {
                            Some(store) => match store.forget(&name, deadline) {
                                Ok(()) => true,
                                Err(error) => {
                                    log::warn!("descriptor withdrawal {name}: {error}");
                                    false
                                }
                            },
                            None => true,
                        };
                        let _ = control.socket_forgotten_blocking(id, processed);
                    }
                    _ => (),
                }
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{ControlMessageOwned, recvmsg};
    use std::io::IoSliceMut;
    use std::time::Duration;
    /// spec: P14 P23
    #[test]
    fn rights_and_ordered_processing_barrier() {
        let dir = crate::testdir::Dir::new();
        let path = dir.path().join("notify");
        let listener = UnixDatagram::bind(&path).unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let manager = std::thread::spawn(move || {
            for expected in [
                "FDSTORE=1\nFDNAME=t17",
                "FDSTOREREMOVE=1\nFDNAME=t17",
                "BARRIER=1",
            ] {
                let mut bytes = [0; 256];
                let mut iov = [IoSliceMut::new(&mut bytes)];
                let mut cmsg = nix::cmsg_space!([i32; 1]);
                let message = recvmsg::<()>(
                    listener.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg),
                    MsgFlags::MSG_CMSG_CLOEXEC,
                )
                .unwrap();
                let count = message.bytes;
                let mut rights = vec![];
                for cmsg in message.cmsgs().unwrap() {
                    if let ControlMessageOwned::ScmRights(fds) = cmsg {
                        for fd in fds {
                            rights.push(unsafe { OwnedFd::from_raw_fd(fd) });
                        }
                    }
                }
                assert_eq!(&bytes[..count], expected.as_bytes());
                assert_eq!(
                    rights.len(),
                    usize::from(!expected.starts_with("FDSTOREREMOVE"))
                );
                drop(rights);
            }
        });
        let store = Store::new(path.as_os_str()).unwrap();
        let file = std::fs::File::open("/dev/null").unwrap().into();
        store.store("t17", &file).unwrap();
        store
            .forget("t17", Instant::now() + Duration::from_secs(2))
            .unwrap();
        manager.join().unwrap();
        assert!(store.store("t17\nFDSTORE=0", &file).is_err());
    }
    /// spec: P14 P17
    #[test]
    fn barrier_timeout_is_a_failure() {
        let dir = crate::testdir::Dir::new();
        let path = dir.path().join("notify");
        let _listener = UnixDatagram::bind(&path).unwrap();
        let store = Store::new(path.as_os_str()).unwrap();
        assert_eq!(
            store.forget("t1", Instant::now()).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}

#[cfg(test)]
mod manager_tests {
    use super::*;
    /// spec: P14 P21 P23
    #[test]
    #[ignore = "run in a user systemd service with the template address-family restrictions"]
    fn actual_manager_processing_and_address_family_filter() {
        let unit = std::env::var("PHASE5_NOTIFY_UNIT").unwrap();
        let families = include_str!("../../../contrib/rs-l2tpd.service.in")
            .lines()
            .find_map(|line| line.strip_prefix("RestrictAddressFamilies="))
            .unwrap();
        let query = |property: &str| {
            let output = std::process::Command::new("systemctl")
                .args([
                    "--user",
                    "--no-pager",
                    "--value",
                    "--property",
                    property,
                    "show",
                    &unit,
                ])
                .env("SYSTEMD_PAGER", "cat")
                .output()
                .unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        let actual = query("RestrictAddressFamilies");
        for family in families.split_whitespace() {
            assert!(actual.split_whitespace().any(|f| f == family));
        }
        let store = Store::new(&std::env::var_os("NOTIFY_SOCKET").unwrap()).unwrap();
        store.send("READY=1", None).unwrap();
        let file = std::fs::File::open("/dev/null").unwrap().into();
        store.store("t17", &file).unwrap();
        store
            .barrier(Instant::now() + std::time::Duration::from_secs(3))
            .unwrap();
        assert_eq!(query("NFileDescriptorStore"), "1");
        store
            .forget("t17", Instant::now() + std::time::Duration::from_secs(3))
            .unwrap();
        assert_eq!(query("NFileDescriptorStore"), "0");
    }
}

#[cfg(test)]
mod completion_tests {
    use super::*;

    /// spec: P14, P17
    #[test]
    fn fallback_closing_is_bounded_without_trusting_the_soft_limit() {
        assert_eq!(
            close_individually(3, i32::MAX as u64, Instant::now())
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        if std::env::var_os("COMPLETION_CLOSE_CHILD").is_none() {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "fdstore::completion_tests::fallback_closing_is_bounded_without_trusting_the_soft_limit"])
                .env("COMPLETION_CLOSE_CHILD", "1").status().unwrap().success());
            return;
        }
        let fd = std::fs::File::open("/dev/null").unwrap();
        let high = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD, 100) };
        assert!(high >= 100);
        let limits = libc::rlimit {
            rlim_cur: 32,
            rlim_max: 256,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);
        // Exercise the fallback independently of close_range availability.
        close_individually(3, limits.rlim_max, Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!(unsafe { libc::fcntl(high, libc::F_GETFD) }, -1);
        std::mem::forget(fd); // Its descriptor was deliberately closed above.
    }
}
