//! Single-threaded double fork and readiness pipe (P4).
use nix::sys::signal::{SigSet, Signal};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

pub enum Started {
    Parent(u8),
    Child(Option<File>),
}
static STOP_PARENT: AtomicBool = AtomicBool::new(false);
static DAEMON_PID: AtomicI32 = AtomicI32::new(0);
extern "C" fn stop_parent(_: i32) {
    STOP_PARENT.store(true, Ordering::Relaxed);
    let pid = DAEMON_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
}
pub fn start(foreground: bool) -> io::Result<Started> {
    super::signals::prepare()?;
    if foreground {
        return Ok(Started::Child(None));
    }
    let mut fds = [-1; 2];
    // Called before any thread exists; each branch owns its end of this pipe.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut read = unsafe { File::from_raw_fd(fds[0]) };
    let mut write = unsafe { File::from_raw_fd(fds[1]) };
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            drop(read);
            if unsafe { libc::setsid() } < 0 {
                return Err(io::Error::last_os_error());
            }
            match unsafe { libc::fork() } {
                -1 => return Err(io::Error::last_os_error()),
                0 => (),
                _ => unsafe { libc::_exit(0) },
            }
            write.write_all(&std::process::id().to_ne_bytes())?;
            let null = File::open("/dev/null")?;
            if unsafe { libc::dup2(null.as_raw_fd(), 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe {
                libc::umask(0o077);
            }
            Ok(Started::Child(Some(write)))
        }
        child => {
            drop(write);
            unsafe {
                libc::signal(
                    libc::SIGTERM,
                    stop_parent as *const () as libc::sighandler_t,
                );
                libc::signal(libc::SIGINT, stop_parent as *const () as libc::sighandler_t);
            }
            let mut shutdown = SigSet::empty();
            shutdown.add(Signal::SIGTERM);
            shutdown.add(Signal::SIGINT);
            shutdown.thread_unblock()?;
            let mut status = 0;
            while unsafe { libc::waitpid(child, &mut status, 0) } < 0 {
                if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
            let mut pid = [0; 4];
            if read.read_exact(&mut pid).is_err() {
                return Ok(Started::Parent(1));
            }
            let pid = u32::from_ne_bytes(pid) as i32;
            DAEMON_PID.store(pid, Ordering::Relaxed);
            loop {
                if STOP_PARENT.load(Ordering::Relaxed) {
                    let _ =
                        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), Signal::SIGTERM);
                    return Ok(Started::Parent(1));
                }
                let mut poll = libc::pollfd {
                    fd: read.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                };
                let result = unsafe { libc::poll(&mut poll, 1, 100) };
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
                let mut byte = [0];
                let ready = read.read_exact(&mut byte).is_ok()
                    && byte == [1]
                    && !STOP_PARENT.load(Ordering::Relaxed);
                return Ok(Started::Parent(u8::from(!ready)));
            }
        }
    }
}
pub fn ready(pipe: &mut Option<File>) {
    if let Some(mut pipe) = pipe.take()
        && let Err(error) = pipe.write_all(&[1])
    {
        log::warn!("readiness parent: {error}");
    }
}
