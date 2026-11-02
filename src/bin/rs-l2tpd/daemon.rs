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
    let read = unsafe { File::from_raw_fd(fds[0]) };
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
                _ => unsafe {
                    #[cfg(coverage_nightly)]
                    crate::flush_profile();
                    libc::_exit(0)
                },
            }
            notify(&mut write, &std::process::id().to_ne_bytes())?;
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
            parent(read, child)
        }
    }
}
fn parent(mut read: File, child: i32) -> io::Result<Started> {
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
            let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), Signal::SIGTERM);
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
// kernel: fs/pipe.c pipe_write (v6.8), anon_pipe_write (v7.3): no reader -> EPIPE + SIGPIPE.
fn notify(pipe: &mut File, bytes: &[u8]) -> io::Result<()> {
    match pipe.write_all(bytes) {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
            log::warn!("readiness parent: {error}");
            Ok(())
        }
        result => result,
    }
}
pub fn ready(pipe: &mut Option<File>) {
    if let Some(mut pipe) = pipe.take()
        && let Err(error) = notify(&mut pipe, &[1])
    {
        log::warn!("readiness parent: {error}");
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    /// spec: P12 P22
    #[test]
    fn broken_pipe_and_collector_shutdown_child() {
        if std::env::var_os("PHASE5_PIPE_CHILD").is_none() {
            return;
        }
        crate::logger::init(false);
        let signals = crate::signals::Signals::install().unwrap();
        let mask = SigSet::thread_get_mask().unwrap();
        assert!(!mask.contains(Signal::SIGUSR1));
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        unsafe {
            libc::close(fds[0]);
        }
        let mut pipe = unsafe { File::from_raw_fd(fds[1]) };
        notify(&mut pipe, &std::process::id().to_ne_bytes()).unwrap();
        let mut pipe = Some(pipe);
        ready(&mut pipe);
        assert!(pipe.is_none());
        let mut invalid = File::open("/dev/null").unwrap();
        assert!(notify(&mut invalid, &[1]).is_err());
        ready(&mut Some(invalid));
        drop(signals);
    }
    /// spec: P12 P22
    #[test]
    fn vanished_parent_is_logged_and_signal_threads_join() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "daemon::tests::broken_pipe_and_collector_shutdown_child",
                "--nocapture",
            ])
            .env("PHASE5_PIPE_CHILD", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
        let logs = String::from_utf8(output.stderr).unwrap();
        assert_eq!(logs.matches("readiness parent:").count(), 3, "{logs}");
        assert_eq!(logs.matches("Broken pipe").count(), 2, "{logs}");
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod parent_boundary_tests {
    use super::*;
    use nix::sys::signal::{SaFlags, SigAction, SigHandler, sigaction};
    use nix::sys::wait::{Id, WaitPidFlag, waitid};
    use nix::unistd::Pid;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::process::{Child, Command};
    use std::sync::atomic::AtomicUsize;

    const POLL: &[libc::c_long] = &[
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "arm",
            target_arch = "powerpc64"
        ))]
        libc::SYS_poll,
        libc::SYS_ppoll,
    ];
    static HANDLED: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn interrupted(_: i32) {
        HANDLED.fetch_add(1, Ordering::Relaxed);
    }
    struct Owned(Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            // The wait-error fixture filters wait4 for this child; waitid still reaps it.
            let _ = waitid(
                Id::Pid(Pid::from_raw(self.0.id() as i32)),
                WaitPidFlag::WEXITED,
            );
        }
    }

    /// spec: P4, P12, P22, G1
    #[test]
    fn parent_wait_and_readiness_failures_are_bounded_and_preserve_shutdown() {
        const CHILD: &str = "PHASE6_DAEMON_PARENT_BOUNDARY";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = PathBuf::from(root);
            let case = root.file_name().unwrap().to_str().unwrap();
            unsafe {
                sigaction(
                    Signal::SIGUSR1,
                    &SigAction::new(
                        SigHandler::Handler(interrupted),
                        SaFlags::empty(),
                        SigSet::empty(),
                    ),
                )
                .unwrap();
            }
            let first = if case == "wait-interrupted" {
                Owned(
                    Command::new("timeout")
                        .args([
                            "5",
                            "/bin/sh",
                            "-c",
                            "while [ ! -f \"$1/go\" ]; do :; done",
                            "sh",
                        ])
                        .arg(&root)
                        .spawn()
                        .unwrap(),
                )
            } else {
                Owned(Command::new("/bin/true").spawn().unwrap())
            };
            let daemon = Owned(Command::new("/bin/sleep").arg("30").spawn().unwrap());
            let (read, write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
            let mut write = File::from(write);
            write.write_all(&daemon.0.id().to_ne_bytes()).unwrap();
            if !case.starts_with("poll") {
                write.write_all(&[1]).unwrap();
            }
            std::fs::write(root.join("writer-fd"), write.as_raw_fd().to_string()).unwrap();
            std::fs::write(root.join("first-pid"), first.0.id().to_string()).unwrap();
            #[cfg(coverage_nightly)]
            crate::syscall_fault::keep_profile_output();
            crate::syscall_barrier::stop().unwrap();
            if case == "wait-error" {
                crate::syscall_fault::on_exec_argument(libc::SYS_wait4, 0, first.0.id(), libc::EIO)().unwrap();
            }
            if case == "poll-error" {
                crate::syscall_fault::refuse(POLL, libc::EIO);
            }
            if case == "stop-before-pid" {
                assert_eq!(DAEMON_PID.load(Ordering::Relaxed), 0);
                stop_parent(0);
            }
            let result = parent(File::from(read), first.0.id() as i32);
            std::fs::write(root.join("finished"), "").unwrap();
            std::fs::write(root.join("go"), "").unwrap();
            drop(write);
            drop(first);
            drop(daemon);
            if case == "poll-error" {
                assert_eq!(result.err().unwrap().raw_os_error(), Some(libc::EIO));
            } else {
                assert!(
                    matches!(result.unwrap(), Started::Parent(code) if code == u8::from(case == "stop-before-pid"))
                );
            }
            assert_eq!(
                HANDLED.load(Ordering::Relaxed),
                usize::from(case.ends_with("interrupted"))
            );
            println!("DAEMON_PARENT_BOUNDARY_CHECKED={case}");
            return;
        }
        let directory = crate::testdir::Dir::new();
        for case in [
            "wait-error",
            "wait-interrupted",
            "poll-error",
            "poll-interrupted",
            "poll-timeout",
            "stop-before-pid",
        ] {
            let root = directory.path().join(case);
            std::fs::create_dir(&root).unwrap();
            let mut waits = 0;
            let mut polls = 0;
            let mut delivered = false;
            let output = crate::syscall_barrier::run(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "daemon::parent_boundary_tests::parent_wait_and_readiness_failures_are_bounded_and_preserve_shutdown", "--nocapture"])
                    .env(CHILD, &root),
                &root,
                |tid, number, arguments| {
                    if root.join("finished").exists() { return Ok(()); }
                    let first: u32 = std::fs::read_to_string(root.join("first-pid"))?.parse().unwrap();
                    if number == libc::SYS_wait4 as u64 && arguments[0] as u32 == first {
                        waits += 1;
                        if case == "wait-interrupted" && waits == 2 {
                            std::fs::write(root.join("go"), "")?;
                        }
                    }
                    if POLL.iter().any(|poll| *poll as u64 == number) {
                        polls += 1;
                        if polls == 2 && matches!(case, "poll-interrupted" | "poll-timeout") {
                            let fd = std::fs::read_to_string(root.join("writer-fd"))?;
                            std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(format!("/proc/{tid}/fd/{}", fd.trim()))?.write_all(&[1])?;
                        }
                    }
                    if !delivered && ((case == "wait-interrupted" && waits == 1) || (case == "poll-interrupted" && polls == 1)) {
                        let status = std::fs::read_to_string(format!("/proc/{tid}/status"))?;
                        let group: i32 = status.lines().find_map(|line| line.strip_prefix("Tgid:")) .unwrap().trim().parse().unwrap();
                        // kernel: kernel/signal.c do_tkill targets only this stopped, owned worker.
                        if unsafe { libc::syscall(libc::SYS_tgkill, group, tid, libc::SIGUSR1) } != 0 {
                            return Err(io::Error::last_os_error());
                        }
                        delivered = true;
                    }
                    Ok(())
                },
            ).unwrap();
            assert!(output.status.success(), "{case}: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("DAEMON_PARENT_BOUNDARY_CHECKED=")
            );
            assert_eq!(
                waits,
                if case == "wait-interrupted" { 2 } else { 1 },
                "{case}"
            );
            if matches!(case, "poll-interrupted" | "poll-timeout") {
                assert_eq!(polls, 2, "{case}");
            }
        }
    }
}
