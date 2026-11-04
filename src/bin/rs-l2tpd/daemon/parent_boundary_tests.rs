//! Parent readiness, interrupted syscalls and shutdown ordering.
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

fn parent_boundary_child(root: PathBuf) {
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
        write
            .write_all(&[u8::from(case != "invalid-readiness")])
            .unwrap();
    }
    std::fs::write(root.join("writer-fd"), write.as_raw_fd().to_string()).unwrap();
    std::fs::write(root.join("first-pid"), first.0.id().to_string()).unwrap();
    #[cfg(coverage_nightly)]
    crate::syscall_fault::keep_profile_output();
    crate::syscall_barrier::stop().unwrap();
    if case == "wait-error" {
        crate::syscall_fault::on_exec_argument(libc::SYS_wait4, 0, first.0.id(), libc::EIO)()
            .unwrap();
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
            matches!(result.unwrap(), Started::Parent(code) if code == u8::from(matches!(case, "stop-before-pid" | "invalid-readiness")))
        );
    }
    assert_eq!(
        HANDLED.load(Ordering::Relaxed),
        usize::from(case.ends_with("interrupted"))
    );
    println!("DAEMON_PARENT_BOUNDARY_CHECKED={case}");
}

struct ParentTrace<'a> {
    root: &'a std::path::Path,
    case: &'a str,
    waits: usize,
    polls: usize,
    delivered: bool,
}

impl ParentTrace<'_> {
    fn step(&mut self, tid: i32, number: u64, arguments: [u64; 6]) -> io::Result<()> {
        if self.root.join("finished").exists() {
            return Ok(());
        }
        let first: u32 = std::fs::read_to_string(self.root.join("first-pid"))?
            .parse()
            .unwrap();
        if number == libc::SYS_wait4 as u64 && arguments[0] as u32 == first {
            self.waits += 1;
            if self.case == "wait-interrupted" && self.waits == 2 {
                std::fs::write(self.root.join("go"), "")?;
            }
        }
        if POLL.iter().any(|poll| *poll as u64 == number) {
            self.polls += 1;
            if self.polls == 2 && matches!(self.case, "poll-interrupted" | "poll-timeout") {
                let fd = std::fs::read_to_string(self.root.join("writer-fd"))?;
                std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(format!("/proc/{tid}/fd/{}", fd.trim()))?
                    .write_all(&[1])?;
            }
        }
        if !self.delivered
            && ((self.case == "wait-interrupted" && self.waits == 1)
                || (self.case == "poll-interrupted" && self.polls == 1))
        {
            let status = std::fs::read_to_string(format!("/proc/{tid}/status"))?;
            let group: i32 = status
                .lines()
                .find_map(|line| line.strip_prefix("Tgid:"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            // kernel: kernel/signal.c do_tkill targets only this stopped, owned worker.
            if unsafe { libc::syscall(libc::SYS_tgkill, group, tid, libc::SIGUSR1) } != 0 {
                return Err(io::Error::last_os_error());
            }
            self.delivered = true;
        }
        Ok(())
    }
}

/// spec: P4, P12, P22, G1
#[test]
fn parent_wait_and_readiness_failures_are_bounded_and_preserve_shutdown() {
    const CHILD: &str = "PHASE6_DAEMON_PARENT_BOUNDARY";
    if let Some(root) = std::env::var_os(CHILD) {
        parent_boundary_child(PathBuf::from(root));
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
        "invalid-readiness",
    ] {
        let root = directory.path().join(case);
        std::fs::create_dir(&root).unwrap();
        let mut trace = ParentTrace {
            root: &root,
            case,
            waits: 0,
            polls: 0,
            delivered: false,
        };
        let output = crate::syscall_barrier::run(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "daemon::parent_boundary_tests::parent_wait_and_readiness_failures_are_bounded_and_preserve_shutdown", "--nocapture"])
                .env(CHILD, &root),
            &root,
            |tid, number, arguments| trace.step(tid, number, arguments),
        ).unwrap();
        assert!(output.status.success(), "{case}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("DAEMON_PARENT_BOUNDARY_CHECKED=")
        );
        assert_eq!(
            trace.waits,
            if case == "wait-interrupted" { 2 } else { 1 },
            "{case}"
        );
        if matches!(case, "poll-interrupted" | "poll-timeout") {
            assert_eq!(trace.polls, 2, "{case}");
        }
    }
}
