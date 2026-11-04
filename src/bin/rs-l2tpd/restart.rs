//! Versioned, same-process exec with isolated descriptor shuffling (P26).
use super::pidfile::PidFile;
use rs_l2tpd::AdoptedSocket;
use std::ffi::OsString;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const VERSION: &str = "rs-l2tpd-adopt 1\n";
pub struct Entry {
    pub reexec: bool,
    pub pid: Option<PidFile>,
}
pub fn entry() -> io::Result<Entry> {
    let marker = std::env::var_os("RS_L2TPD_REEXEC");
    let state = std::env::var_os("RS_L2TPD_PIDFILE");
    // Entry is single-threaded; consume internal state even on errors.
    unsafe {
        std::env::remove_var("RS_L2TPD_REEXEC");
        std::env::remove_var("RS_L2TPD_PIDFILE");
    }
    match marker {
        None if state.is_none() => {
            return Ok(Entry {
                reexec: false,
                pid: None,
            });
        }
        Some(marker) if marker == format!("1:{}", std::process::id()).as_str() => (),
        _ => return Err(io::Error::other("invalid re-exec marker/state")),
    }
    if std::env::var("LISTEN_PID").ok().as_deref() != Some(&std::process::id().to_string())
        || std::env::var("LISTEN_FDS")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .is_none()
    {
        return Err(io::Error::other("invalid re-exec descriptor announcement"));
    }
    let state = state.ok_or_else(|| io::Error::other("missing re-exec PID-file state"))?;
    let state = state
        .to_str()
        .ok_or_else(|| io::Error::other("invalid re-exec state encoding"))?;
    let pid = if state == "1:none" {
        None
    } else {
        let fields: Vec<_> = state.split(':').collect();
        if fields.len() != 4 || fields[0] != "1" {
            return Err(io::Error::other("invalid re-exec PID-file state"));
        }
        let parse = |s: &str| {
            s.parse::<u64>()
                .map_err(|_| io::Error::other("invalid re-exec inode"))
        };
        let encoded = fields[3].as_bytes();
        if encoded.len() % 2 != 0 {
            return Err(io::Error::other("invalid re-exec pathname"));
        }
        let bytes: Option<Vec<u8>> = encoded
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digit = |b: u8| (b as char).to_digit(16).map(|n| n as u8);
                Some(digit(pair[0])? * 16 + digit(pair[1])?)
            })
            .collect();
        let path = PathBuf::from(OsString::from_vec(
            bytes.ok_or_else(|| io::Error::other("invalid re-exec pathname"))?,
        ));
        if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
            return Err(io::Error::other("invalid re-exec PID path"));
        }
        let pid = PidFile {
            path,
            dev: parse(fields[1])?,
            ino: parse(fields[2])?,
        };
        match pid.matches() {
            Ok(true) => Some(pid),
            Ok(false) => {
                log::warn!("re-exec PID file no longer matches; removal authority discarded");
                None
            }
            Err(error) => {
                log::warn!(
                    "re-exec PID file could not be inspected: {error}; removal authority discarded"
                );
                None
            }
        }
    };
    Ok(Entry { reexec: true, pid })
}
fn state(pid: Option<&PidFile>) -> String {
    match pid {
        None => "1:none".into(),
        Some(pid) => {
            let path: String = pid
                .path
                .as_os_str()
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            format!("1:{}:{}:{path}", pid.dev, pid.ino)
        }
    }
}
// Resolve argv[0] before chdir: current_exe names the old inode on Linux.
pub fn executable_at(
    argv0: &std::ffi::OsStr,
    original: io::Result<PathBuf>,
) -> io::Result<PathBuf> {
    let input = Path::new(argv0);
    if input.is_absolute() {
        return Ok(input.to_owned());
    }
    let original = original?;
    if input.components().count() > 1 {
        return Ok(original.join(input));
    }
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let candidate = original.join(directory).join(input);
        if let Ok(metadata) = candidate.metadata() {
            use std::os::unix::fs::PermissionsExt;
            if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
                return Ok(candidate);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "cannot resolve executable path",
    ))
}
fn probe(path: &Path) -> io::Result<()> {
    let mut child = Command::new(path)
        .arg("--adopt-version")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = probe_output(&mut child);
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

fn drain_probe(stdout: &mut std::process::ChildStdout, output: &mut Vec<u8>) -> io::Result<()> {
    let mut bytes = [0; 64];
    loop {
        match stdout.read(&mut bytes) {
            Ok(0) => break,
            Ok(count) => {
                output.extend_from_slice(&bytes[..count]);
                if output.len() > VERSION.len() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn probe_output(child: &mut std::process::Child) -> io::Result<()> {
    let mut stdout = child.stdout.take().unwrap();
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    fcntl(&stdout, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    let mut output = vec![];
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut bytes = [0; 64];
        match stdout.read(&mut bytes) {
            Ok(count) => output.extend_from_slice(&bytes[..count]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
        if output.len() > VERSION.len() {
            return Err(io::Error::other("incompatible adoption protocol"));
        }
        if let Some(status) = child.try_wait()? {
            // Drain the small remaining pipe payload after process exit.
            drain_probe(&mut stdout, &mut output)?;
            return if status.success() && output == VERSION.as_bytes() {
                Ok(())
            } else {
                Err(io::Error::other("incompatible adoption protocol"))
            };
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "adoption probe"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
pub fn exec(
    path: &Path,
    arguments: &[OsString],
    sockets: Vec<AdoptedSocket>,
    pid: Option<&PidFile>,
) -> io::Result<()> {
    probe(path)?;
    let mut command = Command::new(path);
    command
        .args(arguments)
        .env("LISTEN_PID", std::process::id().to_string())
        .env("LISTEN_FDS", sockets.len().to_string())
        .env(
            "LISTEN_FDNAMES",
            sockets
                .iter()
                .map(|s| s.name())
                .collect::<Vec<_>>()
                .join(":"),
        )
        .env("RS_L2TPD_REEXEC", format!("1:{}", std::process::id()))
        .env("RS_L2TPD_PIDFILE", state(pid));
    // Command::exec resets SIGPIPE even on failure; restore P12 before execve.
    unsafe {
        command.pre_exec(super::signals::ignore_pipe);
    }
    let raw: Vec<_> = sockets.iter().map(|s| s.fd().as_raw_fd()).collect();
    // A private fd table prevents dup2 from clobbering live subscription fds.
    // On exec failure only this short-lived thread loses its private table.
    let error = std::thread::Builder::new()
        .name("l2tp-exec".into())
        .spawn(move || -> io::Error {
            if unsafe { libc::unshare(libc::CLONE_FILES) } < 0 {
                return io::Error::last_os_error();
            }
            let mut copies = vec![];
            for fd in &raw {
                let copy = unsafe { libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 3 + raw.len() as i32) };
                if copy < 0 {
                    return io::Error::last_os_error();
                }
                copies.push(copy);
            }
            for (index, fd) in copies.iter().enumerate() {
                if unsafe { libc::dup2(*fd, 3 + index as i32) } < 0 {
                    return io::Error::last_os_error();
                }
            }
            // kernel: kernel/signal.c flush_signal_handlers; Rust unix do_exec (1.89+).
            // The mask survives exec; the hook preserves SIGPIPE ignore on either outcome.
            command.exec()
        })?
        .join()
        .map_err(exec_panicked)?;
    drop(sockets);
    Err(error)
}
pub fn signal(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 32
    {
        return Err(io::Error::other("unsafe PID file"));
    }
    let mut text = String::new();
    file.take(33).read_to_string(&mut text)?;
    let number = text
        .strip_suffix('\n')
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && text.len() <= 32)
        .ok_or_else(|| io::Error::other("invalid PID file"))?;
    let pid = number
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid > 1)
        .ok_or_else(|| io::Error::other("invalid PID file"))?;
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGUSR2,
    )?;
    Ok(())
}
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    /// spec: P26
    #[test]
    fn incompatible_probe_never_executes_or_changes_descriptors() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let fd = file.as_raw_fd();
        let socket = AdoptedSocket::new("t1", file.into());
        assert!(exec(Path::new("/bin/false"), &[], vec![socket], None).is_err());
        // A separate live descriptor is unaffected by the rejected request.
        let other = std::fs::File::open("/dev/null").unwrap();
        assert!(other.metadata().is_ok());
        let _ = fd;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod exec_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    /// spec: P26, P27, G12
    #[test]
    fn probe_and_pid_read_failures_return_errno_before_handover() {
        const CHILD: &str = "RS_L2TPD_PROBE_IO_FAULT";
        let Ok(case) = std::env::var(CHILD) else {
            for case in [
                "nonblock",
                "read",
                "interrupted-read",
                "blocked-read",
                "wait",
                "probe-sigpipe",
                "exec-sigpipe",
                "pid-read",
            ] {
                let output = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "restart::exec_tests::probe_and_pid_read_failures_return_errno_before_handover", "--nocapture"])
                    .env(CHILD, case)
                    .output()
                    .unwrap();
                assert!(output.status.success(), "{case}: {output:?}");
                assert!(
                    String::from_utf8_lossy(&output.stdout).contains("PROBE_IO_FAILURE_CHECKED="),
                    "{case}: {output:?}"
                );
            }
            return;
        };
        let dir = crate::testdir::Dir::new();
        let target = dir.path().join("compatible-probe");
        std::fs::write(&target, "#!/bin/sh\nprintf 'rs-l2tpd-adopt 1\\n'\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        if case == "exec-sigpipe" {
            std::fs::write(
                &target,
                format!(
                    "#!/bin/sh\n: > '{}/probe-checked'\nprintf 'rs-l2tpd-adopt 1\\n'\n",
                    dir.path().display()
                ),
            )
            .unwrap();
        }
        let held = std::fs::File::open("/dev/null").unwrap();
        #[cfg(coverage_nightly)]
        crate::syscall_fault::keep_profile_output();
        // In this isolated worker, the next open/pipe receives this free slot.
        let next = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        assert!(next >= 0);
        assert_eq!(unsafe { libc::close(next) }, 0);
        match case.as_str() {
            "nonblock" => crate::syscall_fault::on_exec_argument(
                libc::SYS_fcntl,
                1,
                libc::F_SETFL as u32,
                libc::EIO,
            )()
            .unwrap(),
            "read" | "pid-read" | "interrupted-read" | "blocked-read" => {
                let errno = match case.as_str() {
                    "interrupted-read" => libc::EINTR,
                    "blocked-read" => libc::EAGAIN,
                    _ => libc::EIO,
                };
                crate::syscall_fault::on_exec_argument(libc::SYS_read, 0, next as u32, errno)()
                    .unwrap()
            }
            "wait" => crate::syscall_fault::refuse(&[libc::SYS_wait4], libc::EIO),
            "probe-sigpipe" => crate::syscall_fault::on_exec_argument(
                libc::SYS_rt_sigaction,
                0,
                libc::SIGPIPE as u32,
                libc::EIO,
            )()
            .unwrap(),
            "exec-sigpipe" => {
                crate::syscall_fault::on_exec_signal_install(libc::EIO)().unwrap();
                // Query-only and write-only calls must remain available.
                let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut action) },
                    0
                );
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGPIPE, &action, std::ptr::null_mut()) },
                    0
                );
                let mut old = unsafe { std::mem::zeroed::<libc::sigaction>() };
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGUSR1, &action, &mut old) },
                    0
                );
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGUSR1, &old, std::ptr::null_mut()) },
                    0
                );
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGPIPE, &action, &mut old) },
                    -1
                );
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EIO));
                #[cfg(target_arch = "x86_64")]
                for (new, old) in [
                    (1_u64 << 32, &mut old as *mut libc::sigaction as u64),
                    (&action as *const libc::sigaction as u64, 1_u64 << 32),
                    (1_u64 << 32, 1_u64 << 32),
                ] {
                    // Check high-only pointer words before the kernel could dereference them.
                    assert_eq!(
                        unsafe {
                            libc::syscall(libc::SYS_rt_sigaction, libc::SIGPIPE, new, old, 8_usize)
                        },
                        -1
                    );
                    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EIO));
                }
            }
            _ => panic!("unknown probe failure"),
        }
        let error = if case == "pid-read" {
            let pid = dir.path().join("pid");
            std::fs::write(&pid, "2\n").unwrap();
            std::fs::set_permissions(&pid, std::fs::Permissions::from_mode(0o600)).unwrap();
            signal(&pid).unwrap_err()
        } else if case.ends_with("sigpipe") {
            exec(&target, &[], vec![], None).unwrap_err()
        } else {
            probe(&target).unwrap_err()
        };
        if case == "blocked-read" {
            assert_eq!(error.to_string(), "incompatible adoption protocol");
        } else {
            assert_eq!(
                error.raw_os_error(),
                Some(if case == "interrupted-read" {
                    libc::EINTR
                } else {
                    libc::EIO
                }),
                "{case}: {error}"
            );
        }
        assert!(held.metadata().is_ok());
        if case == "exec-sigpipe" {
            assert!(
                dir.path().join("probe-checked").exists(),
                "compatibility probe did not complete"
            );
        }
        println!("PROBE_IO_FAILURE_CHECKED={case}");
    }
    /// spec: P26, G12
    #[test]
    fn descriptor_preparation_failures_leave_the_callers_table_unchanged() {
        const CHILD: &str = "RS_L2TPD_EXEC_PREPARATION_FAULT";
        let Ok(case) = std::env::var(CHILD) else {
            for case in ["unshare", "copy", "move"] {
                let output = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "restart::exec_tests::descriptor_preparation_failures_leave_the_callers_table_unchanged", "--nocapture"])
                    .env(CHILD, case)
                    .output()
                    .unwrap();
                assert!(output.status.success(), "{case}: {output:?}");
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .contains("EXEC_PREPARATION_FAILURE_CHECKED="),
                    "{case}: {output:?}"
                );
            }
            return;
        };
        let dir = crate::testdir::Dir::new();
        let target = dir.path().join("compatible-probe");
        std::fs::write(&target, "#!/bin/sh\nprintf 'rs-l2tpd-adopt 1\\n'\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let held = std::fs::File::open("/dev/null").unwrap();
        let flags = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFD) };
        let socket = AdoptedSocket::new("t1", held.try_clone().unwrap().into());
        match case.as_str() {
            "unshare" => crate::syscall_fault::refuse(&[libc::SYS_unshare], libc::EIO),
            "copy" => crate::syscall_fault::on_exec_arguments(
                libc::SYS_fcntl,
                libc::F_DUPFD_CLOEXEC,
                4,
                libc::EIO,
            )()
            .unwrap(),
            "move" => {
                for &syscall in crate::syscall_fault::DUP_SYSCALLS {
                    crate::syscall_fault::on_exec_argument(syscall, 1, 3, libc::EIO)().unwrap();
                }
            }
            _ => panic!("unknown exec failure"),
        }
        let error = exec(&target, &[], vec![socket], None).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO), "{case}");
        assert!(held.metadata().is_ok());
        assert_eq!(
            unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFD) },
            flags
        );
        println!("EXEC_PREPARATION_FAILURE_CHECKED={case}");
    }
    /// spec: P26
    #[test]
    fn failed_exec_after_a_compatible_probe_keeps_the_shared_table() {
        if std::env::var_os("PHASE5_FAILED_EXEC_CHILD").is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "restart::exec_tests::failed_exec_after_a_compatible_probe_keeps_the_shared_table", "--nocapture"])
                .env("PHASE5_FAILED_EXEC_CHILD", "1").output().unwrap();
            assert!(output.status.success(), "{output:?}");
            return;
        }
        let dir = crate::testdir::Dir::new();
        let target = dir.path().join("vanishing-target");
        std::fs::write(
            &target,
            "#!/bin/sh\nprintf 'rs-l2tpd-adopt 1\\n'\nrm \"$0\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let held = std::fs::File::open("/dev/null").unwrap();
        let original = held.as_raw_fd();
        let socket = AdoptedSocket::new("t1", held.try_clone().unwrap().into());
        let flags = unsafe { libc::fcntl(original, libc::F_GETFD) };
        let error = exec(&target, &[], vec![socket], None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(held.metadata().is_ok());
        assert_eq!(unsafe { libc::fcntl(original, libc::F_GETFD) }, flags);
        assert!(!target.exists());
        let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), action.as_mut_ptr()) },
            0
        );
        assert_eq!(unsafe { action.assume_init() }.sa_sigaction, libc::SIG_IGN);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod signal_tests {
    use super::*;
    use nix::sys::signal::{SigSet, Signal};
    /// spec: P12 P26
    #[test]
    fn exec_mask_child() {
        let Some(stage) = std::env::var_os("PHASE5_EXEC_MASK") else {
            return;
        };
        let signals = [
            Signal::SIGHUP,
            Signal::SIGTERM,
            Signal::SIGINT,
            Signal::SIGUSR2,
        ];
        if stage == "exec" {
            let mut set = SigSet::empty();
            for signal in signals {
                set.add(signal);
            }
            set.thread_set_mask().unwrap();
            let error = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "restart::signal_tests::exec_mask_child",
                    "--nocapture",
                ])
                .env("PHASE5_EXEC_MASK", "check")
                .exec();
            panic!("{error}");
        }
        let mask = SigSet::thread_get_mask().unwrap();
        for signal in signals {
            assert!(mask.contains(signal), "{signal:?}");
        }
        assert!(!mask.contains(Signal::SIGUSR1));
        let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), action.as_mut_ptr()) },
            0
        );
        assert_eq!(unsafe { action.assume_init() }.sa_sigaction, libc::SIG_IGN);
    }
    /// spec: P12 P26
    #[test]
    fn exec_preserves_requests_and_rust_entry_ignores_sigpipe() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "restart::signal_tests::exec_mask_child",
                "--nocapture",
            ])
            .env("PHASE5_EXEC_MASK", "exec")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod completion_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    /// spec: P26, G12
    #[test]
    fn probe_drains_output_written_between_its_read_and_exit_check() {
        const CHILD: &str = "RS_L2TPD_PROBE_DRAIN_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = PathBuf::from(root);
            let held = std::fs::File::open("/dev/null").unwrap();
            #[cfg(coverage_nightly)]
            crate::syscall_fault::keep_profile_output();
            let next = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            assert!(next >= 0);
            assert_eq!(unsafe { libc::close(next) }, 0);
            std::fs::write(root.join("probe-fd"), next.to_string()).unwrap();
            crate::syscall_barrier::stop().unwrap();
            let result = probe(&root.join("probe"));
            if root.ends_with("compatible") {
                result.unwrap();
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "incompatible adoption protocol"
                );
            }
            assert!(held.metadata().is_ok());
            println!("PROBE_DRAIN_LIMIT_CHECKED=1");
            return;
        }
        let dir = crate::testdir::Dir::new();
        for (case, tail, expected_reads) in [
            ("compatible", "printf 's-l2tpd-adopt 1\\n'", 3),
            ("oversized", "printf '%064d' 0", 2),
        ] {
            let root = dir.path().join(case);
            std::fs::create_dir(&root).unwrap();
            let root = root.as_path();
            let script = format!(
                "#!/bin/sh\nprintf r\n: > '{}/ready'\nwhile [ ! -f '{}/go' ]; do :; done\n{tail}\n",
                root.display(),
                root.display()
            );
            std::fs::write(root.join("probe.body"), script).unwrap();
            // Bound the disposable writer even if its tracing parent fails.
            std::fs::write(
                root.join("probe"),
                "#!/bin/sh\nexec timeout 5 /bin/sh \"$0.body\"\n",
            )
            .unwrap();
            std::fs::set_permissions(root.join("probe"), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let mut reads = 0;
            let mut released = false;
            let output = crate::syscall_barrier::run(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "restart::completion_tests::probe_drains_output_written_between_its_read_and_exit_check", "--nocapture"])
                .env(CHILD, root),
            root,
            |_, number, arguments| {
                let deadline = Instant::now() + Duration::from_secs(5);
                if number == libc::SYS_read as u64
                    && arguments[0] as i32 == std::fs::read_to_string(root.join("probe-fd"))?.parse::<i32>().unwrap()
                {
                    reads += 1;
                    if reads == 1 {
                        while !root.join("ready").exists() {
                            assert!(Instant::now() < deadline);
                            std::thread::yield_now();
                        }
                    }
                }
                if number == libc::SYS_wait4 as u64 && reads == 1 && !released {
                    std::fs::write(root.join("go"), "")?;
                    let pid = arguments[0] as i32;
                    loop {
                        let status = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
                        if status.rsplit_once(") ").is_some_and(|(_, state)| state.starts_with('Z')) {
                            break;
                        }
                        assert!(Instant::now() < deadline, "probe did not exit after release");
                        std::thread::yield_now();
                    }
                    released = true;
                }
                Ok(())
            },
        ).unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(
                released && reads == expected_reads,
                "release={released} reads={reads}"
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("PROBE_DRAIN_LIMIT_CHECKED=1")
            );
        }
    }
    /// spec: P26
    #[test]
    fn malformed_entry_child() {
        let Some(case) = std::env::var_os("PHASE6_ENTRY_CASE") else {
            return;
        };
        let (state, diagnostic) = match case.to_str().unwrap() {
            "missing" => (None, "missing re-exec PID-file state"),
            "encoding" => (
                Some(OsString::from_vec(vec![0xff])),
                "invalid re-exec state encoding",
            ),
            "version" => (Some("2:none".into()), "invalid re-exec PID-file state"),
            "four-fields-version" => (
                Some("2:1:2:2f706964".into()),
                "invalid re-exec PID-file state",
            ),
            "wrong-pid" | "missing-pid" | "missing-fds" => (
                Some("1:none".into()),
                "invalid re-exec descriptor announcement",
            ),
            "fields" => (Some("1:1:2".into()), "invalid re-exec PID-file state"),
            "odd-hex" => (Some("1:1:2:2f0".into()), "invalid re-exec pathname"),
            "bad-hex" => (Some("1:1:2:zz".into()), "invalid re-exec pathname"),
            "relative" => (Some("1:1:2:706964".into()), "invalid re-exec PID path"),
            "nul" => (Some("1:1:2:2f00".into()), "invalid re-exec PID path"),
            "device" => (Some("1:bad:2:2f706964".into()), "invalid re-exec inode"),
            "inode" => (Some("1:1:bad:2f706964".into()), "invalid re-exec inode"),
            "announcement" => (
                Some("1:none".into()),
                "invalid re-exec descriptor announcement",
            ),
            _ => panic!("unknown entry case"),
        };
        // This dedicated child runs only this test; no other code accesses its environment.
        unsafe {
            std::env::set_var("RS_L2TPD_REEXEC", format!("1:{}", std::process::id()));
            std::env::set_var("LISTEN_PID", std::process::id().to_string());
            std::env::set_var(
                "LISTEN_FDS",
                if case == "announcement" { "bad" } else { "0" },
            );
            if case == "wrong-pid" {
                std::env::set_var("LISTEN_PID", "0");
            }
            if case == "missing-pid" {
                std::env::remove_var("LISTEN_PID");
            }
            if case == "missing-fds" {
                std::env::remove_var("LISTEN_FDS");
            }
            std::env::remove_var("RS_L2TPD_PIDFILE");
            if let Some(state) = state {
                std::env::set_var("RS_L2TPD_PIDFILE", state);
            }
        }
        assert_eq!(entry().err().unwrap().to_string(), diagnostic);
        assert!(std::env::var_os("RS_L2TPD_REEXEC").is_none());
        assert!(std::env::var_os("RS_L2TPD_PIDFILE").is_none());
    }
    /// spec: P26
    #[test]
    fn malformed_entry_state_is_consumed_and_refused() {
        for case in [
            "missing",
            "encoding",
            "version",
            "four-fields-version",
            "wrong-pid",
            "missing-pid",
            "missing-fds",
            "fields",
            "odd-hex",
            "bad-hex",
            "relative",
            "nul",
            "device",
            "inode",
            "announcement",
        ] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "restart::completion_tests::malformed_entry_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("PHASE6_ENTRY_CASE", case)
                .output()
                .unwrap();
            assert!(output.status.success(), "{case}: {output:?}");
        }
    }
    /// spec: P27
    #[test]
    fn restart_file_checks_precede_any_signal() {
        let dir = crate::testdir::Dir::new();
        let path = dir.path().join("pid");
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let contents = format!("{}\n", child.id());
        for text in [
            contents.trim_end().to_owned(),
            "\n".into(),
            format!("+{}", contents),
            "0\n".into(),
            "1\n".into(),
            "1\n2\n".into(),
            "9".repeat(33),
        ] {
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(signal(&path).is_err());
            assert!(child.try_wait().unwrap().is_none());
        }
        std::fs::write(&path, &contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(signal(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        std::fs::hard_link(&path, &link).unwrap();
        assert!(signal(&path).is_err());
        std::fs::remove_file(&link).unwrap();
        symlink(&path, &link).unwrap();
        assert!(signal(&link).is_err());
        assert!(signal(dir.path()).is_err());
        let fifo = dir.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(signal(&fifo).is_err());
        assert!(child.try_wait().unwrap().is_none());
        signal(&path).unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGUSR2));
    }
    /// spec: P23 P26
    #[test]
    fn absolute_executable_does_not_need_a_working_directory() {
        assert_eq!(
            executable_at(
                std::ffi::OsStr::new("/absolute/daemon"),
                Err(io::Error::other("deleted cwd"))
            )
            .unwrap(),
            Path::new("/absolute/daemon")
        );
        assert!(
            executable_at(
                std::ffi::OsStr::new("./daemon"),
                Err(io::Error::other("deleted cwd"))
            )
            .is_err()
        );
    }
    /// spec: P26
    #[test]
    fn pid_inspection_error_child() {
        let Some(case) = std::env::var_os("COMPLETION_PID_ENTRY") else {
            return;
        };
        crate::logger::init(true);
        let dir = crate::testdir::Dir::new();
        let keep = dir.path().join("file");
        std::fs::write(&keep, "keep").unwrap();
        let metadata = std::fs::metadata(&keep).unwrap();
        let mut pid = PidFile {
            path: keep.clone(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
        match case.to_str().unwrap() {
            "inspect" => pid.path = keep.join("pid"),
            "device" => pid.dev ^= 1,
            "inode" => pid.ino ^= 1,
            "symlink" | "directory" => {
                pid.path = if case == "symlink" {
                    let alias = dir.path().join("alias");
                    symlink(&keep, &alias).unwrap();
                    alias
                } else {
                    dir.path().to_owned()
                };
                let metadata = std::fs::symlink_metadata(&pid.path).unwrap();
                pid.dev = metadata.dev();
                pid.ino = metadata.ino();
            }
            _ => panic!("unknown PID fixture"),
        }
        unsafe {
            std::env::set_var("RS_L2TPD_REEXEC", format!("1:{}", std::process::id()));
            std::env::set_var("RS_L2TPD_PIDFILE", state(Some(&pid)));
            std::env::set_var("LISTEN_PID", std::process::id().to_string());
            std::env::set_var("LISTEN_FDS", "0");
        }
        let result = entry().unwrap();
        assert!(result.reexec && result.pid.is_none());
        assert_eq!(std::fs::read_to_string(keep).unwrap(), "keep");
        assert!(std::fs::symlink_metadata(&pid.path).is_ok() || case == "inspect");
    }
    /// spec: P11, P26
    #[test]
    fn pid_metadata_mismatches_and_inspection_errors_discard_only_removal_authority() {
        for case in ["inspect", "device", "inode", "symlink", "directory"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "restart::completion_tests::pid_inspection_error_child",
                ])
                .env("COMPLETION_PID_ENTRY", case)
                .output()
                .unwrap();
            assert!(output.status.success(), "{case}: {output:?}");
        }
    }

    /// spec: P23 P26
    #[test]
    fn executable_search_child() {
        let Some(root) = std::env::var_os("PHASE6_EXECUTABLE_SEARCH") else {
            return;
        };
        let root = PathBuf::from(root);
        assert_eq!(
            executable_at(std::ffi::OsStr::new("daemon"), Ok(root.clone())).unwrap(),
            root.join("good/daemon")
        );
        assert_eq!(
            executable_at(std::ffi::OsStr::new("./relative/daemon"), Ok(root.clone())).unwrap(),
            root.join("./relative/daemon")
        );
        let error = executable_at(std::ffi::OsStr::new("missing"), Ok(root)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(error.to_string(), "cannot resolve executable path");
    }

    /// spec: P23 P26
    #[test]
    fn executable_search_skips_missing_directories_and_nonexecutable_files() {
        let dir = crate::testdir::Dir::new();
        for part in ["directory/daemon", "nonexec", "good"] {
            std::fs::create_dir_all(dir.path().join(part)).unwrap();
        }
        for (part, mode) in [("nonexec", 0o600), ("good", 0o700)] {
            let path = dir.path().join(part).join("daemon");
            std::fs::write(&path, "fixture").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "restart::completion_tests::executable_search_child",
            ])
            .env("PATH", "missing:directory:nonexec:good")
            .env("PHASE6_EXECUTABLE_SEARCH", dir.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    /// spec: P26
    #[test]
    fn adoption_probes_bound_output_and_time_before_any_exec() {
        if std::env::var_os("PHASE6_ISOLATED_PROBES").is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "restart::completion_tests::adoption_probes_bound_output_and_time_before_any_exec", "--nocapture", "--test-threads=1"])
                .env("PHASE6_ISOLATED_PROBES", "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            return;
        }
        // Other tests' forks must never inherit these scripts' writable descriptors.
        let dir = crate::testdir::Dir::new();
        for (name, script, error) in [
            ("compatible", "printf 'rs-l2tpd-adopt 1\\n'", None),
            (
                "failed",
                "printf 'rs-l2tpd-adopt 1\\n'; exit 1",
                Some(io::ErrorKind::Other),
            ),
            (
                "oversized",
                "printf '%064d' 0; exec /bin/sleep 30",
                Some(io::ErrorKind::Other),
            ),
            (
                "silent",
                "exec /bin/sleep 30",
                Some(io::ErrorKind::TimedOut),
            ),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let started = Instant::now();
            match error {
                None => probe(&path).unwrap(),
                Some(expected) => assert_eq!(probe(&path).unwrap_err().kind(), expected),
            }
            assert!(started.elapsed() < Duration::from_secs(10));
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod pid_growth_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    /// spec: P27, G1
    #[test]
    fn a_pid_file_growing_after_metadata_is_refused_before_signalling() {
        const CHILD: &str = "PHASE6_RESTART_PID_GROWTH";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = PathBuf::from(root);
            let mut target = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            let pid = target.id().to_string();
            std::fs::write(root.join("grown"), format!("{pid:0>32}\n")).unwrap();
            #[cfg(coverage_nightly)]
            crate::syscall_fault::keep_profile_output();
            crate::syscall_barrier::stop().unwrap();
            let result = signal(&root.join("pid"));
            let _ = target.kill();
            let status = target.wait().unwrap();
            assert_eq!(result.unwrap_err().to_string(), "invalid PID file");
            assert_eq!(status.signal(), Some(libc::SIGKILL));
            println!("PID_GROWTH_REFUSAL_CHECKED=1");
            return;
        }
        let dir = crate::testdir::Dir::new();
        let path = dir.path().join("pid");
        std::fs::write(&path, "2\n").unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let mut grew = false;
        let output = crate::syscall_barrier::run(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "restart::pid_growth_tests::a_pid_file_growing_after_metadata_is_refused_before_signalling", "--nocapture"])
                .env(CHILD, dir.path()),
            dir.path(),
            |tid, number, arguments| {
                if !grew && number == libc::SYS_read as u64
                    && std::fs::read_link(format!("/proc/{tid}/fd/{}", arguments[0])).ok().as_ref() == Some(&path)
                {
                    std::fs::write(&path, std::fs::read(dir.path().join("grown"))?)?;
                    grew = true;
                }
                Ok(())
            },
        ).unwrap();
        assert!(grew && output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("PID_GROWTH_REFUSAL_CHECKED=1"));
    }
}

fn exec_panicked(_: Box<dyn std::any::Any + Send>) -> io::Error {
    io::Error::other("exec thread panicked")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod panic_tests {
    /// spec: P26, O1, G1
    #[test]
    fn an_exec_worker_panic_becomes_an_error_and_releases_its_payload() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        let (mut reader, writer) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let payload = std::thread::spawn(move || std::panic::panic_any(writer))
            .join()
            .unwrap_err();
        let error = super::exec_panicked(payload);
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(error.raw_os_error(), None);
        assert_eq!(error.to_string(), "exec thread panicked");
        let mut byte = [0];
        assert_eq!(reader.read(&mut byte).unwrap(), 0);
    }
}
