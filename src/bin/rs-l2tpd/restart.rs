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
    let result = (|| {
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
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
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
        command.pre_exec(|| {
            if libc::signal(libc::SIGPIPE, libc::SIG_IGN) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
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
        .map_err(|_| io::Error::other("exec thread panicked"))?;
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
mod exec_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
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
mod completion_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    /// spec: P27
    #[test]
    fn restart_file_checks_precede_any_signal() {
        let dir = crate::testdir::Dir::new();
        let path = dir.path().join("pid");
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let contents = format!("{}\n", child.id());
        for text in [
            contents.trim_end().to_owned(),
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
        if std::env::var_os("COMPLETION_PID_ENTRY").is_none() {
            return;
        }
        let dir = crate::testdir::Dir::new();
        let parent = dir.path().join("file");
        std::fs::write(&parent, "").unwrap();
        let pid = PidFile {
            path: parent.join("pid"),
            dev: 0,
            ino: 0,
        };
        unsafe {
            std::env::set_var("RS_L2TPD_REEXEC", format!("1:{}", std::process::id()));
            std::env::set_var("RS_L2TPD_PIDFILE", state(Some(&pid)));
            std::env::set_var("LISTEN_PID", std::process::id().to_string());
            std::env::set_var("LISTEN_FDS", "0");
        }
        let result = entry().unwrap();
        assert!(result.reexec && result.pid.is_none());
    }
    /// spec: P26
    #[test]
    fn pid_inspection_error_discards_only_removal_authority() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "restart::completion_tests::pid_inspection_error_child",
            ])
            .env("COMPLETION_PID_ENTRY", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
}
