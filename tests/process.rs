//! Actual binary process cases. Live cases run in an isolated container.
use nix::sys::signal::{Signal, kill};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
use nix::unistd::Pid;
use rs_l2tpd::kernel::{Kernel, L2tpIfName, linux::LinuxKernel};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_rs-l2tpd");
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes).unwrap();
        let path = std::env::temp_dir().join(format!(
            "rs-l2tpd-process-{:016x}",
            u64::from_ne_bytes(bytes)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn command() -> Command {
    let mut command = Command::new(BINARY);
    for key in [
        "LISTEN_PID",
        "LISTEN_FDS",
        "LISTEN_FDNAMES",
        "NOTIFY_SOCKET",
        "FDSTORE",
        "RS_L2TPD_REEXEC",
        "RS_L2TPD_PIDFILE",
    ] {
        command.env_remove(key);
    }
    command
}
fn config(dir: &Dir) -> PathBuf {
    let path = dir.path().join("main.toml");
    fs::write(&path, "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.1'\n[sessions.a]\ntunnel_name='a'\nsession_id=100\ninterface_name='testl2tp'").unwrap();
    path
}
fn namespace() {
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
}
struct Process {
    child: Child,
    pid: i32,
    logs: mpsc::Receiver<String>,
    done: bool,
}
impl Process {
    fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, logs) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else {
                    break;
                };
                eprintln!("daemon: {line}");
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            pid: child.id() as i32,
            child,
            logs,
            done: false,
        }
    }
    fn event(&self, text: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let line = self
                .logs
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|e| panic!("waiting for {text:?}: {e}"));
            if line.contains(text) {
                return line;
            }
        }
    }
    fn signal(&self, signal: Signal) {
        kill(Pid::from_raw(self.pid), signal).unwrap();
    }
    fn stop(&mut self) {
        self.signal(Signal::SIGTERM);
        self.event("shutdown complete");
        assert!(self.child.wait().unwrap().success());
        self.done = true;
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if !self.done {
            let _ = kill(Pid::from_raw(self.pid), Signal::SIGKILL);
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn start(config: &Path, foreground: bool, pid: &Path) -> Command {
    let mut command = command();
    command
        .arg("--config")
        .arg(config)
        .arg("--config-dir")
        .arg(config.with_extension("dropins"))
        .arg("--pid-file")
        .arg(pid);
    if foreground {
        command.arg("--foreground");
    }
    command
}
fn index(kernel: &mut LinuxKernel) -> u32 {
    kernel
        .link_by_name(&L2tpIfName::try_from("testl2tp").unwrap())
        .unwrap()
        .unwrap()
        .index()
}

/// spec: P3 P19 P24 P27 O1 O5 O7 O8 C1 C3 C4
#[test]
fn check_cli_and_no_process_side_effects() {
    let dir = Dir::new();
    let main = config(&dir);
    let pid = dir.path().join("pid");
    fs::write(&pid, "sentinel").unwrap();
    let output = start(&main, false, &pid)
        .arg("--check")
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let rendered = String::from_utf8(output.stdout).unwrap();
    assert!(rendered.contains("tunnel_id = 10"));
    assert_eq!(fs::read_to_string(&pid).unwrap(), "sentinel");
    fs::write(&main, "[sessions.a]\ncookie='secret-cookie'\nunknown=true").unwrap();
    let output = start(&main, false, &pid).arg("--check").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let errors = String::from_utf8(output.stderr).unwrap();
    assert!(!errors.contains("secret-cookie"));
    assert!(
        errors
            .lines()
            .all(|line| line.starts_with("WARN ") || line.starts_with("ERROR "))
    );
    fs::write(&main, "cookie = secret-cookie").unwrap();
    let output = start(&main, false, &pid).arg("--check").output().unwrap();
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("secret-cookie")
    );
    let unusual = dir.path().join("line\nbreak.toml");
    fs::write(&unusual, "invalid document").unwrap();
    let output = start(&unusual, false, &pid)
        .arg("--check")
        .output()
        .unwrap();
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert_eq!(diagnostic.lines().count(), 1);
    assert!(diagnostic.contains("line\\nbreak.toml"));
    for option in ["--unknown", "--config", "--check --foreground"] {
        let output = command().args(option.split_whitespace()).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8(output.stderr).unwrap().contains("usage:"));
    }
    assert_eq!(
        command().arg("--adopt-version").output().unwrap().stdout,
        b"rs-l2tpd-adopt 1\n"
    );
    assert!(
        command()
            .arg("--version")
            .output()
            .unwrap()
            .status
            .success()
    );
}

/// spec: P1 P4 P6 P7 P9 P12 P13 P16 P17 P20 P22 P23 O7
#[test]
#[ignore = "isolated privileged container"]
fn foreground_reload_and_clean_shutdown_without_network() {
    namespace();
    let dir = Dir::new();
    let main = config(&dir);
    let pid = dir.path().join("pid");
    let mut process = Process::spawn(start(&main, true, &pid));
    process.event("ready");
    assert!(!pid.exists());
    let mut kernel = LinuxKernel::new().unwrap();
    let original = index(&mut kernel);
    let changed = fs::read_to_string(&main)
        .unwrap()
        .replace("192.0.2.1", "192.0.2.2");
    fs::write(&main, changed).unwrap();
    process.signal(Signal::SIGHUP);
    process.event("reload completed");
    assert_eq!(index(&mut kernel), original);
    fs::write(&main, "invalid document").unwrap();
    process.signal(Signal::SIGHUP);
    process.event("reload refused");
    assert_eq!(index(&mut kernel), original);
    process.stop();
    assert!(kernel.tunnel(10).unwrap().is_none());
}

/// spec: P4 P6 P10 P11 P12 P15 P22 P26 O7
#[test]
#[ignore = "isolated privileged container"]
fn daemon_readiness_pid_inode_and_reexec() {
    namespace();
    let dir = Dir::new();
    let main = config(&dir);
    let pid = dir.path().join("pid");
    let executable = dir.path().join("daemon");
    fs::copy(BINARY, &executable).unwrap();
    let mut command = start(&main, false, &pid);
    let arguments: Vec<_> = command.get_args().map(|a| a.to_owned()).collect();
    command = Command::new(&executable);
    command.args(arguments);
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
            Ok(())
        });
    }
    let mut process = Process::spawn(command);
    process.event("ready");
    assert!(process.child.wait().unwrap().success());
    process.pid = fs::read_to_string(&pid).unwrap().trim().parse().unwrap();
    use std::os::unix::fs::MetadataExt;
    let before = fs::metadata(&pid).unwrap();
    let mut kernel = LinuxKernel::new().unwrap();
    let original = index(&mut kernel);
    let replacement = dir.path().join("new-daemon");
    fs::copy(BINARY, &replacement).unwrap();
    fs::rename(replacement, &executable).unwrap();
    process.signal(Signal::SIGUSR2);
    process.event("adopted");
    assert_eq!(index(&mut kernel), original);
    assert_eq!(fs::metadata(&pid).unwrap().ino(), before.ino());
    assert_eq!(
        fs::read_to_string(&pid).unwrap().trim(),
        process.pid.to_string()
    );
    process.signal(Signal::SIGTERM);
    process.event("shutdown complete");
    assert!(!pid.exists());
    assert!(kernel.tunnel(10).unwrap().is_none());
    process.done = true;
}

/// spec: P4 P26
#[test]
#[ignore = "isolated privileged container"]
fn zero_tunnel_reexec_stays_foreground_and_preserves_pid() {
    namespace();
    let dir = Dir::new();
    let main = dir.path().join("main");
    fs::write(&main, "[host]\nfix_bindv6only=false").unwrap();
    let pid = dir.path().join("pid");
    let mut process = Process::spawn(start(&main, true, &pid));
    process.event("ready");
    process.signal(Signal::SIGUSR2);
    // Reload completion in the new image proves that re-exec installed handlers.
    // The restart callback logs before exec; the next image logs its startup.
    process.event("re-exec");
    process.signal(Signal::SIGHUP);
    process.event("reload completed");
    assert!(!pid.exists());
    process.stop();
}

/// spec: P26
#[test]
fn invalid_reexec_state_fails_without_forking() {
    if std::env::var_os("PHASE5_INVALID_REEXEC_CHILD").is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "invalid_reexec_state_fails_without_forking",
                "--nocapture",
            ])
            .env("PHASE5_INVALID_REEXEC_CHILD", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let dir = Dir::new();
    let main = config(&dir);
    let pid = dir.path().join("pid");
    for state in [false, true] {
        let mut command = start(&main, false, &pid);
        if state {
            command.env("RS_L2TPD_PIDFILE", "1:none");
        } else {
            command.env("RS_L2TPD_REEXEC", "1:0");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("invalid re-exec")
        );
        assert!(!pid.exists());
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}

type Stored = Arc<Mutex<HashMap<String, Vec<OwnedFd>>>>;
struct Manager {
    path: PathBuf,
    stored: Stored,
    events: mpsc::Receiver<String>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Manager {
    fn new(dir: &Dir) -> Self {
        Self::with_removal(dir, true)
    }
    fn with_removal(dir: &Dir, remove: bool) -> Self {
        let path = dir.path().join("notify");
        let listener = UnixDatagram::bind(&path).unwrap();
        let stored: Stored = Arc::new(Mutex::new(HashMap::new()));
        let state = stored.clone();
        let (tx, events) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            loop {
                let mut bytes = [0; 512];
                let mut iov = [IoSliceMut::new(&mut bytes)];
                let mut cmsg = nix::cmsg_space!([i32; 8]);
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
                let text = String::from_utf8(bytes[..count].to_vec()).unwrap();
                if text == "STOP" {
                    break;
                }
                let name = text
                    .lines()
                    .find_map(|s| s.strip_prefix("FDNAME="))
                    .unwrap_or("")
                    .to_owned();
                if text.starts_with("FDSTORE=1\n") {
                    assert_eq!(rights.len(), 1);
                    state
                        .lock()
                        .unwrap()
                        .entry(name.clone())
                        .or_default()
                        .append(&mut rights);
                } else if text.starts_with("FDSTOREREMOVE=1\n") {
                    if remove {
                        state.lock().unwrap().remove(&name);
                    }
                } else {
                    assert_eq!(text, "BARRIER=1");
                    assert_eq!(rights.len(), 1);
                }
                drop(rights);
                let _ = tx.send(text);
            }
        });
        Self {
            path,
            stored,
            events,
            thread: Some(thread),
        }
    }
    fn event(&self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let event = self
                .events
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap();
            if event.contains(text) {
                break;
            }
        }
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        let _ = UnixDatagram::unbound()
            .unwrap()
            .send_to(b"STOP", &self.path);
        let _ = self.thread.take().unwrap().join();
    }
}

/// spec: P14 P18 P26
#[test]
#[ignore = "isolated privileged container"]
fn crash_store_adoption_and_ordered_withdrawal() {
    store_adoption(false, false);
}

/// spec: P4 P14 P18
#[test]
#[ignore = "isolated privileged container"]
fn stored_descriptors_survive_double_fork() {
    store_adoption(true, false);
}

/// spec: P14
#[test]
#[ignore = "isolated privileged container"]
fn rejected_store_name_is_withdrawn_before_replacement() {
    store_adoption(false, true);
}

fn store_adoption(daemon: bool, reject_name: bool) {
    namespace();
    let dir = Dir::new();
    let main = config(&dir);
    let pid = dir.path().join("pid");
    let manager = Manager::new(&dir);
    let mut first = start(&main, true, &pid);
    first
        .env("NOTIFY_SOCKET", &manager.path)
        .env("FDSTORE", "16");
    let mut process = Process::spawn(first);
    process.event("ready");
    manager.event("FDSTORE=1");
    let mut kernel = LinuxKernel::new().unwrap();
    let original = index(&mut kernel);
    process.signal(Signal::SIGKILL);
    assert!(!process.child.wait().unwrap().success());
    process.done = true;
    assert!(kernel.tunnel(10).unwrap().is_some());
    let fd = manager.stored.lock().unwrap()["t10"][0]
        .try_clone()
        .unwrap();
    if reject_name {
        let mut stored = manager.stored.lock().unwrap();
        let fds = stored.remove("t10").unwrap();
        stored.insert("unexpected".into(), fds);
    }
    let mut launcher = Command::new(std::env::current_exe().unwrap());
    launcher
        .arg("--exact")
        .arg("handover_launcher")
        .arg("--nocapture")
        .env("PROCESS_LAUNCH_BINARY", BINARY)
        .env("PROCESS_LAUNCH_CONFIG", &main)
        .env("PROCESS_LAUNCH_NOTIFY", &manager.path)
        .env("PROCESS_LAUNCH_PIDFILE", &pid);
    if daemon {
        launcher.env("PROCESS_LAUNCH_DAEMON", "1");
    }
    if reject_name {
        launcher.env("PROCESS_LAUNCH_NAMES", "unexpected");
    }
    let raw = fd.as_raw_fd();
    unsafe {
        launcher.pre_exec(move || {
            if libc::dup2(raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut adopted = Process::spawn(launcher);
    drop(fd);
    adopted.event("ready");
    if daemon {
        assert!(adopted.child.wait().unwrap().success());
        adopted.pid = fs::read_to_string(&pid).unwrap().trim().parse().unwrap();
    }
    if reject_name {
        manager.event("FDSTOREREMOVE=1\nFDNAME=unexpected");
        manager.event("BARRIER=1");
        manager.event("FDSTORE=1\nFDNAME=t10");
        assert_ne!(index(&mut kernel), original);
    } else {
        assert_eq!(index(&mut kernel), original);
    }
    adopted.stop();
    assert!(manager.stored.lock().unwrap().is_empty());
    assert!(kernel.tunnel(10).unwrap().is_none());
}

/// spec: P14
#[test]
fn handover_launcher() {
    let Some(binary) = std::env::var_os("PROCESS_LAUNCH_BINARY") else {
        return;
    };
    let mut command = Command::new(binary);
    if std::env::var_os("PROCESS_LAUNCH_DAEMON").is_none() {
        command.arg("--foreground");
    }
    if let Some(pid) = std::env::var_os("PROCESS_LAUNCH_PIDFILE") {
        command.arg("--pid-file").arg(pid);
    }
    let error = command
        .arg("--config")
        .arg(std::env::var_os("PROCESS_LAUNCH_CONFIG").unwrap())
        .arg("--config-dir")
        .arg("/absent")
        .env(
            "NOTIFY_SOCKET",
            std::env::var_os("PROCESS_LAUNCH_NOTIFY").unwrap(),
        )
        .env("FDSTORE", "16")
        .env("LISTEN_PID", std::process::id().to_string())
        .env("LISTEN_FDS", "1")
        .env(
            "LISTEN_FDNAMES",
            std::env::var("PROCESS_LAUNCH_NAMES").unwrap_or_else(|_| "t10".into()),
        )
        .exec();
    panic!("launch failed: {error}");
}

/// spec: P18 P17
#[test]
#[ignore = "isolated privileged container"]
fn crash_without_store_closes_tunnel() {
    namespace();
    let dir = Dir::new();
    let main = config(&dir);
    let mut process = Process::spawn(start(&main, true, &dir.path().join("pid")));
    process.event("ready");
    let mut kernel = LinuxKernel::new().unwrap();
    assert!(kernel.tunnel(10).unwrap().is_some());
    process.signal(Signal::SIGKILL);
    process.child.wait().unwrap();
    process.done = true;
    let deadline = Instant::now() + Duration::from_secs(2);
    while kernel.tunnel(10).unwrap().is_some() {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
}

/// spec: P27
#[test]
#[cfg(feature = "setup-systemd")]
fn setup_prefix_preserves_configuration() {
    let dir = Dir::new();
    assert!(
        command()
            .arg("--setup-systemd")
            .arg("--prefix")
            .arg(dir.path())
            .status()
            .unwrap()
            .success()
    );
    let installed = dir.path().join("usr/local/sbin/rs-l2tpd");
    assert_eq!(fs::read(&installed).unwrap(), fs::read(BINARY).unwrap());
    let main = dir.path().join("etc/rs-l2tpd.toml");
    fs::write(&main, "# mine").unwrap();
    let unit = dir
        .path()
        .join("usr/local/lib/systemd/system/rs-l2tpd.service");
    fs::write(&unit, "# mine").unwrap();
    assert!(
        command()
            .arg("--setup-systemd")
            .arg("--prefix")
            .arg(dir.path())
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fs::read_to_string(main).unwrap(), "# mine");
    assert_eq!(fs::read_to_string(unit).unwrap(), "# mine");
}

fn deny_netlink() -> std::io::Result<()> {
    deny_socket_family(libc::AF_NETLINK)
}

fn deny_socket_family(family: i32) -> std::io::Result<()> {
    let mut filter = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 3,
            k: libc::SYS_socket as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 16,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: family as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0
        || unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// spec: P4 P5 P9 P12 O7
#[test]
#[ignore = "isolated privileged container"]
fn failed_kernel_open_withholds_readiness_and_parent_shutdown_returns_one() {
    namespace();
    let dir = Dir::new();
    let main = config(&dir);
    let pid = dir.path().join("pid");
    for foreground in [true, false] {
        let mut command = start(&main, foreground, &pid);
        unsafe {
            command.pre_exec(deny_netlink);
        }
        let mut process = Process::spawn(command);
        process.event("opening kernel interfaces");
        for _ in 0..10 {
            assert!(
                process.child.try_wait().unwrap().is_none(),
                "process exited while readiness was withheld"
            );
            assert!(!pid.exists());
            std::thread::sleep(Duration::from_millis(10));
        }
        process.signal(Signal::SIGTERM);
        assert_eq!(process.child.wait().unwrap().code(), Some(1));
        process.done = true;
        loop {
            match process.logs.recv_timeout(Duration::from_secs(5)) {
                Ok(line) => assert!(!line.contains(": ready")),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(error) => panic!("daemon failed to exit: {error}"),
            }
        }
    }
}

/// spec: R49 P23
#[test]
#[ignore = "isolated privileged container, drops child uid"]
fn missing_capabilities_are_reported_once_and_empty_configuration_runs() {
    namespace();
    let dir = Dir::new();
    let main = dir.path().join("empty");
    fs::write(&main, "[host]\nfix_bindv6only=false").unwrap();
    let mut command = start(&main, true, &dir.path().join("pid"));
    command.uid(65534).gid(65534);
    let mut process = Process::spawn(command);
    for name in ["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE"] {
        process.event(&format!("missing {name}"));
    }
    process.event("ready");
    process.stop();
}

fn launcher(main: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "handover_launcher", "--nocapture"])
        .env("PROCESS_LAUNCH_BINARY", BINARY)
        .env("PROCESS_LAUNCH_CONFIG", main)
        .env("PROCESS_LAUNCH_NOTIFY", "/absent");
    command
}
/// spec: P14 P19
#[test]
fn malformed_and_closed_announcements_are_errors_without_panics() {
    let dir = Dir::new();
    let main = config(&dir);
    let file = fs::File::open("/dev/null").unwrap();
    let raw = file.as_raw_fd();
    for closed in [false, true] {
        let mut command = launcher(&main);
        if !closed {
            command.env("PROCESS_LAUNCH_NAMES", "");
        }
        unsafe {
            command.pre_exec(move || {
                if closed {
                    libc::close(3);
                } else {
                    if libc::dup2(raw, 3) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    libc::fcntl(3, libc::F_SETFD, 0);
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("cleanup cannot be confirmed"), "{error}");
        assert!(!error.contains("panicked"));
    }
}

/// spec: P4 P14
#[test]
#[ignore = "isolated privileged container"]
fn unannounced_descriptors_close_before_service_start() {
    namespace();
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    let dir = Dir::new();
    let main = dir.path().join("empty");
    fs::write(&main, "[host]\nfix_bindv6only=false").unwrap();
    let (mut observer, extra) = UnixStream::pair().unwrap();
    observer
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let raw = extra.as_raw_fd();
    let mut command = start(&main, true, &dir.path().join("pid"));
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(raw, 201) < 0 || libc::fcntl(201, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut process = Process::spawn(command);
    drop(extra);
    process.event("ready");
    assert_eq!(observer.read(&mut [0]).unwrap(), 0);
    process.stop();
}

/// spec: P10 P11 O7
#[test]
#[ignore = "isolated privileged container"]
fn pid_publication_failure_does_not_revoke_kernel_readiness() {
    namespace();
    let dir = Dir::new();
    let main = config(&dir);
    let victim = dir.path().join("victim");
    let pid = dir.path().join("pid");
    fs::write(&victim, "keep").unwrap();
    std::os::unix::fs::symlink(&victim, &pid).unwrap();
    let mut process = Process::spawn(start(&main, false, &pid));
    let line = process.event("ready pid=");
    process.pid = line.rsplit_once("pid=").unwrap().1.parse().unwrap();
    assert!(process.child.wait().unwrap().success());
    let mut kernel = LinuxKernel::new().unwrap();
    assert!(kernel.tunnel(10).unwrap().is_some());
    process.stop();
    assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
}

/// spec: P5 P25
#[test]
#[ignore = "isolated privileged container with namespace-local writable network sysctls"]
fn binary_tunable_handshake_and_opt_out() {
    namespace();
    let dir = Dir::new();
    let path = config(&dir);
    let original = fs::read_to_string(&path).unwrap();
    let sysctl = Path::new("/proc/sys/net/ipv6/bindv6only");
    for fix in [false, true] {
        fs::write(sysctl, "1\n").unwrap();
        fs::write(
            &path,
            original.replace("fix_bindv6only=false", &format!("fix_bindv6only={fix}")),
        )
        .unwrap();
        let mut process = Process::spawn(start(&path, true, &dir.path().join("pid")));
        if fix {
            process.event("previous value 1");
        }
        process.event("ready");
        assert_eq!(
            fs::read_to_string(sysctl).unwrap().trim(),
            if fix { "0" } else { "1" }
        );
        process.stop();
    }
}

/// spec: P26
#[test]
#[ignore = "isolated privileged container"]
fn incompatible_replacement_keeps_running_interfaces() {
    namespace();
    let dir = Dir::new();
    let main = config(&dir);
    let executable = dir.path().join("daemon");
    fs::copy(BINARY, &executable).unwrap();
    let template = start(&main, true, &dir.path().join("pid"));
    let mut command = Command::new(&executable);
    command.args(template.get_args());
    let mut process = Process::spawn(command);
    process.event("ready");
    let mut kernel = LinuxKernel::new().unwrap();
    let original = index(&mut kernel);
    let replacement = dir.path().join("new");
    fs::copy("/bin/false", &replacement).unwrap();
    fs::rename(replacement, &executable).unwrap();
    process.signal(Signal::SIGUSR2);
    process.event("incompatible adoption protocol");
    assert_eq!(index(&mut kernel), original);
    process.signal(Signal::SIGHUP);
    process.event("reload completed");
    process.stop();
}

/// spec: P2 O1
#[test]
fn startup_changes_directory_before_loading_and_logs_problems() {
    let dir = Dir::new();
    let main = config(&dir);
    use std::io::Write;
    writeln!(
        fs::OpenOptions::new().append(true).open(&main).unwrap(),
        "\nunknown=true"
    )
    .unwrap();
    let output = command()
        .current_dir(dir.path())
        .arg("--check")
        .arg("--config")
        .arg(main.strip_prefix("/").unwrap())
        .arg("--config-dir")
        .arg("/absent")
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("tunnel_id = 10")
    );
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("WARN ")
    );
}

/// spec: P14 P16 P17 O7
#[test]
#[ignore = "isolated privileged container"]
fn failed_store_cleanup_is_reported_and_shutdown_is_bounded() {
    namespace();
    let dir = Dir::new();
    let main = config(&dir);
    let manager = Manager::with_removal(&dir, false);
    let mut command = start(&main, true, &dir.path().join("pid"));
    command
        .env("NOTIFY_SOCKET", &manager.path)
        .env("FDSTORE", "16");
    let mut process = Process::spawn(command);
    process.event("ready");
    manager.event("FDSTORE=1");
    process.signal(Signal::SIGTERM);
    process.event("shutdown complete");
    assert_eq!(process.child.wait().unwrap().code(), Some(1));
    process.done = true;
    let mut kernel = LinuxKernel::new().unwrap();
    assert!(
        kernel.tunnel(10).unwrap().is_some(),
        "manager deliberately retained its reference"
    );
    drop(manager);
    let deadline = Instant::now() + Duration::from_secs(2);
    while kernel.tunnel(10).unwrap().is_some() {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
}

/// spec: P7 P8 P20
#[test]
#[ignore = "isolated privileged container; exercises the ten-second conflict budget"]
fn overlapping_instance_becomes_ready_without_deleting_foreign_objects() {
    namespace();
    let dir = Dir::new();
    let main = config(&dir);
    let mut first = Process::spawn(start(&main, true, &dir.path().join("first.pid")));
    first.event("ready");
    let mut kernel = LinuxKernel::new().unwrap();
    let original = index(&mut kernel);
    let second_pid = dir.path().join("second.pid");
    let mut second = Process::spawn(start(&main, false, &second_pid));
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        assert!(
            second.child.try_wait().unwrap().is_none(),
            "parent exited before readiness"
        );
        assert!(!second_pid.exists());
        std::thread::sleep(Duration::from_millis(10));
    }
    second.event("ready");
    assert!(second.child.wait().unwrap().success());
    second.pid = fs::read_to_string(&second_pid)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(index(&mut kernel), original);
    second.stop();
    assert_eq!(index(&mut kernel), original);
    first.stop();
}

/// spec: P27
#[test]
#[cfg(feature = "setup-systemd")]
#[ignore = "root in disposable container, records systemctl without contacting a manager"]
fn installer_enables_once_and_never_restarts() {
    let dir = Dir::new();
    let script = dir.path().join("systemctl");
    fs::write(&script, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SETUP_CALLS\"\ncase \"$*\" in\n '--no-pager --quiet is-enabled rs-l2tpd.service') test -e \"$SETUP_ENABLED\" ;;\n '--no-pager daemon-reload') exit 0 ;;\n '--no-pager --now enable rs-l2tpd.service') : > \"$SETUP_ENABLED\" ;;\n *) exit 2 ;;\nesac\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let calls = dir.path().join("calls");
    let enabled = dir.path().join("enabled");
    for _ in 0..2 {
        assert!(
            command()
                .arg("--setup-systemd")
                .env("PATH", dir.path())
                .env("SETUP_CALLS", &calls)
                .env("SETUP_ENABLED", &enabled)
                .status()
                .unwrap()
                .success()
        );
    }
    assert_eq!(
        fs::read_to_string(calls)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        [
            "--no-pager --quiet is-enabled rs-l2tpd.service",
            "--no-pager daemon-reload",
            "--no-pager --now enable rs-l2tpd.service",
            "--no-pager --quiet is-enabled rs-l2tpd.service",
            "--no-pager daemon-reload",
        ]
    );
}

/// spec: O8 C3
#[test]
fn check_and_startup_report_file_errors_in_the_same_words() {
    let dir = Dir::new();
    let main = dir.path().join("bad.toml");
    fs::write(&main, "invalid document").unwrap();
    let pid = dir.path().join("pid");
    let output = start(&main, false, &pid).arg("--check").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let check = String::from_utf8(output.stderr).unwrap();
    assert!(check.contains("; file left out"));
    let mut command = start(&main, true, &pid);
    unsafe {
        command.pre_exec(deny_netlink);
    }
    let mut process = Process::spawn(command);
    assert_eq!(process.event("file left out"), check.trim_end());
    // File reporting precedes signal installation; wait for the startup retry loop.
    process.event("opening kernel interfaces");
    process.signal(Signal::SIGTERM);
    assert_eq!(process.child.wait().unwrap().code(), Some(1));
    process.done = true;
}

/// spec: P12 P22
#[test]
#[ignore = "isolated privileged container"]
fn sigusr1_retains_its_default_action() {
    namespace();
    let dir = Dir::new();
    let main = dir.path().join("main");
    fs::write(&main, "[host]\nfix_bindv6only=false").unwrap();
    let mut process = Process::spawn(start(&main, true, &dir.path().join("pid")));
    process.event("ready");
    process.signal(Signal::SIGUSR1);
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(process.child.wait().unwrap().signal(), Some(libc::SIGUSR1));
    process.done = true;
}

/// spec: P14 P5
#[test]
#[ignore = "isolated privileged container"]
fn an_unusable_notify_store_does_not_abort_startup() {
    namespace();
    let dir = Dir::new();
    let main = dir.path().join("main");
    fs::write(&main, "[host]\nfix_bindv6only=false").unwrap();
    for (address, filter) in [
        ("/".to_owned() + &"x".repeat(200), false),
        (
            dir.path().join("absent").to_string_lossy().into_owned(),
            false,
        ),
        (
            dir.path().join("filtered").to_string_lossy().into_owned(),
            true,
        ),
    ] {
        let mut command = start(&main, true, &dir.path().join("pid"));
        command.env("NOTIFY_SOCKET", address).env("FDSTORE", "8");
        if filter {
            unsafe {
                command.pre_exec(|| deny_socket_family(libc::AF_UNIX));
            }
        }
        let mut process = Process::spawn(command);
        process.event("descriptor store unavailable");
        process.event("ready");
        process.stop();
    }
}

/// spec: P26 P2
#[test]
fn an_absolute_executable_starts_from_a_deleted_working_directory() {
    let dir = Dir::new();
    let main = config(&dir);
    let cwd = dir.path().join("gone");
    fs::create_dir(&cwd).unwrap();
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let removed = CString::new(cwd.as_os_str().as_bytes()).unwrap();
    let mut command = start(&main, true, &dir.path().join("pid"));
    command.current_dir(cwd);
    unsafe {
        command.pre_exec(move || {
            if libc::rmdir(removed.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            deny_netlink()
        });
    }
    let mut process = Process::spawn(command);
    process.event("opening kernel interfaces");
    process.signal(Signal::SIGTERM);
    assert_eq!(process.child.wait().unwrap().code(), Some(1));
    process.done = true;
}
