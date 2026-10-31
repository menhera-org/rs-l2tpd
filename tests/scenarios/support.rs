use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

pub const BINARY: &str = env!("CARGO_BIN_EXE_rs-l2tpd");

pub fn checked(mut command: Command) -> String {
    let output = command.output().unwrap();
    assert!(output.status.success(), "{command:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

pub fn deny_socket_option(path: &std::path::Path, level: i32, option: i32) {
    let architecture = match std::env::consts::ARCH {
        "x86_64" => 0xc000003e,
        "aarch64" => 0xc00000b7,
        other => panic!("unsupported seccomp fixture ABI: {other}"),
    };
    // Linux seccomp_data: arch at 4, syscall at 0, setsockopt arguments at 16.
    let filter: [(u16, u8, u8, u32); 11] = [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, architecture),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
        (0x15, 0, 5, nix::libc::SYS_setsockopt as u32),
        (0x20, 0, 0, 24),
        (0x15, 0, 3, level as u32),
        (0x20, 0, 0, 32),
        (0x15, 0, 1, option as u32),
        (0x06, 0, 0, 0x00050000 | nix::libc::EPERM as u32),
        (0x06, 0, 0, 0x7fff0000),
    ];
    let bytes: Vec<u8> = filter
        .into_iter()
        .flat_map(|(code, jt, jf, value)| {
            let [a, b] = code.to_ne_bytes();
            let [c, d, e, f] = value.to_ne_bytes();
            [a, b, jt, jf, c, d, e, f]
        })
        .collect();
    fs::write(path, bytes).unwrap();
}

pub fn wait(label: &str, predicate: impl FnMut() -> bool) {
    wait_with_timeout(label, Duration::from_secs(10), predicate);
}
pub fn wait_with_timeout(label: &str, timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !predicate() {
        assert!(Instant::now() < deadline, "timeout: {label}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub struct Pair {
    pub dir: PathBuf,
    pub names: [String; 2],
}
impl Pair {
    pub fn new() -> Self {
        // Each fixture gets a mount/network namespace as well as unique names;
        // nothing created by a test is visible on the host.
        assert_eq!(
            std::env::var("RS_L2TPD_SCENARIO_CONTAINER").as_deref(),
            Ok("1"),
            "run through tests/docker/run.sh"
        );
        let mut bytes = [0; 4];
        getrandom::fill(&mut bytes).unwrap();
        let id = u32::from_ne_bytes(bytes);
        let fixture = Self {
            dir: std::env::temp_dir().join(format!("rs-l2tpd-scenario-{id:x}")),
            names: [format!("l2tp-{id:x}-a"), format!("l2tp-{id:x}-b")],
        };
        fs::create_dir(&fixture.dir).unwrap();
        for name in &fixture.names {
            let mut cmd = Command::new("ip");
            cmd.args(["netns", "add", name]);
            checked(cmd);
        }
        fixture.make_underlay();
        fixture
    }
    pub fn make_underlay(&self) {
        self.ip(
            0,
            &[
                "link", "add", "underlay", "type", "veth", "peer", "name", "other",
            ],
        );
        self.ip(0, &["link", "set", "other", "netns", &self.names[1]]);
        self.ip(1, &["link", "set", "other", "name", "underlay"]);
        for side in 0..2 {
            if std::path::Path::new("/proc/sys/net/ipv6").exists() {
                self.ip(side, &["link", "set", "underlay", "addrgenmode", "none"]);
            }
        }
    }
    pub fn command(&self, side: usize, program: &str, args: &[&str]) -> Command {
        let mut command = Command::new("nsenter");
        command
            .arg(format!("--net=/run/netns/{}", self.names[side]))
            .arg(program)
            .args(args);
        command
    }
    pub fn output(&self, side: usize, program: &str, args: &[&str]) -> Output {
        self.command(side, program, args).output().unwrap()
    }
    pub fn ip(&self, side: usize, args: &[&str]) -> String {
        checked(self.command(side, "ip", args))
    }
    pub fn underlay(&self, ipv4: bool, ipv6: bool) {
        for side in 0..2 {
            self.ip(side, &["link", "set", "underlay", "up"]);
            if ipv4 {
                self.ip(
                    side,
                    &[
                        "addr",
                        "add",
                        &format!("192.0.2.{}/24", side + 1),
                        "dev",
                        "underlay",
                    ],
                );
            }
            if ipv6 {
                self.ip(
                    side,
                    &[
                        "-6",
                        "addr",
                        "add",
                        &format!("2001:db8:1::{}/64", side + 1),
                        "dev",
                        "underlay",
                        "nodad",
                    ],
                );
            }
        }
    }
    pub fn index(&self, side: usize, name: &str) -> u32 {
        self.ip(side, &["-o", "link", "show", name])
            .split(':')
            .next()
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }
    pub fn tunable(&self, side: usize, value: &str) {
        checked(self.command(
            side,
            "sh",
            &[
                "-ec",
                &format!("echo {value} > /proc/sys/net/ipv6/bindv6only"),
            ],
        ));
    }
    pub fn only_v6_default(&self, side: usize) -> String {
        checked(self.command(side, "cat", &["/proc/sys/net/ipv6/bindv6only"]))
            .trim()
            .to_owned()
    }
    pub fn ipv6_tunnels(&self, side: usize, count: usize) {
        let tunnels = self.ip(side, &["l2tp", "show", "tunnel"]);
        eprintln!("side {side}: {tunnels}");
        let endpoints: Vec<_> = tunnels
            .lines()
            .filter_map(|line| line.trim().strip_prefix("From "))
            .collect();
        assert_eq!(endpoints.len(), count);
        for line in endpoints {
            let (source, peer) = line.split_once(" to ").unwrap();
            assert!(
                source.contains(':') && peer.contains(':'),
                "not AF_INET6: {line}"
            );
        }
    }
    pub fn inner6(&self, device: &str, subnet: usize) {
        for side in 0..2 {
            if std::path::Path::new("/proc/sys/net/ipv6").exists() {
                self.ip(side, &["link", "set", device, "addrgenmode", "none"]);
            }
            self.ip(side, &["link", "set", device, "up"]);
            self.ip(
                side,
                &[
                    "-6",
                    "addr",
                    "add",
                    &format!("2001:db8:18:{subnet}::{}/64", side + 1),
                    "dev",
                    device,
                    "nodad",
                ],
            );
        }
    }
    pub fn frames6(&self, subnet: usize) {
        for side in 0..2 {
            let peer = format!("2001:db8:18:{subnet}::{}", 2 - side);
            wait(&format!("IPv6 frames from side {side}"), || {
                self.output(side, "ping", &["-6", "-c", "1", "-W", "1", &peer])
                    .status
                    .success()
            });
        }
    }
    pub fn inner(&self, device: &str, subnet: usize) {
        for side in 0..2 {
            if std::path::Path::new("/proc/sys/net/ipv6").exists() {
                self.ip(side, &["link", "set", device, "addrgenmode", "none"]);
            }
            self.ip(side, &["link", "set", device, "up"]);
            self.ip(
                side,
                &[
                    "addr",
                    "add",
                    &format!("198.18.{subnet}.{}/24", side + 1),
                    "dev",
                    device,
                ],
            );
        }
    }
    pub fn frames(&self, subnet: usize) {
        for side in 0..2 {
            let peer = format!("198.18.{subnet}.{}", 2 - side);
            wait(&format!("frames from side {side}"), || {
                self.output(side, "ping", &["-c", "1", "-W", "1", &peer])
                    .status
                    .success()
            });
        }
    }
    pub fn drops(&self, side: usize, device: &str) -> u64 {
        let text = self.ip(side, &["-s", "link", "show", "dev", device]);
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            if line.trim_start().starts_with("TX:") {
                return lines
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(3)
                    .unwrap()
                    .parse()
                    .unwrap();
            }
        }
        panic!("no TX counters: {text}");
    }
    pub fn start(&self, side: usize, text: &str) -> Daemon {
        self.start_with(side, text, &[])
    }
    pub fn start_with(&self, side: usize, text: &str, prefix: &[&str]) -> Daemon {
        let path = self.dir.join(format!("{side}.toml"));
        fs::write(&path, text).unwrap();
        let mut command = if let Some((program, args)) = prefix.split_first() {
            let mut command = self.command(side, program, args);
            command.arg(BINARY);
            command
        } else {
            self.command(side, BINARY, &[])
        };
        command
            .arg("--foreground")
            .arg("--config")
            .arg(&path)
            .arg("--config-dir")
            .arg(self.dir.join("absent"))
            .env_remove("NOTIFY_SOCKET")
            .env_remove("LISTEN_FDS")
            .env_remove("LISTEN_PID")
            .env_remove("LISTEN_FDNAMES")
            .env_remove("FDSTORE")
            .env_remove("RS_L2TPD_REEXEC")
            .env_remove("RS_L2TPD_PIDFILE");
        Daemon::spawn(command)
    }
    pub fn absent(&self, side: usize) {
        wait("all tunnels and sessions removed", || {
            self.ip(side, &["l2tp", "show", "tunnel"]).trim().is_empty()
                && self
                    .ip(side, &["l2tp", "show", "session"])
                    .trim()
                    .is_empty()
        });
    }
}
impl Drop for Pair {
    fn drop(&mut self) {
        if std::thread::panicking() {
            for side in 0..2 {
                for args in [
                    vec!["-s", "link", "show"],
                    vec!["l2tp", "show", "tunnel"],
                    vec!["l2tp", "show", "session"],
                    vec!["neigh", "show"],
                    vec!["addr", "show"],
                    vec!["-6", "route", "show", "table", "all"],
                ] {
                    eprintln!(
                        "side {side}: {args:?}\n{:?}",
                        self.command(side, "ip", &args).output()
                    );
                }
            }
        }
        for name in &self.names {
            let _ = Command::new("ip").args(["netns", "del", name]).output();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

pub struct Daemon {
    child: Child,
    events: mpsc::Receiver<(Instant, String)>,
    lines: Arc<Mutex<Vec<String>>>,
}
impl Daemon {
    pub fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, events) = mpsc::channel();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let captured = lines.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let line = line.unwrap();
                let at = Instant::now();
                eprintln!("daemon: {line}");
                captured.lock().unwrap().push(line.clone());
                let _ = tx.send((at, line));
            }
        });
        Self {
            child,
            events,
            lines,
        }
    }
    pub fn event(&self, text: &str) -> Instant {
        self.event_with_timeout(text, Duration::from_secs(10))
    }
    pub fn event_with_timeout(&self, text: &str, timeout: Duration) -> Instant {
        let deadline = Instant::now() + timeout;
        loop {
            let (at, line) = self
                .events
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|error| panic!("waiting for {text}: {error}"));
            if line.contains(text) {
                return at;
            }
        }
    }
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn count(&self, text: &str) -> usize {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.contains(text))
            .count()
    }
    pub fn reload(&self) {
        self.reload_with_timeout(Duration::from_secs(10));
    }
    pub fn reload_with_timeout(&self, timeout: Duration) {
        kill(Pid::from_raw(self.child.id() as i32), Signal::SIGHUP).unwrap();
        self.event_with_timeout("reload complete", timeout);
    }
    pub fn assert_unready_for(&mut self, duration: Duration) {
        let deadline = Instant::now() + duration;
        assert_eq!(self.count("ready pid="), 0);
        while Instant::now() < deadline {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "exited before readiness"
            );
            match self.events.recv_timeout(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(100)),
            ) {
                Ok((_, line)) => assert!(!line.contains("ready pid="), "false readiness: {line}"),
                Err(mpsc::RecvTimeoutError::Timeout) => (),
                Err(error) => panic!("daemon log closed before readiness: {error}"),
            }
        }
    }
    pub fn wait_exit(&mut self, code: i32) {
        wait("process exit", || self.child.try_wait().unwrap().is_some());
        assert_eq!(self.child.wait().unwrap().code(), Some(code));
        loop {
            match self.events.recv_timeout(Duration::from_secs(5)) {
                Ok(_) => (),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(error) => panic!("daemon log did not close: {error}"),
            }
        }
    }
    pub fn stop(&mut self) {
        self.stop_with_timeout(Duration::from_secs(10));
    }
    pub fn stop_with_timeout(&mut self, timeout: Duration) {
        kill(Pid::from_raw(self.child.id() as i32), Signal::SIGTERM).unwrap();
        self.event_with_timeout("shutdown complete", timeout);
        self.wait_exit(0);
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn config(side: usize, peers: &[&str]) -> String {
    let mut text = "[host]\nfix_bindv6only=false\n".to_owned();
    for (n, peer) in peers.iter().enumerate() {
        let id = 10 * n + side + 1;
        let other = 10 * n + 2 - side;
        text.push_str(&format!(
            "[tunnels.t{n}]\ntunnel_id={id}\npeer_tunnel_id={other}\nremote_addr='{peer}'\n\
             [sessions.s{n}]\ntunnel_name='t{n}'\nsession_id={}\npeer_session_id={}\ninterface_name='l2tp{n}'\n",
             100+id, 100+other));
    }
    text
}

pub struct Detached {
    namespace: String,
    side: usize,
    launcher: Child,
    pid_file: PathBuf,
    log: PathBuf,
}
impl Detached {
    pub fn spawn(
        pair: &Pair,
        side: usize,
        mut command: Command,
        pid_file: PathBuf,
        log: PathBuf,
    ) -> Self {
        for key in [
            "NOTIFY_SOCKET",
            "LISTEN_FDS",
            "LISTEN_PID",
            "LISTEN_FDNAMES",
            "FDSTORE",
            "RS_L2TPD_REEXEC",
            "RS_L2TPD_PIDFILE",
        ] {
            command.env_remove(key);
        }
        let mut process = Self {
            namespace: pair.names[side].clone(),
            side,
            launcher: command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(fs::File::create(&log).unwrap())
                .spawn()
                .unwrap(),
            pid_file,
            log,
        };
        wait("daemonizing parent readiness exit", || {
            process.launcher.try_wait().unwrap().is_some()
        });
        assert!(
            process.launcher.wait().unwrap().success(),
            "{}",
            fs::read_to_string(&process.log).unwrap()
        );
        assert!(process.pid_file.exists());
        process
    }
    pub fn pid(&self) -> i32 {
        let pid = fs::read_to_string(&self.pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(pid > 1);
        pid
    }
    pub fn signal(&self, signal: Signal) {
        kill(Pid::from_raw(self.pid()), signal).unwrap();
    }
    pub fn event(&self, text: &str) {
        wait(text, || {
            fs::read_to_string(&self.log).unwrap().contains(text)
        });
    }
    pub fn stop(&self, pair: &Pair) {
        self.signal(Signal::SIGTERM);
        wait("daemonized PID file removed", || !self.pid_file.exists());
        pair.absent(self.side);
    }
}
impl Drop for Detached {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("daemonized log: {:?}", fs::read_to_string(&self.log));
        }
        // Covers double-fork startup failure before the PID file is published.
        if let Ok(output) = Command::new("ip")
            .args(["netns", "pids", &self.namespace])
            .output()
        {
            for pid in String::from_utf8_lossy(&output.stdout).split_whitespace() {
                if let Ok(pid) = pid.parse::<i32>()
                    && pid > 1
                {
                    let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
                }
            }
        }
        let _ = self.launcher.kill();
        let _ = self.launcher.wait();
    }
}
