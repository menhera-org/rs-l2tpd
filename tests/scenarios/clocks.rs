//! H16 runs only in the isolated QEMU clock profile.
#[allow(dead_code)]
#[path = "../support/discovery.rs"]
mod discovery;
use super::support::{Pair, checked, config, wait};
use discovery::Dns;
use std::io::Write;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn set_wall(seconds: u64) {
    let mut command = std::process::Command::new("date");
    command.args(["-u", "-s", &format!("@{seconds}")]);
    checked(command);
    let actual = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        actual.abs_diff(seconds) <= 1,
        "wall clock did not step: {actual} vs {seconds}"
    );
    println!("H16_WALL_SET={seconds}");
}
fn retry(daemon: &super::support::Daemon, previous: Instant) -> Instant {
    let next = daemon.event_with_timeout(
        "tunnel t1 (tunnel_id=11): disconnected, peer 203.0.113.2 pending",
        Duration::from_secs(2),
    );
    let interval = next.saturating_duration_since(previous);
    assert!(
        (Duration::from_millis(750)..=Duration::from_millis(1500)).contains(&interval),
        "retry interval: {interval:?}"
    );
    println!("H16_RETRY_NS={}", interval.as_nanos());
    next
}
fn query_times(dns: &Dns) -> Vec<Instant> {
    dns.requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(family, _)| *family == 1)
        .map(|(_, at)| *at)
        .collect()
}

/// spec: H16, R8, V4, E13
#[test]
#[ignore = "QEMU clock profile only; changes guest wall clock and requests a monitored VM pause"]
fn clock_steps_and_vm_pause_preserve_retries_refreshes_and_network_events() {
    assert_eq!(std::env::var("RS_L2TPD_CLOCK_GUEST").as_deref(), Ok("1"));
    assert!(
        std::fs::read_to_string("/proc/cmdline")
            .unwrap()
            .split_whitespace()
            .any(|p| p == "rs_l2tpd_clock_guest=1"),
        "never step the clock of a container or the host"
    );
    let original_wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let original_mono = Instant::now();
    let pair = Pair::new();
    pair.underlay(true, true);
    pair.ip(1, &["addr", "add", "192.0.2.9/24", "dev", "underlay"]);
    pair.ip(1, &["addr", "add", "203.0.113.2/24", "dev", "underlay"]);
    let original = std::fs::File::open("/proc/self/ns/net").unwrap();
    let target = std::fs::File::open(format!("/run/netns/{}", pair.names[1])).unwrap();
    nix::sched::setns(target, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    let dns = Dns::new("2001:db8:1::2", "underlay");
    nix::sched::setns(original, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    let text=config(0,&["controlled.example","203.0.113.2"]).replace("remote_addr='controlled.example'","remote_addr='controlled.example'\nip_version='V4'\nresolver_name='clock-dns'\nbind_interface='underlay'")
        + "\n[resolvers.clock-dns]\naddresses=['[2001:db8:1::2]:53']\nbind_interface='underlay'\n";
    let mut peer = pair.start(1, &config(1, &["192.0.2.1", "192.0.2.1"]));
    let mut daemon = pair.start_with(0, &text, &["sh", "-ec", "exec \"$0\" --verbose \"$@\""]);
    daemon.event("ready");
    peer.event("ready");
    daemon.event("tunnel t0 (tunnel_id=1): connected to 192.0.2.9");
    pair.inner("l2tp0", 0);
    pair.frames(0);
    let indices = [pair.index(0, "l2tp0"), pair.index(0, "l2tp1")];
    assert_eq!(daemon.count("): connected to"), 1);
    let mut previous =
        daemon.event("tunnel t1 (tunnel_id=11): disconnected, peer 203.0.113.2 pending");
    set_wall(original_wall + 365 * 24 * 3600);
    previous = retry(&daemon, previous);
    set_wall(original_wall - 365 * 24 * 3600);
    previous = retry(&daemon, previous);
    while query_times(&dns).len() < 2 {
        previous = retry(&daemon, previous);
    }
    let queries = query_times(&dns);
    let refresh = queries[1].duration_since(queries[0]);
    assert!(
        (Duration::from_millis(29900)..=Duration::from_secs(32)).contains(&refresh),
        "clock-step DNS refresh: {refresh:?}"
    );
    println!("H16_REFRESH_BEFORE_PAUSE_NS={}", refresh.as_nanos());
    assert_eq!(
        daemon.count("): connected to"),
        1,
        "clock jumps or an unchanged DNS answer reconnected a working tunnel"
    );
    pair.frames(0);
    set_wall(original_wall + original_mono.elapsed().as_secs());
    previous = retry(&daemon, previous);
    let before_pause = Instant::now();
    println!("H16_PAUSE_READY");
    std::io::stdout().flush().unwrap();
    let mut reply = String::new();
    std::io::stdin().read_line(&mut reply).unwrap();
    assert_eq!(reply.trim(), "H16_RESUMED");
    let pause_elapsed = before_pause.elapsed();
    assert!(
        pause_elapsed < Duration::from_secs(2),
        "guest monotonic clock advanced through the three-second VM pause: {pause_elapsed:?}"
    );
    println!("H16_GUEST_PAUSE_NS={}", pause_elapsed.as_nanos());
    previous = retry(&daemon, previous);
    while query_times(&dns).len() < 3 {
        previous = retry(&daemon, previous);
    }
    let queries = query_times(&dns);
    assert_eq!(queries.len(), 3, "unexpected extra DNS refresh");
    let refresh = queries[2].duration_since(queries[1]);
    assert!(
        (Duration::from_millis(29900)..=Duration::from_secs(32)).contains(&refresh),
        "post-resume DNS refresh: {refresh:?}"
    );
    println!("H16_REFRESH_AFTER_PAUSE_NS={}", refresh.as_nanos());
    assert_eq!(daemon.count("): connected to"), 1);
    pair.frames(0);
    // A route-only change emits no subscribed link/address notification:
    // only a real retry can establish this previously unreachable tunnel.
    pair.ip(0, &["route", "add", "203.0.113.0/24", "dev", "underlay"]);
    let route = Instant::now();
    let connected = daemon.event("tunnel t1 (tunnel_id=11): connected to 203.0.113.2");
    assert!(connected.saturating_duration_since(route) <= Duration::from_secs(1));
    pair.inner("l2tp1", 1);
    pair.frames(1);
    let connects = daemon.count("tunnel t0 (tunnel_id=1): connected to");
    pair.ip(0, &["addr", "add", "192.0.2.3/24", "dev", "underlay"]);
    wait("address event after resume", || {
        daemon.count("tunnel t0 (tunnel_id=1): connected to") > connects
    });
    pair.frames(0);
    pair.ip(0, &["link", "set", "underlay", "name", "clock-old"]);
    daemon.event("its bind device is absent");
    let drops = pair.drops(0, "l2tp0");
    assert!(
        !pair
            .output(0, "ping", &["-c", "1", "-W", "1", "198.18.0.2"])
            .status
            .success()
    );
    assert!(pair.drops(0, "l2tp0") > drops);
    let connects = daemon.count("tunnel t0 (tunnel_id=1): connected to");
    pair.ip(0, &["link", "set", "clock-old", "name", "underlay"]);
    wait("link event after resume", || {
        daemon.count("tunnel t0 (tunnel_id=1): connected to") > connects
    });
    pair.frames(0);
    assert_eq!([pair.index(0, "l2tp0"), pair.index(0, "l2tp1")], indices);
    daemon.stop();
    peer.stop();
    pair.absent(0);
    pair.absent(1);
}
