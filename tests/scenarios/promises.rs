use super::support::{Detached, Pair, config};
use std::fs;
use std::time::{Duration, Instant};

/// spec: G15, G16, G17, G18, G19, G20
#[test]
#[ignore = "disposable privileged container"]
fn readiness_existence_fidelity_stability_and_ordered_shutdown() {
    let pair = Pair::new();
    let configured = config(0, &["192.0.2.2", "pending.invalid", "2001:db8:1::2"]).replace(
        "[sessions.s1]",
        "ip_version='V4'\nbind_interface='absent'\nresolver_name='r'\n[sessions.s1]",
    ) + "\n[resolvers.r]\naddresses=['192.0.2.53']\n";
    let mut a = pair.start(0, &configured);
    let last_created = a.event("session s2 (tunnel_id=21, session_id=121): created");
    let ready = a.event("ready");
    println!(
        "G15_READY_AFTER_LAST_CREATE elapsed_ns={}",
        ready.duration_since(last_created).as_nanos()
    );
    assert!(ready.duration_since(last_created) <= Duration::from_secs(1));
    assert_eq!(a.count("connected to"), 0);
    let mut b = pair.start(1, &config(1, &["192.0.2.1", "192.0.2.1", "2001:db8:1::1"]));
    b.event("ready");
    let indices: Vec<_> = (0..3).map(|n| pair.index(0, &format!("l2tp{n}"))).collect();
    let verify = |first: &str| {
        for (n, index) in indices.iter().enumerate() {
            let name = if n == 0 {
                first.to_string()
            } else {
                format!("l2tp{n}")
            };
            assert_eq!(pair.index(0, &name), *index);
        }
        for (kind, prefix) in [("tunnel", "Tunnel "), ("session", "Session ")] {
            assert_eq!(
                pair.ip(0, &["l2tp", "show", kind])
                    .lines()
                    .filter(|line| line.starts_with(prefix))
                    .count(),
                3
            );
        }
        assert_eq!(a.count("created as"), 3);
        assert_eq!(a.count(": removed"), 0);
    };
    verify("l2tp0");
    assert!(
        pair.ip(0, &["route", "show", "table", "all"])
            .trim()
            .is_empty()
    );
    assert!(
        pair.ip(0, &["-6", "route", "show", "table", "all"])
            .trim()
            .is_empty()
    );
    pair.underlay(true, true);
    let reachable = Instant::now();
    for _ in 0..2 {
        let connected = a.event(": connected to");
        println!(
            "G17_REACHABLE elapsed_ns={}",
            connected.saturating_duration_since(reachable).as_nanos()
        );
        assert!(connected.saturating_duration_since(reachable) <= Duration::from_secs(1));
    }
    for _ in 0..3 {
        b.event(": connected to");
    }
    pair.inner("l2tp0", 0);
    pair.frames(0);
    verify("l2tp0");
    let connected = a.count("connected to");
    assert_eq!(
        connected, 2,
        "the absent binding/DNS entry must stay disconnected"
    );
    a.reload();
    b.reload();
    assert_eq!(
        a.count("connected to"),
        connected,
        "identical reload must not reconnect"
    );
    verify("l2tp0");

    let renamed = configured.replace("interface_name='l2tp0'", "interface_name='renamed'");
    fs::write(pair.dir.join("0.toml"), &renamed).unwrap();
    a.reload();
    verify("renamed");
    pair.frames(0);
    assert_eq!(a.count("connected to"), connected);
    pair.ip(1, &["addr", "add", "192.0.2.3/24", "dev", "underlay"]);
    fs::write(
        pair.dir.join("0.toml"),
        renamed.replace("192.0.2.2", "192.0.2.3"),
    )
    .unwrap();
    a.reload();
    verify("renamed");
    assert_eq!(a.count("connected to"), connected + 1);
    let tunnel = pair.ip(0, &["l2tp", "show", "tunnel"]).to_ascii_lowercase();
    assert!(
        tunnel.contains("from ::ffff:192.0.2.1 to ::ffff:192.0.2.3"),
        "{tunnel}"
    );
    pair.frames(0);

    let stopping = Instant::now();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(a.pid() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    // Consuming events in order fails if a tunnel is removed before its sessions.
    for n in 0..3 {
        let id = 10 * n + 1;
        a.event(&format!(
            "session s{n} (tunnel_id={id}, session_id={}): removed",
            100 + id
        ));
    }
    for n in 0..3 {
        a.event(&format!("tunnel t{n} (tunnel_id={}): removed", 10 * n + 1));
    }
    a.event("shutdown complete");
    a.wait_exit(0);
    let cleanup = stopping.elapsed();
    println!("G20_SHUTDOWN tunnels=3 elapsed_ns={}", cleanup.as_nanos());
    assert!(cleanup <= Duration::from_secs(6));
    pair.absent(0);
    b.stop();
    pair.absent(1);
}

fn legacy_config(side: usize) -> String {
    let peers = if side == 0 {
        ["192.0.2.2", "2001:db8:1::2"]
    } else {
        ["192.0.2.1", "2001:db8:1::1"]
    };
    config(side, &peers)
        .replace("[host]\nfix_bindv6only=false\n", "")
        .replace("[sessions.s0]", "ip_version='V4'\n[sessions.s0]")
        .replace("[sessions.s1]", "ip_version='V6'\n[sessions.s1]")
}
fn baseline(pair: &Pair) -> Detached {
    let binary = std::env::var("RS_L2TPD_BASELINE").expect("the scenario runner builds v0.1.5");
    fs::create_dir_all("/etc/rs-l2tpd.toml.d").unwrap();
    fs::write("/etc/rs-l2tpd.toml", legacy_config(1)).unwrap();
    let pid_file = pair.dir.join("baseline.pid");
    let mut command = pair.command(1, &binary, &["--verbose", "--pidfile"]);
    command.arg(&pid_file);
    Detached::spawn(pair, 1, command, pid_file, pair.dir.join("baseline.log"))
}

/// spec: G11, G22
#[test]
#[ignore = "disposable privileged container; runner supplies the archived v0.1.5 binary"]
fn version_015_configuration_and_peer_exchange_frames() {
    let pair = Pair::new();
    pair.underlay(true, true);
    let mut current = pair.start(0, &legacy_config(0));
    current.event("ready");
    let baseline = baseline(&pair);
    for n in 0..2 {
        pair.inner(&format!("l2tp{n}"), n);
        pair.frames(n);
    }
    current.reload();
    for n in 0..2 {
        pair.frames(n);
    }
    baseline.stop(&pair);
    current.stop();
    pair.absent(0);
}
