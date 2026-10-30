use super::support::{Pair, config};
use std::time::{Duration, Instant};

/// spec: H6, G8, G21, P1
#[test]
#[ignore = "disposable privileged container"]
fn readiness_without_routes_then_frames_after_the_first_route() {
    let pair = Pair::new();
    for side in 0..2 {
        assert!(
            pair.ip(side, &["route", "show", "table", "all"])
                .trim()
                .is_empty()
        );
        assert!(
            pair.ip(side, &["-6", "route", "show", "table", "all"])
                .trim()
                .is_empty()
        );
    }
    let mut a = pair.start(0, &config(0, &["192.0.2.2"]));
    let mut b = pair.start(1, &config(1, &["192.0.2.1"]));
    a.event("ready");
    b.event("ready");
    for side in 0..2 {
        assert!(
            pair.ip(side, &["l2tp", "show", "tunnel"])
                .contains(&format!("Tunnel {}", side + 1))
        );
        assert!(pair.ip(side, &["link", "show", "l2tp0"]).contains("l2tp0"));
    }
    pair.inner("l2tp0", 0);
    let before = pair.drops(0, "l2tp0");
    assert!(
        !pair
            .output(0, "ping", &["-c", "1", "-W", "1", "198.18.0.2"])
            .status
            .success()
    );
    assert!(
        pair.drops(0, "l2tp0") > before,
        "a disconnected tunnel must actually drop transmitted frames"
    );
    // Configure B first so its route exists before A's connect is measured.
    pair.ip(1, &["link", "set", "underlay", "up"]);
    pair.ip(1, &["addr", "add", "192.0.2.2/24", "dev", "underlay"]);
    b.event("connected to");
    pair.ip(0, &["link", "set", "underlay", "up"]);
    pair.ip(0, &["addr", "add", "192.0.2.1/24", "dev", "underlay"]);
    let route = Instant::now();
    let connected = a.event("connected to");
    assert!(
        connected.saturating_duration_since(route) <= Duration::from_secs(1),
        "route-to-connect delay: {:?}",
        connected.saturating_duration_since(route)
    );
    pair.frames(0);
    a.stop();
    b.stop();
    pair.absent(0);
    pair.absent(1);
}

/// spec: H1
#[test]
#[ignore = "disposable privileged container"]
fn dual_stack_peers_exchange_frames_on_ipv6_tunnels() {
    let pair = Pair::new();
    pair.underlay(true, true);
    let mut a = pair.start(0, &config(0, &["192.0.2.2", "2001:db8:1::2"]));
    let mut b = pair.start(1, &config(1, &["192.0.2.1", "2001:db8:1::1"]));
    a.event("ready");
    b.event("ready");
    for side in 0..2 {
        pair.ipv6_tunnels(side, 2);
    }
    for n in 0..2 {
        pair.inner(&format!("l2tp{n}"), n);
        pair.frames(n);
    }
    a.stop();
    b.stop();
    pair.absent(0);
    pair.absent(1);
}

fn v4_only(disabled: bool) {
    let pair = Pair::new();
    if disabled {
        for side in 0..2 {
            super::support::checked(pair.command(side, "sh", &["-ec",
                "echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6; echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6"]));
        }
    }
    pair.underlay(true, false);
    let mut a = pair.start(0, &config(0, &["192.0.2.2", "2001:db8:1::2"]));
    let mut b = pair.start(1, &config(1, &["192.0.2.1", "2001:db8:1::1"]));
    a.event("ready");
    b.event("ready");
    for side in 0..2 {
        pair.ipv6_tunnels(side, 2);
        assert!(pair.ip(side, &["-6", "addr", "show"]).trim().is_empty());
        assert!(pair.ip(side, &["link", "show", "l2tp1"]).contains("l2tp1"));
    }
    pair.inner("l2tp0", 0);
    pair.frames(0);
    for daemon in [&a, &b] {
        for _ in 0..3 {
            daemon.reload();
        }
        assert_eq!(daemon.count("disconnected, peer 2001:db8:1::"), 1);
    }
    pair.inner("l2tp1", 1);
    let before = pair.drops(0, "l2tp1");
    assert!(
        !pair
            .output(0, "ping", &["-c", "1", "-W", "1", "198.18.1.2"])
            .status
            .success()
    );
    assert!(pair.drops(0, "l2tp1") > before);
    a.stop();
    b.stop();
    pair.absent(0);
    pair.absent(1);
}

/// spec: H2
#[test]
#[ignore = "disposable privileged container"]
fn ipv4_only_with_ipv6_stack_needs_no_ipv6_configuration() {
    v4_only(false);
}

/// spec: H3
#[test]
#[ignore = "disposable privileged container"]
fn sysctl_disabled_ipv6_still_carries_ipv4_on_ipv6_sockets() {
    v4_only(true);
}

/// spec: H5
#[test]
#[ignore = "disposable privileged container"]
fn ipv6_only_keeps_ipv4_disconnected_without_a_source() {
    let pair = Pair::new();
    pair.underlay(false, true);
    let mut a = pair.start(0, &config(0, &["192.0.2.2", "2001:db8:1::2"]));
    let mut b = pair.start(1, &config(1, &["192.0.2.1", "2001:db8:1::1"]));
    a.event("ready");
    b.event("ready");
    for side in 0..2 {
        pair.ipv6_tunnels(side, 2);
        assert!(pair.ip(side, &["-4", "addr", "show"]).trim().is_empty());
        assert!(pair.ip(side, &["link", "show", "l2tp0"]).contains("l2tp0"));
    }
    pair.inner6("l2tp1", 1);
    pair.frames6(1);
    for daemon in [&a, &b] {
        for _ in 0..3 {
            daemon.reload();
        }
        assert_eq!(daemon.count("disconnected, peer 192.0.2."), 1);
    }
    pair.inner6("l2tp0", 0);
    let before = pair.drops(0, "l2tp0");
    assert!(
        !pair
            .output(0, "ping", &["-6", "-c", "1", "-W", "1", "2001:db8:18:0::2"])
            .status
            .success()
    );
    assert!(pair.drops(0, "l2tp0") > before);
    a.stop();
    b.stop();
    pair.absent(0);
    pair.absent(1);
}

/// spec: H13
#[test]
#[ignore = "disposable privileged container"]
fn bind_devices_can_appear_lose_their_names_and_be_replaced() {
    let pair = Pair::new();
    pair.underlay(true, false);
    let bound = |side, peer| {
        config(side, &[peer]).replace("[sessions.s0]", "bind_interface='bindA'\n[sessions.s0]")
    };
    let mut a = pair.start(0, &bound(0, "192.0.2.2"));
    let mut b = pair.start(1, &bound(1, "192.0.2.1"));
    a.event("ready");
    b.event("ready");
    let indices = [pair.index(0, "l2tp0"), pair.index(1, "l2tp0")];
    for side in 0..2 {
        pair.ip(side, &["link", "set", "underlay", "name", "bindA"]);
    }
    a.event("connected to");
    b.event("connected to");
    pair.inner("l2tp0", 0);
    pair.frames(0);
    pair.ip(0, &["link", "set", "bindA", "name", "away"]);
    a.event("disconnected: its bind device is absent");
    let before = pair.drops(0, "l2tp0");
    assert!(
        !pair
            .output(0, "ping", &["-c", "1", "-W", "1", "198.18.0.2"])
            .status
            .success()
    );
    assert!(pair.drops(0, "l2tp0") > before);
    pair.ip(0, &["link", "set", "away", "name", "bindA"]);
    a.event("connected to");
    pair.frames(0);
    let old = pair.index(0, "bindA");
    pair.ip(0, &["link", "del", "bindA"]);
    a.event("disconnected: its bind device is absent");
    b.event("disconnected: its bind device is absent");
    pair.make_underlay();
    pair.underlay(true, false);
    for side in 0..2 {
        pair.ip(side, &["link", "set", "underlay", "name", "bindA"]);
    }
    a.event("connected to");
    b.event("connected to");
    assert_ne!(pair.index(0, "bindA"), old);
    for (side, index) in indices.into_iter().enumerate() {
        assert_eq!(pair.index(side, "l2tp0"), index);
    }
    pair.frames(0);
    a.stop();
    b.stop();
    pair.absent(0);
    pair.absent(1);
}

/// spec: H14
#[test]
#[ignore = "disposable privileged container"]
fn address_churn_reconnects_only_the_bound_tunnel_of_that_family() {
    let pair = Pair::new();
    pair.underlay(true, true);
    let bound = |side, peers: &[&str]| {
        config(side, peers).replace("[sessions.", "bind_interface='underlay'\n[sessions.")
    };
    let mut a = pair.start(0, &bound(0, &["192.0.2.2", "2001:db8:1::2"]));
    let mut b = pair.start(1, &bound(1, &["192.0.2.1", "2001:db8:1::1"]));
    a.event("ready");
    b.event("ready");
    let indices = [pair.index(0, "l2tp0"), pair.index(0, "l2tp1")];
    for n in 0..2 {
        pair.inner(&format!("l2tp{n}"), n);
        pair.frames(n);
    }
    let v4 = "tunnel t0 (tunnel_id=1): connected to";
    let v6 = "tunnel t1 (tunnel_id=11): connected to";
    assert_eq!((a.count(v4), a.count(v6)), (1, 1));
    for (operation, expected) in [("add", 2), ("del", 3)] {
        pair.ip(0, &["addr", operation, "192.0.2.9/24", "dev", "underlay"]);
        a.event(v4);
        assert_eq!((a.count(v4), a.count(v6)), (expected, 1));
    }
    for (operation, expected) in [("add", 2), ("del", 3)] {
        let mut args = vec![
            "-6",
            "addr",
            operation,
            "2001:db8:1::9/64",
            "dev",
            "underlay",
        ];
        if operation == "add" {
            args.push("nodad");
        }
        pair.ip(0, &args);
        a.event(v6);
        assert_eq!((a.count(v4), a.count(v6)), (3, expected));
    }
    for (n, index) in indices.into_iter().enumerate() {
        assert_eq!(pair.index(0, &format!("l2tp{n}")), index);
        pair.frames(n);
    }
    a.stop();
    b.stop();
    pair.absent(0);
    pair.absent(1);
}

/// spec: H18
#[test]
#[ignore = "disposable privileged container"]
fn bindv6only_correction_and_native_ipv4_fallback_both_deliver_frames() {
    for fix in [false, true] {
        let pair = Pair::new();
        pair.underlay(true, true);
        for side in 0..2 {
            pair.tunable(side, "1");
        }
        let configured = |side, peers: &[&str]| {
            config(side, peers).replace("fix_bindv6only=false", &format!("fix_bindv6only={fix}"))
        };
        let mut a = pair.start(0, &configured(0, &["192.0.2.2", "2001:db8:1::2"]));
        let mut b = pair.start(1, &configured(1, &["192.0.2.1", "2001:db8:1::1"]));
        a.event("ready");
        b.event("ready");
        let indices = [pair.index(0, "l2tp0"), pair.index(0, "l2tp1")];
        for side in 0..2 {
            assert_eq!(pair.only_v6_default(side), if fix { "0" } else { "1" });
            if fix {
                pair.ipv6_tunnels(side, 2);
            } else {
                let record = pair.ip(side, &["l2tp", "show", "tunnel"]);
                assert!(record.contains("From 192.0.2."));
                assert!(record.contains("From 2001:db8:1::"));
            }
        }
        for n in 0..2 {
            pair.inner(&format!("l2tp{n}"), n);
            pair.frames(n);
        }
        pair.tunable(0, "1");
        a.reload();
        super::support::wait("tunable correction or configured opt-out", || {
            pair.only_v6_default(0) == if fix { "0" } else { "1" }
        });
        for (n, index) in indices.into_iter().enumerate() {
            assert_eq!(pair.index(0, &format!("l2tp{n}")), index);
            pair.frames(n);
        }
        a.stop();
        b.stop();
        pair.absent(0);
        pair.absent(1);
    }
}

/// spec: H7
#[test]
#[ignore = "disposable privileged container"]
fn vrf_membership_selects_the_domain_and_scoped_member() {
    let pair = Pair::new();
    pair.underlay(true, true);
    for side in 0..2 {
        pair.ip(
            side,
            &[
                "-6",
                "addr",
                "add",
                &format!("fe80::{}/64", side + 1),
                "dev",
                "underlay",
                "nodad",
            ],
        );
        pair.ip(
            side,
            &["link", "add", "vrfA", "type", "vrf", "table", "100"],
        );
        pair.ip(side, &["link", "set", "vrfA", "up"]);
        pair.ip(
            side,
            &[
                "route",
                "add",
                "table",
                "100",
                "unreachable",
                "default",
                "metric",
                "4278198272",
            ],
        );
        pair.ip(
            side,
            &[
                "-6",
                "route",
                "add",
                "table",
                "100",
                "unreachable",
                "default",
                "metric",
                "4278198272",
            ],
        );
    }
    let bound = |side, peers: &[&str]| {
        config(side, peers).replace("[sessions.", "bind_interface='vrfA'\n[sessions.")
    };
    let mut a = pair.start(0, &bound(0, &["192.0.2.2", "fe80::2%underlay"]));
    let mut b = pair.start(1, &bound(1, &["192.0.2.1", "fe80::1%underlay"]));
    a.event("ready");
    b.event("ready");
    let indices = [pair.index(0, "l2tp0"), pair.index(0, "l2tp1")];
    for side in 0..2 {
        pair.ip(side, &["link", "set", "underlay", "master", "vrfA"]);
        // Enslaving can cycle the device down and discard its IPv6 addresses.
        pair.ip(
            side,
            &[
                "-6",
                "addr",
                "replace",
                &format!("fe80::{}/64", side + 1),
                "dev",
                "underlay",
                "nodad",
            ],
        );
    }
    for daemon in [&a, &b] {
        daemon.event("tunnel t0");
        daemon.event("connected to");
    }
    // Frames, not the event logs, establish both connections.
    for n in 0..2 {
        pair.inner(&format!("l2tp{n}"), n);
        pair.frames(n);
    }
    let tunnels = pair.ip(0, &["l2tp", "show", "tunnel"]);
    assert!(tunnels.contains("From ::ffff:192.0.2.1"));
    assert!(tunnels.contains("From fe80::1"));
    pair.ip(0, &["link", "set", "underlay", "nomaster"]);
    a.event("disconnected");
    for (n, index) in indices.into_iter().enumerate() {
        let dev = format!("l2tp{n}");
        let before = pair.drops(0, &dev);
        assert!(
            !pair
                .output(0, "ping", &["-c", "1", "-W", "1", &format!("198.18.{n}.2")])
                .status
                .success()
        );
        assert!(pair.drops(0, &dev) > before);
        assert_eq!(pair.index(0, &dev), index);
    }
    pair.ip(0, &["link", "set", "underlay", "master", "vrfA"]);
    pair.ip(
        0,
        &[
            "-6",
            "addr",
            "replace",
            "fe80::1/64",
            "dev",
            "underlay",
            "nodad",
        ],
    );
    a.event("connected to");
    for n in 0..2 {
        pair.frames(n);
    }
    a.stop();
    b.stop();
    pair.absent(0);
    pair.absent(1);
}

/// spec: H9, G10
#[test]
#[ignore = "disposable privileged container"]
fn noninitial_namespace_without_proc_runs_with_only_the_three_capabilities() {
    let pair = Pair::new();
    pair.underlay(true, false);
    let prefix = [
        "unshare",
        "--mount",
        "--propagation",
        "private",
        "sh",
        "-ec",
        "mount -t tmpfs tmpfs /proc; exec setpriv --bounding-set=-all,+net_admin,+net_raw,+net_bind_service \"$@\"",
        "run",
    ];
    let mut a = pair.start_with(0, &config(0, &["192.0.2.2"]), &prefix);
    let mut b = pair.start_with(1, &config(1, &["192.0.2.1"]), &prefix);
    a.event("ready");
    b.event("ready");
    for daemon in [&a, &b] {
        let status = std::fs::read_to_string(format!("/proc/{}/status", daemon.pid())).unwrap();
        let caps = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:\t"))
            .unwrap();
        assert_eq!(
            u64::from_str_radix(caps, 16).unwrap(),
            (1 << 10) | (1 << 12) | (1 << 13)
        );
        let mounts = std::fs::read_to_string(format!("/proc/{}/mounts", daemon.pid())).unwrap();
        assert!(
            mounts
                .lines()
                .any(|line| line.starts_with("tmpfs /proc tmpfs "))
        );
    }
    pair.inner("l2tp0", 0);
    pair.frames(0);
    a.stop();
    b.stop();
    pair.absent(0);
    pair.absent(1);
}

/// spec: H19, P22
#[test]
#[ignore = "disposable privileged container"]
fn non_systemd_init_observes_parent_exit_pidfile_reload_restart_and_shutdown() {
    use super::support::{BINARY, Detached};
    use nix::sys::signal::Signal;
    let pair = Pair::new();
    pair.underlay(true, false);
    let text = config(0, &["192.0.2.2"]);
    let path = pair.dir.join("init.toml");
    let pid_file = pair.dir.join("init.pid");
    std::fs::write(&path, &text).unwrap();
    let mut peer = pair.start(1, &config(1, &["192.0.2.1"]));
    peer.event("ready");
    let mut command = pair.command(0, "sh", &["-ec",
        "\"$@\" & parent=$!; wait \"$parent\"; test -s \"$PIDFILE\"; kill -0 \"$(cat \"$PIDFILE\")\"",
        "init", BINARY]);
    command
        .arg("--config")
        .arg(&path)
        .arg("--config-dir")
        .arg(pair.dir.join("absent"))
        .arg("--pid-file")
        .arg(&pid_file)
        .env("PIDFILE", &pid_file);
    let process = Detached::spawn(&pair, 0, command, pid_file, pair.dir.join("init.log"));
    process.event("ready");
    let pid = process.pid();
    let index = pair.index(0, "l2tp0");
    assert!(
        pair.ip(0, &["l2tp", "show", "tunnel"])
            .contains("Tunnel 1,")
    );
    assert!(
        pair.ip(0, &["l2tp", "show", "session"])
            .contains("Session 101 in tunnel 1")
    );
    pair.inner("l2tp0", 0);
    pair.frames(0);
    pair.ip(1, &["addr", "add", "192.0.2.3/24", "dev", "underlay"]);
    std::fs::write(&path, text.replace("192.0.2.2", "192.0.2.3")).unwrap();
    process.signal(Signal::SIGHUP);
    process.event("reload completed");
    assert_eq!(pair.index(0, "l2tp0"), index);
    assert!(
        pair.ip(0, &["l2tp", "show", "tunnel"])
            .contains("to ::ffff:192.0.2.3")
    );
    pair.frames(0);
    process.signal(Signal::SIGUSR2);
    process.event("re-exec resumed");
    assert_eq!(process.pid(), pid);
    assert_eq!(pair.index(0, "l2tp0"), index);
    pair.frames(0);
    process.stop(&pair);
    peer.stop();
    pair.absent(1);
}
