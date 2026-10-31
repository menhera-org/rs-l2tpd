//! Cases whose host conditions require a separately booted kernel.
#[allow(dead_code)]
#[path = "support.rs"]
mod support;

mod clocks;

use support::{Pair, config};

/// spec: R45, T10, G8
#[test]
#[ignore = "stock-kernel QEMU guest with vrf absent and module autoload disabled"]
fn unavailable_vrf_driver_keeps_ordinary_device_binding_and_frames() {
    assert_eq!(std::env::var("RS_L2TPD_NO_VRF").as_deref(), Ok("1"));
    assert!(!std::path::Path::new("/sys/module/vrf").exists());
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/modprobe")
            .unwrap()
            .trim(),
        "/no-module-loader"
    );
    let pair = Pair::new();
    let refused = pair.output(
        0,
        "ip",
        &["link", "add", "vrfprobe", "type", "vrf", "table", "100"],
    );
    assert!(!refused.status.success(), "{refused:?}");
    assert!(!std::path::Path::new("/sys/module/vrf").exists());
    pair.underlay(true, true);
    for side in 0..2 {
        pair.ip(side, &["link", "set", "underlay", "name", "vrf0"]);
        assert!(
            !pair
                .ip(side, &["-d", "link", "show", "vrf0"])
                .contains("vrf table")
        );
    }
    let bound = |side, peers: &[&str]| {
        config(side, peers).replace("[sessions.s", "bind_interface='vrf0'\n[sessions.s")
    };
    let mut a = pair.start(0, &bound(0, &["192.0.2.2", "2001:db8:1::2"]));
    let mut b = pair.start(1, &bound(1, &["192.0.2.1", "2001:db8:1::1"]));
    a.event("ready");
    b.event("ready");
    for daemon in [&a, &b] {
        assert_eq!(daemon.count("connected to"), 2);
    }
    for n in 0..2 {
        pair.inner(&format!("l2tp{n}"), n);
        pair.frames(n);
    }
    let indices = [pair.index(0, "l2tp0"), pair.index(0, "l2tp1")];
    pair.ip(0, &["link", "set", "vrf0", "name", "away"]);
    support::wait("both ordinary-device bindings lost", || {
        a.count("disconnected: its bind device is absent") == 2
    });
    pair.ip(0, &["link", "set", "away", "name", "vrf0"]);
    support::wait("both ordinary-device bindings restored", || {
        a.count("connected to") == 4
    });
    for (n, index) in indices.into_iter().enumerate() {
        assert_eq!(pair.index(0, &format!("l2tp{n}")), index);
        pair.frames(n);
    }
    a.stop();
    b.stop();
    pair.absent(0);
    pair.absent(1);
    assert!(!std::path::Path::new("/sys/module/vrf").exists());
}

/// spec: H4, T4, R27
#[test]
#[ignore = "QEMU guest booted with ipv6.disable=1 or CONFIG_IPV6=n"]
fn absent_ipv6_stack_uses_native_ipv4_and_keeps_ipv6_peers_disconnected() {
    assert_eq!(std::env::var("RS_L2TPD_IPV6_ABSENT").as_deref(), Ok("1"));
    let refused = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::from(115)),
    )
    .unwrap_err();
    assert!(matches!(
        refused.raw_os_error(),
        Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT)
    ));
    let pair = Pair::new();
    pair.underlay(true, false);
    let mut a = pair.start(0, &config(0, &["192.0.2.2", "2001:db8:1::2"]));
    let mut b = pair.start(1, &config(1, &["192.0.2.1", "2001:db8:1::1"]));
    a.event("ready");
    b.event("ready");
    let indices = [pair.index(0, "l2tp0"), pair.index(0, "l2tp1")];
    for side in 0..2 {
        let tunnels = pair.ip(side, &["l2tp", "show", "tunnel"]);
        assert_eq!(
            tunnels
                .lines()
                .filter(|line| line.trim_start().starts_with("From "))
                .count(),
            2
        );
        assert!(tunnels.contains("From 192.0.2.") && !tunnels.contains("::ffff:"));
        assert!(tunnels.contains("From 0.0.0.0 to 0.0.0.0"));
    }
    pair.inner("l2tp0", 0);
    pair.frames(0);
    pair.inner("l2tp1", 1);
    let drops = pair.drops(0, "l2tp1");
    assert!(
        !pair
            .output(0, "ping", &["-c", "1", "-W", "1", "198.18.1.2"])
            .status
            .success()
    );
    assert!(pair.drops(0, "l2tp1") > drops);
    for _ in 0..3 {
        a.reload();
        b.reload();
    }
    for daemon in [&a, &b] {
        assert_eq!(daemon.count("AF_INET6 L2TP/IP sockets are refused"), 1);
        assert_eq!(
            daemon.count("an IPv6 peer cannot be reached on its AF_INET socket"),
            1
        );
    }
    for (n, index) in indices.into_iter().enumerate() {
        assert_eq!(pair.index(0, &format!("l2tp{n}")), index);
    }
    pair.frames(0);
    a.stop();
    b.stop();
    pair.absent(0);
    pair.absent(1);
}

/// spec: H15, R1, K3, O2
#[test]
#[ignore = "stock-kernel QEMU guest with l2tp_eth absent and module autoload disabled"]
fn missing_ethernet_driver_withholds_readiness_until_the_driver_is_loaded() {
    use std::path::Path;
    use std::process::Command;
    use std::time::{Duration, Instant};
    assert_eq!(std::env::var("RS_L2TPD_NO_ETHERNET").as_deref(), Ok("1"));
    assert!(Path::new("/sys/module/l2tp_core").exists());
    assert!(!Path::new("/sys/module/l2tp_eth").exists());
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/modprobe")
            .unwrap()
            .trim(),
        "/no-module-loader"
    );
    let pair = Pair::new();
    pair.underlay(true, true);
    let mut daemon = pair.start(0, &config(0, &["192.0.2.2"]));
    daemon.event("session s0 (tunnel_id=1, session_id=101): cannot be created:");
    daemon.assert_unready_for(Duration::from_millis(2200));
    assert_eq!(daemon.count("cannot be created:"), 1);
    assert_eq!(
        daemon.count("ERROR rs_l2tpd::reconciler::report: session"),
        1
    );
    assert!(pair.ip(0, &["l2tp", "show", "tunnel"]).contains("Tunnel 1"));
    assert!(pair.ip(0, &["l2tp", "show", "session"]).trim().is_empty());
    assert!(!Path::new("/sys/module/l2tp_eth").exists());
    let output = Command::new("modprobe").arg("l2tp_eth").output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let available = Instant::now();
    let ready = daemon.event("ready pid=");
    assert!(ready.saturating_duration_since(available) <= Duration::from_secs(1));
    assert_eq!(daemon.count("cannot be created:"), 1);
    let mut peer = pair.start(1, &config(1, &["192.0.2.1"]));
    peer.event("ready");
    pair.inner("l2tp0", 0);
    pair.frames(0);
    daemon.stop();
    peer.stop();
    pair.absent(0);
    pair.absent(1);
}
