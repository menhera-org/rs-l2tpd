//! Cases whose host conditions require a separately booted kernel.
#[allow(dead_code)]
#[path = "support.rs"]
mod support;

use support::{Pair, config};

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
