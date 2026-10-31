//! Capability loss is exercised by real child processes, never by changing the test supervisor.
#[allow(dead_code)]
#[path = "../support/discovery.rs"]
mod discovery;

use super::support::{Pair, checked, config, deny_socket_option, wait};
use discovery::{Dns, advertise};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// spec: R6, A18, K10, G1, O6
#[test]
#[ignore = "disposable privileged container or QEMU guest; child-only filter refusal"]
fn refused_monitor_filter_warns_once_and_address_events_still_reconnect() {
    let pair = Pair::new();
    pair.underlay(true, false);
    let path = pair.dir.join("monitor-filter.bpf");
    deny_socket_option(&path, nix::libc::SOL_SOCKET, nix::libc::SO_ATTACH_FILTER);
    let mut daemon = pair.start_with(
        0,
        &config(0, &["192.0.2.2"]),
        &[
            "setpriv",
            "--no-new-privs",
            "--seccomp-filter",
            path.to_str().unwrap(),
        ],
    );
    let mut peer = pair.start(1, &config(1, &["192.0.2.1"]));
    daemon.event("WARN rs_l2tpd::kernel::linux::monitor: event monitor runs unfiltered: EPERM:");
    daemon.event("ready");
    peer.event("ready");
    pair.inner("l2tp0", 0);
    pair.frames(0);
    let index = pair.index(0, "l2tp0");
    for _ in 0..100 {
        pair.ip(0, &["link", "add", "foreign", "type", "dummy"]);
        pair.ip(0, &["link", "del", "foreign"]);
    }
    pair.ip(0, &["addr", "del", "192.0.2.1/24", "dev", "underlay"]);
    daemon.event("disconnected, peer 192.0.2.2 pending:");
    pair.ip(0, &["addr", "add", "192.0.2.1/24", "dev", "underlay"]);
    daemon.event("connected to 192.0.2.2 from 192.0.2.1");
    assert_eq!(pair.index(0, "l2tp0"), index);
    pair.frames(0);
    daemon.reload();
    assert_eq!(daemon.count("event monitor runs unfiltered:"), 1);
    assert_eq!(peer.count("event monitor runs unfiltered:"), 0);
    daemon.stop();
    peer.stop();
    pair.absent(0);
    pair.absent(1);
}

/// spec: R9, G6, G8, M13, O2, O3
#[test]
#[ignore = "disposable privileged container or QEMU guest; child-only descriptor limit"]
fn descriptor_exhaustion_is_transient_and_recovers_after_the_limit_is_raised() {
    let pair = Pair::new();
    pair.underlay(true, false);
    let mut text = config(0, &["192.0.2.2"]).replace("t0", "a0");
    for n in 1..40 {
        text += &format!(
            "\n[tunnels.extra{n:02}]\ntunnel_id={}\nremote_addr='192.0.2.2'\n",
            n + 100
        );
    }
    let mut daemon = pair.start_with(0, &text, &["prlimit", "--nofile=32:256", "--"]);
    let mut peer = pair.start(1, &config(1, &["192.0.2.1"]));
    daemon.event("EMFILE");
    daemon.assert_unready_for(Duration::from_millis(2200));
    assert_eq!(
        daemon.count("ERROR"),
        0,
        "descriptor exhaustion is transient"
    );
    let partial = pair
        .ip(0, &["l2tp", "show", "tunnel"])
        .lines()
        .filter(|l| l.starts_with("Tunnel "))
        .count();
    assert!(
        partial > 0 && partial < 40,
        "partial tunnel count: {partial}"
    );
    assert_eq!(daemon.count(": cannot be created: EMFILE:"), 40 - partial);
    peer.event("ready");
    pair.inner("l2tp0", 0);
    pair.frames(0);
    let index = pair.index(0, "l2tp0");
    let mut limit = std::process::Command::new("prlimit");
    limit.args(["--pid", &daemon.pid().to_string(), "--nofile=256:256"]);
    checked(limit);
    daemon.event("ready");
    let complete = pair
        .ip(0, &["l2tp", "show", "tunnel"])
        .lines()
        .filter(|l| l.starts_with("Tunnel "))
        .count();
    assert_eq!(complete, 40);
    assert_eq!(pair.index(0, "l2tp0"), index);
    pair.frames(0);
    daemon.stop();
    peer.stop();
    pair.absent(0);
    pair.absent(1);
}

fn capabilities(pid: u32, expected: u64) {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let effective = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:\t"))
        .unwrap();
    assert_eq!(u64::from_str_radix(effective, 16).unwrap(), expected);
}

/// spec: H15, R3, K8
#[test]
#[ignore = "disposable privileged container; drops only the daemon's CAP_NET_ADMIN"]
fn missing_net_admin_reports_once_and_withholds_nonempty_readiness() {
    let pair = Pair::new();
    pair.underlay(true, false);
    let mut daemon = pair.start_with(
        0,
        &config(0, &["192.0.2.2"]),
        &["setpriv", "--bounding-set=-all,+net_raw,+net_bind_service"],
    );
    daemon.event("missing CAP_NET_ADMIN");
    daemon.event("cannot be created: EPERM");
    capabilities(daemon.pid(), (1 << 13) | (1 << 10));
    daemon.assert_unready_for(Duration::from_millis(2200));
    assert_eq!(daemon.count("missing CAP_NET_ADMIN"), 1);
    assert_eq!(daemon.count("cannot be created: EPERM"), 1);
    pair.absent(0);
    daemon.stop();
    assert_eq!(daemon.count("ready pid="), 0);
}

fn discovery_peer(pair: &Pair) -> (Dns, Socket, SocketAddrV6, UdpSocket) {
    pair.underlay(true, true);
    for (side, addresses) in [
        (0, ["fe80::1/64", "2001:db8::1/64"]),
        (1, ["fe80::2/64", "2001:db8::9/64"]),
    ] {
        for address in addresses {
            pair.ip(
                side,
                &["-6", "addr", "add", address, "dev", "underlay", "nodad"],
            );
        }
    }
    pair.ip(
        1,
        &[
            "-6",
            "addr",
            "add",
            "2001:db8::53/64",
            "dev",
            "underlay",
            "nodad",
        ],
    );
    let index = pair.index(1, "underlay");
    let original = std::fs::File::open("/proc/self/ns/net").unwrap();
    let target = std::fs::File::open(format!("/run/netns/{}", pair.names[1])).unwrap();
    nix::sched::setns(target, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    let dns = Dns::new("2001:db8::53", "underlay");
    let dhcp = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    dhcp.set_reuse_address(true).unwrap();
    dhcp.bind_device(Some(b"underlay")).unwrap();
    dhcp.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 547, 0, 0).into())
        .unwrap();
    dhcp.join_multicast_v6(&"ff02::1:2".parse().unwrap(), index)
        .unwrap();
    dhcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let sender = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap();
    sender.bind_device(Some(b"underlay")).unwrap();
    sender.set_unicast_hops_v6(255).unwrap();
    sender
        .bind(&SocketAddrV6::new("fe80::2".parse().unwrap(), 0, 0, index).into())
        .unwrap();
    nix::sched::setns(original, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    (
        dns,
        sender,
        SocketAddrV6::new("fe80::1".parse().unwrap(), 0, 0, index),
        dhcp.into(),
    )
}

fn discovered_config(method: &str) -> String {
    config(0, &["controlled.example"]).replace("remote_addr='controlled.example'", "remote_addr='controlled.example'\nip_version='V6'\nresolver_name='dns'\nbind_interface='underlay'")
        + &format!("\n[resolvers.dns]\nmethod='{method}'\nbind_interface='underlay'\n")
}

/// spec: H15, R4, K6, K14, K39, K40
#[test]
#[ignore = "disposable privileged container; real RA netlink fallback without CAP_NET_RAW"]
fn without_net_raw_router_discovery_requires_accept_ra_and_binding_still_reconnects() {
    let pair = Pair::new();
    let (dns, sender, destination, _dhcp) = discovery_peer(&pair);
    checked(pair.command(
        0,
        "sh",
        &["-ec", "echo 0 > /proc/sys/net/ipv6/conf/underlay/accept_ra"],
    ));
    let mut peer = pair.start(1, &config(1, &["2001:db8::1"]));
    let mut daemon = pair.start_with(
        0,
        &discovered_config("ra"),
        &[
            "setpriv",
            "--bounding-set=-all,+net_admin,+net_bind_service",
        ],
    );
    daemon.event("missing CAP_NET_RAW");
    daemon.event("ready");
    peer.event("ready");
    capabilities(daemon.pid(), (1 << 12) | (1 << 10));
    // The same advertisement reaches the wire repeatedly but the kernel
    // must not forward its options while accept_ra is disabled.
    // Exceed initial discovery's three-second wait so a wrongly delivered RA would trigger DNS.
    let until = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < until {
        advertise(
            &sender,
            destination,
            &[("2001:db8::53".parse().unwrap(), 300)],
        );
        assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !pair
            .ip(0, &["l2tp", "show", "tunnel"])
            .contains("to 2001:db8::9")
    );
    checked(pair.command(
        0,
        "sh",
        &["-ec", "echo 1 > /proc/sys/net/ipv6/conf/underlay/accept_ra"],
    ));
    // Request a fresh lookup rather than waiting for the thirty-second refresh.
    std::fs::write(
        pair.dir.join("0.toml"),
        discovered_config("ra").replace("controlled.example", "renewed.example"),
    )
    .unwrap();
    daemon.reload();
    wait("RA netlink fallback resolves the peer", || {
        advertise(
            &sender,
            destination,
            &[("2001:db8::53".parse().unwrap(), 300)],
        );
        pair.ip(0, &["l2tp", "show", "tunnel"])
            .contains("to 2001:db8::9")
    });
    assert!(dns.calls.load(Ordering::SeqCst) > 0);
    pair.inner("l2tp0", 0);
    pair.frames(0);
    let original_index = pair.index(0, "l2tp0");
    pair.ip(
        0,
        &[
            "-6",
            "addr",
            "replace",
            "2001:db8::3/64",
            "dev",
            "underlay",
            "nodad",
        ],
    );
    daemon.event("connected to 2001:db8::9 from 2001:db8::3");
    assert_eq!(pair.index(0, "l2tp0"), original_index);
    pair.frames(0);
    daemon.reload();
    assert_eq!(daemon.count("missing CAP_NET_RAW"), 1);
    daemon.stop();
    peer.stop();
    pair.absent(0);
    pair.absent(1);
}

/// spec: H15, R46, K13, V12, V14
#[test]
#[ignore = "disposable privileged container; port 546 requires the removed capability"]
fn without_bind_service_dhcpv6_degrades_and_unified_discovery_uses_ra() {
    for (method, port_start) in [("dhcpv6", "1024"), ("ipv6", "1024"), ("dhcpv6", "0")] {
        let pair = Pair::new();
        let (dns, sender, destination, dhcp) = discovery_peer(&pair);
        checked(pair.command(
            0,
            "sh",
            &[
                "-ec",
                &format!("echo {port_start} > /proc/sys/net/ipv4/ip_unprivileged_port_start"),
            ],
        ));
        let mut peer = pair.start(1, &config(1, &["2001:db8::1"]));
        let mut daemon = pair.start_with(
            0,
            &discovered_config(method),
            &["setpriv", "--bounding-set=-all,+net_admin,+net_raw"],
        );
        daemon.event("missing CAP_NET_BIND_SERVICE");
        daemon.event("ready");
        peer.event("ready");
        capabilities(daemon.pid(), (1 << 12) | (1 << 13));
        if method == "ipv6" {
            wait(
                "RA serves the unified resolver despite denied DHCPv6 bind",
                || {
                    advertise(
                        &sender,
                        destination,
                        &[("2001:db8::53".parse().unwrap(), 300)],
                    );
                    pair.ip(0, &["l2tp", "show", "tunnel"])
                        .contains("to 2001:db8::9")
                },
            );
            assert!(dns.calls.load(Ordering::SeqCst) > 0);
            pair.inner("l2tp0", 0);
            pair.frames(0);
        } else if port_start == "0" {
            let mut request = [0; 1500];
            let (length, source) = dhcp.recv_from(&mut request).unwrap();
            assert!(length >= 4 && request[0] == 11);
            assert_eq!(
                source.port(),
                546,
                "the daemon really bound the DHCPv6 client port"
            );
            let mut reply = vec![7, request[1], request[2], request[3], 0, 23, 0, 16];
            reply.extend("2001:db8::53".parse::<Ipv6Addr>().unwrap().octets());
            dhcp.send_to(&reply, source).unwrap();
            wait(
                "DHCPv6 works without the capability in the low unprivileged range",
                || {
                    pair.ip(0, &["l2tp", "show", "tunnel"])
                        .contains("to 2001:db8::9")
                },
            );
            assert!(dns.calls.load(Ordering::SeqCst) > 0);
            assert_eq!(daemon.count("EACCES"), 0);
            pair.inner("l2tp0", 0);
            pair.frames(0);
        } else {
            wait("DHCPv6 bind denied as one host defect", || {
                daemon.count("ERROR rs_l2tpd::reconciler::report:") == 1
                    && daemon.count("EACCES: Permission denied") == 1
            });
            assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
            assert!(
                !pair
                    .ip(0, &["l2tp", "show", "tunnel"])
                    .contains("to 2001:db8::9")
            );
        }
        daemon.reload();
        assert_eq!(daemon.count("missing CAP_NET_BIND_SERVICE"), 1);
        daemon.stop();
        peer.stop();
        pair.absent(0);
        pair.absent(1);
    }
}

/// spec: H15, R5, O6
#[test]
#[ignore = "disposable privileged container; seccomp refuses only the daemon's netlink sockets"]
fn refused_netlink_reports_once_keeps_running_and_withholds_readiness() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    let pair = Pair::new();
    pair.underlay(true, false);
    let architecture = match std::env::consts::ARCH {
        "x86_64" => 0xc000003e,
        "aarch64" => 0xc00000b7,
        other => panic!("unsupported seccomp fixture ABI: {other}"),
    };
    // Linux UAPI seccomp_data: arch at 4, syscall at 0, first argument at 16.
    let filter: [(u16, u8, u8, u32); 9] = [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, architecture),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
        (0x15, 0, 3, libc::SYS_socket as u32),
        (0x20, 0, 0, 16),
        (0x15, 0, 1, libc::AF_NETLINK as u32),
        (0x06, 0, 0, 0x00050000 | libc::EPERM as u32),
        (0x06, 0, 0, 0x7fff0000),
    ];
    let bytes: Vec<_> = filter
        .into_iter()
        .flat_map(|(code, jt, jf, k)| {
            let [a, b] = code.to_ne_bytes();
            let [c, d, e, f] = k.to_ne_bytes();
            [a, b, jt, jf, c, d, e, f]
        })
        .collect();
    let path = pair.dir.join("netlink-denied.bpf");
    std::fs::write(&path, bytes).unwrap();
    let mut daemon = pair.start_with(
        0,
        &config(0, &["192.0.2.2"]),
        &[
            "setpriv",
            "--no-new-privs",
            "--seccomp-filter",
            path.to_str().unwrap(),
            "--bounding-set=-all,+net_admin,+net_raw,+net_bind_service",
        ],
    );
    daemon.event("opening kernel interfaces: EPERM");
    capabilities(daemon.pid(), (1 << 10) | (1 << 12) | (1 << 13));
    daemon.assert_unready_for(Duration::from_millis(2200));
    assert_eq!(daemon.count("opening kernel interfaces:"), 1);
    assert_eq!(daemon.count("missing CAP_"), 0);
    pair.absent(0);
    kill(Pid::from_raw(daemon.pid() as i32), Signal::SIGTERM).unwrap();
    daemon.wait_exit(1);
    assert_eq!(daemon.count("ready pid="), 0);
}
