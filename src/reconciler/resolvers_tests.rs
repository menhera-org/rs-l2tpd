//! Released iphost adapter checks, using isolated, locally controlled peers.
use super::*;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};

/// spec: V5, V6
#[test]
fn selection_checks_every_unusable_address_class_and_preserves_a_present_choice() {
    for text in [
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "::",
        "ff02::1",
        "::ffff:192.0.2.1",
        "fe80::1",
    ] {
        let address = text.parse().unwrap();
        for family in [Family::V4, Family::V6] {
            assert_eq!(
                select(None, &[address], family, false),
                None,
                "{text} {family:?}"
            );
        }
    }
    let a = "192.0.2.1".parse().unwrap();
    let b = "192.0.2.2".parse().unwrap();
    assert_eq!(select(Some(a), &[b, a], Family::V4, false), Some(a));
    assert_eq!(select(Some(a), &[b], Family::V4, false), Some(b));
    let local = "fe80::1".parse().unwrap();
    assert_eq!(select(None, &[local], Family::V6, true), Some(local));
}

fn ip(args: &[&str]) -> String {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn index(name: &str) -> u32 {
    ip(&["-o", "link", "show", "dev", name])
        .split(':')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

fn fixture() -> (Socket, SocketAddrV6, Dns, Dns, UdpSocket) {
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    ip(&["link", "set", "lo", "up"]);
    ip(&[
        "link",
        "add",
        "name",
        "dns-host",
        "type",
        "veth",
        "peer",
        "name",
        "dns-router",
    ]);
    ip(&["link", "set", "dev", "dns-host", "mtu", "9000", "up"]);
    ip(&[
        "-6",
        "addr",
        "add",
        "fe80::2/64",
        "dev",
        "dns-host",
        "nodad",
    ]);
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8::2/64",
        "dev",
        "dns-host",
        "nodad",
    ]);
    let (ready, receive) = std::sync::mpsc::channel();
    let (moved, wait) = std::sync::mpsc::channel();
    let (send, result) = std::sync::mpsc::channel();
    let router = std::thread::spawn(move || {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        ready.send(nix::unistd::gettid().as_raw()).unwrap();
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
        ip(&["link", "set", "lo", "up"]);
        ip(&["link", "set", "dev", "dns-router", "mtu", "9000", "up"]);
        for addr in ["fe80::1/64", "2001:db8::53/64", "2001:db8::54/64"] {
            ip(&["-6", "addr", "add", addr, "dev", "dns-router", "nodad"]);
        }
        let index = index("dns-router");
        let sender = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap();
        sender.bind_device(Some(b"dns-router")).unwrap();
        sender.set_unicast_hops_v6(255).unwrap();
        sender
            .bind(&SocketAddrV6::new("fe80::1".parse().unwrap(), 0, 0, index).into())
            .unwrap();
        let dhcp = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        dhcp.set_reuse_address(true).unwrap();
        dhcp.bind_device(Some(b"dns-router")).unwrap();
        dhcp.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 547, 0, 0).into())
            .unwrap();
        dhcp.join_multicast_v6(&"ff02::1:2".parse().unwrap(), index)
            .unwrap();
        dhcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        send.send((
            sender,
            SocketAddrV6::new("fe80::2".parse().unwrap(), 0, 0, index),
            Dns::new("2001:db8::53"),
            Dns::new("2001:db8::54"),
            UdpSocket::from(dhcp),
        ))
        .unwrap();
    });
    let tid = receive.recv_timeout(Duration::from_secs(5)).unwrap();
    ip(&[
        "link",
        "set",
        "dev",
        "dns-router",
        "netns",
        &tid.to_string(),
    ]);
    moved.send(()).unwrap();
    let fixture = result.recv_timeout(Duration::from_secs(5)).unwrap();
    router.join().unwrap();
    fixture
}

fn advertise(sender: &Socket, destination: SocketAddrV6, servers: &[(Ipv6Addr, u32)]) {
    let mut packet = vec![134, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for (server, lifetime) in servers {
        packet.extend([25, 3, 0, 0]);
        packet.extend(lifetime.to_be_bytes());
        packet.extend(server.octets());
    }
    sender.send_to(&packet, &destination.into()).unwrap();
}

fn until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "fixture did not reach its observed state"
        );
        std::thread::yield_now();
    }
}

/// spec: V10, E23, K14, K39, K40
#[test]
#[ignore = "isolated namespace with CAP_NET_ADMIN and CAP_NET_RAW"]
fn released_ra_adapter_preserves_omitted_addresses_and_bounds_its_repository() {
    let (sender, destination, _primary, _fallback, _dhcp) = fixture();
    std::fs::write("/proc/sys/net/ipv6/conf/dns-host/accept_ra", "0").unwrap();
    let resolver = IphostResolve::default()
        .resolver(&ResolverSpec::Ra {
            interface: "dns-host".into(),
        })
        .unwrap();
    let iphost::Resolver::Ra(ra) = resolver else {
        panic!()
    };
    assert_eq!(ra.source(), iphost::RaSource::RawSocket);
    let (a, b) = (
        "2001:db8::53".parse().unwrap(),
        "2001:db8::54".parse().unwrap(),
    );
    // Reception is observed through the released public adapter, without sleeps.
    // The first listener bind can race this send, so resend until observed.
    until(|| {
        advertise(&sender, destination, &[(a, 300), (b, 300)]);
        ra.nameservers() == [a, b]
    });
    advertise(&sender, destination, &[]);
    advertise(&sender, destination, &[(a, 600)]);
    until(|| ra.nameservers() == [a, b]);
    advertise(&sender, destination, &[(a, 0)]);
    until(|| ra.nameservers() == [b]);
    let many: Vec<_> = (1..=70)
        .map(|n| (Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, n), u32::MAX))
        .collect();
    advertise(&sender, destination, &many);
    until(|| ra.nameservers().len() == 64);
    assert_eq!(
        ra.nameservers(),
        many[..64].iter().map(|(a, _)| *a).collect::<Vec<_>>()
    );
}

struct Dns {
    mode: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    socket: UdpSocket,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Dns {
    fn new(address: &str) -> Self {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        socket.bind_device(Some(b"dns-router")).unwrap();
        socket
            .bind(&SocketAddrV6::new(address.parse().unwrap(), 53, 0, 0).into())
            .unwrap();
        let socket: UdpSocket = socket.into();
        let reader = socket.try_clone().unwrap();
        let mode = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let (policy, count) = (mode.clone(), calls.clone());
        let thread = std::thread::spawn(move || {
            let mut packet = [0; 512];
            while let Ok((len, peer)) = reader.recv_from(&mut packet) {
                if len == 1 {
                    return;
                }
                count.fetch_add(1, Ordering::SeqCst);
                let query = &packet[..len];
                let qtype = u16::from_be_bytes(query[len - 4..len - 2].try_into().unwrap());
                let mode = policy.load(Ordering::SeqCst);
                let failure = mode == 1 || (mode == 3 && qtype == 28);
                let negative = mode == 2;
                let mut reply = query.to_vec();
                reply[2..4].copy_from_slice(&[
                    0x81,
                    if failure {
                        0x82
                    } else if negative {
                        0x83
                    } else {
                        0x80
                    },
                ]);
                if !failure && !negative {
                    reply[6..8].copy_from_slice(&1u16.to_be_bytes());
                    reply.extend([0xc0, 0x0c]);
                    reply.extend(qtype.to_be_bytes());
                    reply.extend([0, 1, 0, 0, 0, 30]);
                    if qtype == 1 {
                        reply.extend([0, 4, 192, 0, 2, 9]);
                    } else {
                        reply.extend([0, 16]);
                        reply.extend("2001:db8::9".parse::<Ipv6Addr>().unwrap().octets());
                    }
                }
                reader.send_to(&reply, peer).unwrap();
            }
        });
        Self {
            mode,
            calls,
            socket,
            thread: Some(thread),
        }
    }
}

impl Drop for Dns {
    fn drop(&mut self) {
        let _ = self.socket.send_to(&[0], self.socket.local_addr().unwrap());
        let _ = self.thread.take().unwrap().join();
    }
}

/// spec: V14, V4, V6
#[test]
#[ignore = "isolated namespace with CAP_NET_ADMIN and CAP_NET_RAW"]
fn released_unified_adapter_enables_per_family_failure_fallback() {
    let (sender, destination, primary, fallback, dhcp) = fixture();
    let resolver = IphostResolve::default()
        .resolver(&ResolverSpec::Ipv6 {
            interface: "dns-host".into(),
            client_id: ClientId::None,
        })
        .unwrap();
    let iphost::Resolver::Ipv6(config) = &resolver else {
        panic!()
    };
    assert_eq!(resolver.max_lookup_time(), Some(Duration::from_secs(63)));
    let mut request = [0; 1500];
    let (len, peer) = dhcp.recv_from(&mut request).unwrap();
    assert!(len >= 4 && request[0] == 11);
    let mut reply = vec![7, request[1], request[2], request[3], 0, 23, 0, 16];
    reply.extend("2001:db8::53".parse::<Ipv6Addr>().unwrap().octets());
    dhcp.send_to(&reply, peer).unwrap();
    until(|| !config.dhcpv6().unwrap().nameservers().is_empty());
    until(|| {
        advertise(
            &sender,
            destination,
            &[("2001:db8::54".parse().unwrap(), 300)],
        );
        !config.ra().unwrap().nameservers().is_empty()
    });
    let lookup = || {
        iphost::IpHostResolver::new_with_config("controlled.example".parse().unwrap(), false, false)
            .with_resolver(resolver.clone())
            .resolve()
    };
    for mode in [1, 0, 2, 3] {
        primary.mode.store(mode, Ordering::SeqCst);
        let before = fallback.calls.load(Ordering::SeqCst);
        let answer = lookup();
        if mode == 2 {
            assert!(answer.is_empty());
        } else {
            assert_eq!(
                answer.len(),
                2,
                "mode {mode}: primary {} fallback {}",
                primary.calls.load(Ordering::SeqCst),
                fallback.calls.load(Ordering::SeqCst)
            );
        }
        assert_eq!(
            fallback.calls.load(Ordering::SeqCst) > before,
            mode == 1 || mode == 3
        );
    }
    primary.mode.store(1, Ordering::SeqCst);
    fallback.mode.store(1, Ordering::SeqCst);
    assert!(lookup().is_empty(), "both sources failed");
}

/// spec: V4, V10, V15, G23
#[test]
#[ignore = "isolated namespace with CAP_NET_ADMIN and CAP_NET_RAW"]
fn removing_the_last_watch_releases_discovery_threads_and_descriptors() {
    let (sender, destination, _primary, _fallback, _dhcp) = fixture();
    let threads = || std::fs::read_dir("/proc/self/task").unwrap().count();
    let descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let baseline = (threads(), descriptors());
    let mut resolve = IphostResolve::default();
    resolve
        .watch(Lookup {
            id: 1,
            host: "controlled.example".into(),
            resolver: ResolverSpec::Ra {
                interface: "dns-host".into(),
            },
        })
        .unwrap();
    let iphost::Resolver::Ra(config) = &resolve.watches[&1].1 else {
        panic!()
    };
    until(|| {
        advertise(
            &sender,
            destination,
            &[("2001:db8::54".parse().unwrap(), 300)],
        );
        !config.nameservers().is_empty()
    });
    until(|| {
        resolve
            .poll()
            .iter()
            .any(|(id, answer)| *id == 1 && answer.len() == 2)
    });
    resolve.unwatch(1);
    assert!(resolve.watches.is_empty());
    assert!(resolve.workers.is_none());
    until(|| threads() <= baseline.0 && descriptors() <= baseline.1);
}
