//! Released iphost adapter checks, using isolated, locally controlled peers.
use super::*;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, UdpSocket};
use std::sync::atomic::Ordering;
#[path = "../../tests/support/discovery.rs"]
mod discovery;
use crate::kernel::linux::syscall_fault as socket_fault;
use discovery::{Dns, advertise};

/// spec: V12, V14
#[test]
#[ignore = "disposable namespace with NET_ADMIN, NET_RAW and seccomp"]
fn dhcp_only_discovery_remains_partial_when_ra_setup_fails() {
    const CHILD: &str = "RS_L2TPD_DHCP_ONLY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "reconciler::resolvers::tests::dhcp_only_discovery_remains_partial_when_ra_setup_fails",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("DHCP_ONLY_PARTIAL=1"));
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    let (_sender, _destination, _primary, _fallback, dhcp) = fixture();
    let mut request = [0; 1500];
    // ICMP6_FILTER is option 1; DHCPv6's IPv6 socket options remain available.
    socket_fault::on_exec_arguments(
        nix::libc::SYS_setsockopt,
        nix::libc::IPPROTO_ICMPV6,
        1,
        nix::libc::EIO,
    )()
    .unwrap();
    let resolver = IphostResolve::default()
        .resolver(&ResolverSpec::Ipv6 {
            interface: "dns-host".into(),
            client_id: ClientId::None,
        })
        .unwrap();
    let iphost::Resolver::Ipv6(config) = &resolver else {
        panic!("the unified resolver must keep its working DHCPv6 source");
    };
    assert!(config.dhcpv6().is_some() && config.ra().is_none());
    assert!(IphostResolve::partial(&resolver));
    assert_eq!(resolver.max_lookup_time(), Some(Duration::from_secs(33)));
    let (len, peer) = dhcp.recv_from(&mut request).unwrap();
    assert!(len >= 4 && request[0] == 11);
    let mut reply = vec![7, request[1], request[2], request[3], 0, 23, 0, 16];
    let address = "2001:db8::53".parse::<Ipv6Addr>().unwrap();
    reply.extend(address.octets());
    dhcp.send_to(&reply, peer).unwrap();
    until(|| config.dhcpv6().unwrap().nameservers() == [address]);
    println!("DHCP_ONLY_PARTIAL=1 dhcp_exchange=1 ra_started=0");
}

/// spec: G23, M16, V7, V9, V15
#[cfg(all(feature = "fake-kernel", feature = "serde"))]
#[test]
fn resolver_dependency_indexes_release_removed_configurations() {
    let _socket_workload = crate::reconciler::tests::socket_workload();
    struct NoDns;
    impl Resolve for NoDns {
        fn watch(&mut self, _: Lookup) -> io::Result<()> {
            Ok(())
        }
        fn unwatch(&mut self, _: u64) {}
        fn poll(&mut self) -> Vec<(u64, Vec<IpAddr>)> {
            Vec::new()
        }
    }
    let mut r = Reconciler::new(crate::kernel::fake::FakeKernel::new(42), Box::new(NoDns));
    for epoch in 0..4 {
        let interface = format!("dns{epoch}");
        let mut text = format!(
            "[host]\nfix_bindv6only=false\n[resolvers.dns]\naddresses=['192.0.2.53']\nbind_interface='{interface}'\n"
        );
        for n in 0..300 {
            let id = 1 + epoch * 1000 + n;
            text += &format!(
                "[tunnels.t{id}]\ntunnel_id={id}\nip_version='V4'\nremote_addr='history.example'\nresolver_name='dns'\n"
            );
        }
        assert!(r.reconcile(toml::from_str(&text).unwrap()));
        assert_eq!(r.resolvers.watches.len(), 300);
        assert_eq!(r.resolvers.lookups.len(), 300);
        assert_eq!(r.resolvers.retries.len(), 300);
        assert_eq!(
            r.resolvers.names.values().map(BTreeSet::len).sum::<usize>(),
            300
        );
        assert!(r.resolvers.devices.is_empty());
        let device = r.k.add_link(&interface, false);
        let link = r.k.link(device).unwrap().clone();
        r.handle(
            super::super::Source::Monitor,
            crate::kernel::Notice::LinkNew(link),
        );
        assert!(r.resolvers.retries.is_empty());
        assert_eq!(
            r.resolvers.lookups,
            r.resolvers
                .watches
                .iter()
                .map(|(id, watch)| (watch.id, *id))
                .collect()
        );
        assert_eq!(r.resolvers.devices[&device].len(), 300);
        assert!(
            r.resolvers
                .watches
                .values()
                .all(|watch| watch.started.is_some())
        );
        r.poll_answers();
        for (id, tunnel) in &r.tunnels {
            assert!(
                !r.report
                    .is_open(&report::tunnel(&tunnel.name, *id), "worker")
            );
        }
        r.reconcile(Config::new());
        r.k.tick();
        r.tick();
        assert!(r.resolvers.watches.is_empty() && r.resolvers.retries.is_empty());
        assert!(r.resolvers.lookups.is_empty());
        assert!(r.resolvers.names.is_empty() && r.resolvers.devices.is_empty());
        assert_eq!(r.resolvers.next_deadline(), None);
        println!(
            "RESOLVER_HISTORY epoch={epoch} removed=300 watches=0 lookups=0 retries=0 names=0 devices=0"
        );
    }
}

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
            Dns::new("2001:db8::53", "dns-router"),
            Dns::new("2001:db8::54", "dns-router"),
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

/// spec: V3, V4, V7, V15, G23, M16
#[test]
fn aliases_share_only_their_current_host_and_resolver_job() {
    let mut resolve = IphostResolve::default();
    let system = ResolverSpec::System;
    let configured = ResolverSpec::Static {
        servers: vec!["192.0.2.53:53".parse().unwrap()],
        bind: None,
    };
    for (id, host, resolver) in [
        (1, "192.0.2.1", system.clone()),
        (2, "192.0.2.1", system.clone()),
        (3, "192.0.2.2", system.clone()),
        (4, "192.0.2.1", configured.clone()),
    ] {
        resolve
            .watch(Lookup::new(id, host.into(), resolver))
            .unwrap();
    }
    let first = resolve.job(&resolve.watches[&1]).id;
    assert_eq!(resolve.job(&resolve.watches[&2]).id, first);
    assert_eq!(resolve.job(&resolve.watches[&1]).users, 2);
    assert_ne!(resolve.job(&resolve.watches[&3]).id, first);
    assert_ne!(resolve.job(&resolve.watches[&4]).id, first);
    assert_eq!(resolve.resolvers[&system].full_jobs, 2);
    let mut answers = BTreeMap::new();
    until(|| {
        answers.extend(resolve.poll());
        answers.len() == 4
    });
    for (id, address) in [
        (1, "192.0.2.1"),
        (2, "192.0.2.1"),
        (3, "192.0.2.2"),
        (4, "192.0.2.1"),
    ] {
        assert_eq!(answers[&id], [address.parse::<IpAddr>().unwrap()]);
    }
    resolve
        .watch(Lookup::new(2, "192.0.2.2".into(), system.clone()))
        .unwrap();
    assert_eq!(resolve.job(&resolve.watches[&1]).users, 1);
    assert_eq!(resolve.job(&resolve.watches[&2]).users, 2);
    resolve.unwatch(1);
    resolve.unwatch(1);
    assert_eq!(resolve.resolvers[&system].jobs.len(), 1);
    assert_eq!(resolve.resolvers[&system].full_jobs, 1);
    assert_eq!(
        resolve
            .watch(Lookup::new(4, "bad host".into(), configured.clone()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(!resolve.resolvers.contains_key(&configured));
    assert!(!resolve.retry_discovery(4));
    assert!(!resolve.waiting(4));
    resolve.unwatch(2);
    assert_eq!(resolve.job(&resolve.watches[&3]).users, 1);
    resolve.unwatch(3);
    resolve.unwatch(99);
    assert!(resolve.resolvers.is_empty());
    assert!(resolve.watches.is_empty());
    assert!(resolve.workers.is_none());
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

/// spec: V14, V4, V6, K13, K38
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

/// spec: V14, V4, V7, V15, G23, M16
#[test]
#[ignore = "isolated namespace with CAP_NET_ADMIN and CAP_NET_RAW"]
fn shared_partial_discovery_retries_replace_the_actual_lookup_snapshot() {
    let (sender, destination, primary, fallback, dhcp) = fixture();
    let occupied = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    occupied.bind_device(Some(b"dns-host")).unwrap();
    occupied
        .bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 546, 0, 0).into())
        .unwrap();
    let spec = ResolverSpec::Ipv6 {
        interface: "dns-host".into(),
        client_id: ClientId::None,
    };
    let lookup = |id| Lookup::new(id, "controlled.example".into(), spec.clone());
    let mut resolve = IphostResolve::default();
    resolve.watch(lookup(1)).unwrap();
    resolve.watch(lookup(2)).unwrap();
    assert!(resolve.retry_discovery(1) && resolve.retry_discovery(2));
    until(|| {
        advertise(
            &sender,
            destination,
            &[("2001:db8::54".parse().unwrap(), 300)],
        );
        resolve.poll().iter().any(|(_, answer)| answer.len() == 2)
    });
    assert!(fallback.calls.load(Ordering::SeqCst) > 0);
    assert_eq!(primary.calls.load(Ordering::SeqCst), 0);
    drop(occupied);
    resolve.watch(lookup(1)).unwrap();
    let mut request = [0; 1500];
    let (len, peer) = dhcp.recv_from(&mut request).unwrap();
    assert!(len >= 4 && request[0] == 11);
    let mut reply = vec![7, request[1], request[2], request[3], 0, 23, 0, 16];
    reply.extend("2001:db8::53".parse::<Ipv6Addr>().unwrap().octets());
    dhcp.send_to(&reply, peer).unwrap();
    resolve.watch(lookup(2)).unwrap();
    assert!(!resolve.retry_discovery(1) && !resolve.retry_discovery(2));
    let deadline = Instant::now() + Duration::from_secs(35);
    while primary.calls.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(
        primary.calls.load(Ordering::SeqCst) > 0,
        "completed discovery retries still use an RA-only lookup snapshot"
    );
    until(|| {
        let answers = resolve.poll();
        answers.len() == 2 && answers.iter().all(|(_, answer)| answer.len() == 2)
    });
    resolve.unwatch(1);
    resolve.unwatch(2);
    assert!(resolve.watches.is_empty() && resolve.workers.is_none());
    assert!(resolve.resolvers.is_empty());
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
    let iphost::Resolver::Ra(config) = &resolve.job(&resolve.watches[&1]).resolver else {
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
    assert!(resolve.resolvers.is_empty());
    assert!(resolve.workers.is_none());
    until(|| threads() <= baseline.0 && descriptors() <= baseline.1);
}

#[cfg(feature = "fake-kernel")]
mod validation {
    use super::*;
    use crate::config::NameServer;
    use crate::kernel::fake::FakeKernel;
    use nix::errno::Errno;

    fn server(zone: Option<L2tpIfName>, bind: Option<L2tpIfName>) -> ResolverConfig {
        ResolverConfig::with_addresses(
            vec![NameServer::new("fe80::53".parse().unwrap(), zone, 5353).unwrap()],
            bind,
        )
        .unwrap()
    }

    /// spec: V9, V12, C16
    #[test]
    fn dependency_and_spec_checks_refuse_missing_vrf_and_failed_link_queries() {
        let mut k = FakeKernel::new(42);
        k.add_link("red", true);
        let red = L2tpIfName::new(b"red").unwrap();
        let missing = L2tpIfName::new(b"absent").unwrap();
        let mut r = Reconciler::new(k, Box::new(IphostResolve::default()));
        r.ensure_lookup(u32::MAX);
        assert!(r.resolvers.watches.is_empty() && r.resolvers.lookups.is_empty());
        for (bind, text) in [
            (red, "red is a VRF, not a link"),
            (missing, "absent does not exist"),
        ] {
            let config = server(None, Some(bind));
            assert_eq!(r.resolver_dependencies(&config).unwrap_err(), text);
            assert_eq!(r.resolver_spec(&config).unwrap_err(), text);
        }
        let link = L2tpIfName::new(b"dns").unwrap();
        let index = r.k.add_link("dns", false);
        let config = server(None, Some(link));
        for dependencies in [false, true] {
            r.k.fail_next("link", Errno::EIO);
            let error = if dependencies {
                r.resolver_dependencies(&config).unwrap_err()
            } else {
                r.resolver_spec(&config).unwrap_err()
            };
            assert!(error.starts_with("EIO: "), "{error}");
        }
        assert_eq!(r.resolver_dependencies(&config).unwrap(), [(link, index)]);
        let invalid = L2tpIfName::new(b"dns\xff").unwrap();
        let config = server(None, Some(invalid));
        let error = r.resolver_spec(&config).unwrap_err();
        assert!(error.contains("not UTF-8"), "{error}");
    }

    /// spec: V9, C16, K14
    #[test]
    fn link_local_servers_use_only_the_matching_live_link_as_their_scope() {
        let mut k = FakeKernel::new(42);
        let index = k.add_link("dns", false);
        k.add_link("other", false);
        let link = L2tpIfName::new(b"dns").unwrap();
        let other = L2tpIfName::new(b"other").unwrap();
        let mut r = Reconciler::new(k, Box::new(IphostResolve::default()));
        for (zone, bind) in [
            (None, Some(link)),
            (Some(link), None),
            (Some(link), Some(link)),
        ] {
            let config = server(zone, bind);
            assert_eq!(r.resolver_dependencies(&config).unwrap(), [(link, index)]);
            assert_eq!(
                r.resolver_spec(&config).unwrap(),
                ResolverSpec::Static {
                    servers: vec![SocketAddr::V6(SocketAddrV6::new(
                        "fe80::53".parse().unwrap(),
                        5353,
                        0,
                        index,
                    ))],
                    bind: bind.map(|name| name.to_str().unwrap().to_owned()),
                }
            );
        }
        r.k.remove_link(index);
        let replacement = r.k.add_link("dns", false);
        assert_ne!(replacement, index);
        let config = server(Some(link), None);
        assert_eq!(
            r.resolver_dependencies(&config).unwrap(),
            [(link, replacement)]
        );
        assert!(matches!(
            r.resolver_spec(&config).unwrap(),
            ResolverSpec::Static { servers, .. }
                if matches!(servers.as_slice(), [SocketAddr::V6(server)] if server.scope_id() == replacement)
        ));
        r.k.fail_next("link", Errno::EIO);
        assert!(r.resolver_spec(&config).unwrap_err().starts_with("EIO: "));
        let config = server(Some(other), Some(link));
        assert_eq!(
            r.resolver_spec(&config).unwrap_err(),
            "a server's zone is not its bind link",
        );
        let config = server(Some(L2tpIfName::new(b"gone").unwrap()), None);
        assert_eq!(r.resolver_spec(&config).unwrap_err(), "gone does not exist");
        r.k.add_link("red", true);
        let config = server(Some(L2tpIfName::new(b"red").unwrap()), None);
        assert_eq!(
            r.resolver_spec(&config).unwrap_err(),
            "red is a VRF, not a link"
        );
    }

    /// spec: V9, C16
    #[test]
    fn global_static_servers_preserve_order_ports_and_zero_ipv6_scope() {
        let mut k = FakeKernel::new(42);
        let index = k.add_link("dns", false);
        let link = L2tpIfName::new(b"dns").unwrap();
        let mut r = Reconciler::new(k, Box::new(IphostResolve::default()));
        for bind in [None, Some(link)] {
            let servers = [
                ("2001:db8::53".parse().unwrap(), 5353),
                ("192.0.2.53".parse().unwrap(), 53),
            ];
            let config = ResolverConfig::with_addresses(
                servers
                    .iter()
                    .map(|&(addr, port)| NameServer::new(addr, None, port).unwrap())
                    .collect(),
                bind,
            )
            .unwrap();
            assert_eq!(
                r.resolver_dependencies(&config).unwrap(),
                bind.map(|name| vec![(name, index)]).unwrap_or_default()
            );
            assert_eq!(
                r.resolver_spec(&config).unwrap(),
                ResolverSpec::Static {
                    servers: servers
                        .into_iter()
                        .map(|(addr, port)| SocketAddr::new(addr, port))
                        .collect(),
                    bind: bind.map(|name| name.to_str().unwrap().to_owned()),
                }
            );
        }
    }

    /// spec: V10, V12, V14, C16
    #[test]
    fn discovery_identities_preserve_explicit_values_and_handle_missing_or_refused_mac() {
        let mut k = FakeKernel::new(42);
        let index = k.add_link("dns", false);
        let link = L2tpIfName::new(b"dns").unwrap();
        let mac = k.ether_addr(index).unwrap().unwrap().octets();
        let mut r = Reconciler::new(k, Box::new(IphostResolve::default()));
        for method in [Method::Dhcpv6, Method::Ipv6] {
            for (identity, client_id) in [
                (None, ClientId::DuidLl(mac)),
                (Some(Dhcpv6Identity::Anonymous), ClientId::None),
                (Some(Dhcpv6Identity::Random), ClientId::RandomDuidLl),
                (
                    Some(Dhcpv6Identity::Duid(vec![0, 4, 9])),
                    ClientId::Raw(vec![0, 4, 9]),
                ),
            ] {
                let config = ResolverConfig::with_method(method, link, identity).unwrap();
                let expected = if method == Method::Dhcpv6 {
                    ResolverSpec::Dhcpv6 {
                        interface: "dns".into(),
                        client_id,
                    }
                } else {
                    ResolverSpec::Ipv6 {
                        interface: "dns".into(),
                        client_id,
                    }
                };
                assert_eq!(r.resolver_spec(&config).unwrap(), expected);
            }
            let config = ResolverConfig::with_method(method, link, None).unwrap();
            for refused in [false, true] {
                if refused {
                    r.k.fail_after("link", 1, Errno::EIO);
                } else {
                    r.k.clear_link_hwaddr(index);
                }
                if method == Method::Dhcpv6 {
                    assert_eq!(
                        r.resolver_spec(&config).unwrap_err(),
                        "dns has no Ethernet address for a DUID-LL",
                    );
                } else {
                    assert_eq!(
                        r.resolver_spec(&config).unwrap(),
                        ResolverSpec::Ra {
                            interface: "dns".into()
                        },
                    );
                }
                r.k.set_link_hwaddr(index, crate::config::HwAddr::new(mac).unwrap());
                assert!(
                    r.resolver_spec(&config).is_ok(),
                    "retry must recover the MAC"
                );
            }
        }
        let config = ResolverConfig::with_method(Method::Ra, link, None).unwrap();
        r.k.fail_after("link", 1, Errno::EIO);
        assert_eq!(
            r.resolver_spec(&config).unwrap(),
            ResolverSpec::Ra {
                interface: "dns".into()
            },
        );
        assert_eq!(
            r.k.ether_addr(index).unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
    }
}

/// spec: V9, V12, K13, K38
#[test]
#[ignore = "isolated namespace with CAP_NET_ADMIN and CAP_NET_RAW"]
fn released_adapter_preserves_client_identifiers_and_static_device_binding() {
    for identity in [
        ClientId::None,
        ClientId::DuidLl([2, 0, 0x5e, 0, 0x53, 1]),
        ClientId::RandomDuidLl,
        ClientId::Raw(vec![
            0, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        ]),
    ] {
        let (_sender, _destination, primary, _fallback, dhcp) = fixture();
        let resolver = IphostResolve::default()
            .resolver(&ResolverSpec::Dhcpv6 {
                interface: "dns-host".into(),
                client_id: identity.clone(),
            })
            .unwrap();
        let iphost::Resolver::Dhcpv6(config) = &resolver else {
            panic!("expected DHCPv6");
        };
        let duid = match &identity {
            ClientId::None => None,
            ClientId::DuidLl(mac) => Some([&[0, 3, 0, 1][..], mac].concat()),
            ClientId::Raw(bytes) => Some(bytes.clone()),
            ClientId::RandomDuidLl => {
                let iphost::ClientId::DuidLl(mac) = config.client_id() else {
                    panic!("random identity was not resolved");
                };
                assert_eq!(mac[0] & 3, 2, "locally administered unicast");
                Some([&[0, 3, 0, 1][..], mac].concat())
            }
        };
        let retained = config.client_id().clone();
        let mut transaction = None;
        let mut reply_peer = None;
        for _ in 0..2 {
            let mut packet = [0; 1500];
            let (len, peer) = dhcp.recv_from(&mut packet).unwrap();
            assert!(len >= 4 && packet[0] == 11);
            assert_eq!(peer.port(), 546);
            let xid = packet[1..4].to_vec();
            if let Some(previous) = transaction.replace(xid) {
                assert_eq!(&packet[1..4], previous, "retransmission transaction");
            }
            let mut options = &packet[4..len];
            let mut received = None;
            while !options.is_empty() {
                let header = options.get(..4).expect("complete option header");
                let code = u16::from_be_bytes([header[0], header[1]]);
                let size = usize::from(u16::from_be_bytes([header[2], header[3]]));
                let (body, remaining) = options[4..]
                    .split_at_checked(size)
                    .expect("complete option body");
                if code == 1 {
                    assert!(
                        received.replace(body.to_vec()).is_none(),
                        "duplicate client ID"
                    );
                }
                options = remaining;
            }
            assert_eq!(received, duid, "{identity:?}");
            assert_eq!(config.client_id(), &retained);
            reply_peer = Some(peer);
        }
        let xid = transaction.unwrap();
        let mut reply = vec![7, xid[0], xid[1], xid[2], 0, 23, 0, 16];
        let server = "2001:db8::53".parse::<Ipv6Addr>().unwrap();
        reply.extend(server.octets());
        if let Some(duid) = duid {
            reply.extend(1u16.to_be_bytes());
            reply.extend((duid.len() as u16).to_be_bytes());
            reply.extend(duid);
        }
        dhcp.send_to(&reply, reply_peer.unwrap()).unwrap();
        until(|| config.nameservers() == [server]);

        let resolver = IphostResolve::default()
            .resolver(&ResolverSpec::Static {
                servers: vec![SocketAddrV6::new(server, 53, 0, 0).into()],
                bind: Some("dns-host".into()),
            })
            .unwrap();
        let iphost::Resolver::Static(bound) = &resolver else {
            panic!("expected static resolver");
        };
        assert_eq!(
            bound.bind_device(),
            Some(&iphost::BindDevice::Interface("dns-host".into()))
        );
        let before = primary.calls.load(Ordering::SeqCst);
        let answer = iphost::IpHostResolver::new_with_config(
            "controlled.example".parse().unwrap(),
            false,
            false,
        )
        .with_resolver(resolver)
        .resolve();
        assert_eq!(
            answer.into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "192.0.2.9".parse::<IpAddr>().unwrap(),
                "2001:db8::9".parse::<IpAddr>().unwrap(),
            ])
        );
        assert!(primary.calls.load(Ordering::SeqCst) >= before + 2);
    }
}

/// spec: V12, K13, K38
#[test]
#[ignore = "isolated namespace with CAP_NET_ADMIN and CAP_NET_RAW"]
fn anonymous_adapter_rejects_a_reply_carrying_another_client_identifier() {
    let (_sender, _destination, _primary, _fallback, dhcp) = fixture();
    let resolver = IphostResolve::default()
        .resolver(&ResolverSpec::Dhcpv6 {
            interface: "dns-host".into(),
            client_id: ClientId::None,
        })
        .unwrap();
    let iphost::Resolver::Dhcpv6(config) = &resolver else {
        panic!("expected DHCPv6");
    };
    let mut request = [0; 1500];
    let (len, peer) = dhcp.recv_from(&mut request).unwrap();
    assert!(len >= 4 && request[0] == 11);
    let reply = |server: Ipv6Addr, include_client: bool| {
        let identifier = [0, 3, 0, 1, 2, 0, 0x5e, 0, 0x53, 7];
        let mut reply = vec![7, request[1], request[2], request[3], 0, 2, 0, 10];
        reply.extend(identifier);
        if include_client {
            reply.extend([0, 1, 0, 10]);
            reply.extend(identifier);
        }
        reply.extend([0, 23, 0, 16]);
        reply.extend(server.octets());
        reply
    };
    let foreign = "2001:db8::53".parse().unwrap();
    let own = "2001:db8::54".parse().unwrap();
    dhcp.send_to(&reply(foreign, true), peer).unwrap();
    dhcp.send_to(&reply(own, false), peer).unwrap();
    until(|| !config.nameservers().is_empty());
    assert_eq!(
        config.nameservers(),
        [own],
        "anonymous client accepted a Reply containing a Client Identifier"
    );
}

/// spec: C7, L4, V9, G1
#[test]
#[cfg(feature = "fake-kernel")]
fn a_privately_malformed_unscoped_resolver_returns_the_defensive_error() {
    let malformed = crate::config::unscoped_resolver_for_test();
    let error = ResolverConfig::with_addresses(malformed.addresses().to_vec(), None).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("it needs a zone or bind_interface"),
        "{error}"
    );
    let mut r = Reconciler::new(
        crate::kernel::fake::FakeKernel::new(42),
        Box::new(IphostResolve::default()),
    );
    r.k.clear_ops();
    assert_eq!(
        r.resolver_spec(&malformed).unwrap_err(),
        "a link-local server has no scope"
    );
    assert!(r.k.ops().is_empty());
    assert!(!r.resolvers.any());
}
