//! The conformance suite and the method-level live tests on the real
//! kernel (docs/testing.md). Ignored: run them in an isolated network
//! namespace with CAP_NET_ADMIN, CAP_NET_RAW and the L2TP modules, as
//! tests/kernel/README.md shows.

#[path = "conformance.rs"]
mod conformance;

use std::net::IpAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Command;
use std::task::Poll;
use std::time::Duration;

use conformance::Fixture;
use nix::libc;
use rs_l2tpd::kernel::linux::LinuxKernel;
use rs_l2tpd::kernel::{
    Family, HwAddr, Kernel, L2tpIfName, Notice, Peer, Proof, SessionCreate, Subscription,
};

fn ip(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().expect("iproute2");
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// The index of a device, as iproute2 reports it.
fn index_of(name: &str) -> u32 {
    let line = ip(&["-o", "link", "show", "dev", name]);
    line.split(':').next().unwrap().trim().parse().unwrap()
}

/// The name of a device, as iproute2 reports it.
fn name_of(index: u32) -> String {
    ip(&["-o", "link", "show"])
        .lines()
        .find_map(|line| {
            let mut fields = line.split(": ");
            let found: u32 = fields.next()?.trim().parse().ok()?;
            let name = fields.next()?.split('@').next()?;
            (found == index).then(|| name.to_string())
        })
        .unwrap_or_else(|| panic!("no device {index}"))
}

fn name(text: &str) -> L2tpIfName {
    L2tpIfName::new(text.as_bytes()).unwrap()
}

fn errno<T: std::fmt::Debug>(result: std::io::Result<T>) -> i32 {
    result.unwrap_err().raw_os_error().unwrap()
}

struct LinuxFixture {
    kernel: LinuxKernel,
    runtime: tokio::runtime::Runtime,
    tables: u32,
}

impl LinuxFixture {
    /// A fixture in a network namespace of its own, which this thread, the
    /// `ip` commands it runs and the kernel's lifetime thread share.
    fn new() -> Self {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).expect("CAP_SYS_ADMIN");
        ip(&["link", "set", "lo", "up"]);
        LinuxFixture {
            kernel: LinuxKernel::new().unwrap(),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
            tables: 0,
        }
    }
}

impl Fixture for LinuxFixture {
    fn k(&mut self) -> &mut dyn Kernel {
        &mut self.kernel
    }
    fn add_link(&mut self, name: &str, vrf: bool) -> u32 {
        if vrf {
            self.tables += 1;
            let table = (1000 + self.tables).to_string();
            ip(&["link", "add", name, "type", "vrf", "table", &table]);
        } else {
            ip(&["link", "add", name, "type", "dummy"]);
        }
        index_of(name)
    }
    fn set_up(&mut self, index: u32, up: bool) {
        let state = if up { "up" } else { "down" };
        ip(&["link", "set", "dev", &name_of(index), state]);
    }
    fn set_master(&mut self, index: u32, master: u32) {
        ip(&[
            "link",
            "set",
            "dev",
            &name_of(index),
            "master",
            &name_of(master),
        ]);
    }
    fn add_addr(&mut self, index: u32, addr: IpAddr) {
        let dev = name_of(index);
        match addr {
            IpAddr::V4(_) => ip(&["addr", "add", &format!("{addr}/24"), "dev", &dev]),
            IpAddr::V6(_) => ip(&["addr", "add", &format!("{addr}/64"), "dev", &dev, "nodad"]),
        };
    }
    fn rename_link(&mut self, index: u32, name: &str) {
        ip(&["link", "set", "dev", &name_of(index), "name", name]);
    }
    fn settle(&mut self) {
        std::thread::yield_now();
    }
    fn net_raw(&self) -> bool {
        true
    }
    fn send_frame(&mut self, index: u32) {
        let before = self.tx_drops(index);
        std::net::UdpSocket::bind("192.0.2.1:0")
            .unwrap()
            .send_to(b"drop", "192.0.2.2:9")
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while self.tx_drops(index) <= before {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
    }
    fn tx_drops(&mut self, index: u32) -> u64 {
        packets(&name_of(index), "TX:", 3)
    }
    fn wait_notice(
        &mut self,
        sub: &mut dyn Subscription,
        want: &mut dyn FnMut(&Notice) -> bool,
    ) -> Option<Notice> {
        let wait = std::future::poll_fn(|cx| {
            loop {
                match sub.poll_notice(cx) {
                    Poll::Ready(notice) if want(&notice) => return Poll::Ready(notice),
                    Poll::Ready(_) => {}
                    Poll::Pending => return Poll::Pending,
                }
            }
        });
        self.runtime
            .block_on(async { tokio::time::timeout(Duration::from_secs(2), wait).await })
            .ok()
    }
}

/// spec: K16, K17, K18, K19, K20, K22, K24, K26, K27, K28, K31, K34, K41, S9, S19, E5, T7
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN, CAP_NET_RAW and L2TP modules"]
fn conformance_on_the_linux_kernel() {
    let mut failed = Vec::new();
    for (case, run) in conformance::CASES {
        eprintln!("case {case}");
        let result = catch_unwind(AssertUnwindSafe(|| run(&mut LinuxFixture::new())));
        if result.is_err() {
            failed.push(*case);
        }
    }
    assert!(failed.is_empty(), "failed on the real kernel: {failed:?}");
}

fn create(tunnel_id: u32, session_id: u32, ifname: &str) -> SessionCreate {
    SessionCreate::new(
        tunnel_id,
        session_id,
        session_id + 1,
        None,
        None,
        name(ifname),
    )
}

fn library_config(id: u32) -> rs_l2tpd::config::Config {
    use rs_l2tpd::config::{Config, HostConfig, SessionConfig, TunnelConfig};
    let mut config = Config::new();
    config.set_host(HostConfig::new().with_fix_bindv6only(false));
    config
        .insert_tunnel(
            "wan",
            TunnelConfig::builder(id)
                .ip_version(Family::V6)
                .build()
                .unwrap(),
        )
        .unwrap();
    config
        .insert_session(
            "lan",
            SessionConfig::builder("wan", id + 100, name("rslive0"))
                .build()
                .unwrap(),
        )
        .unwrap();
    config
}

/// spec: R37, G14, L5, L8, L9
#[test]
#[ignore = "isolated privileged container; public constructors use the real kernel"]
fn library_constructors_reject_missing_tokio_and_preserve_adopted_descriptors() {
    use rs_l2tpd::{AdoptedSocket, Error, Runtime, blocking, service};
    let _fixture = LinuxFixture::new();
    assert!(tokio::runtime::Handle::try_current().is_err());
    let (fd, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let Err((error, returned)) = Runtime::new(vec![AdoptedSocket::new("t10", fd.into())]) else {
        panic!("Runtime needs a Tokio context");
    };
    assert!(matches!(error, Error::Other(_)), "{error}");
    assert_eq!(returned[0].name(), "t10");
    assert!(returned[0].fd().try_clone().is_ok());
    let Err((error, returned)) = service::Service::new(rs_l2tpd::config::Config::new(), returned)
    else {
        panic!("Service needs a Tokio context");
    };
    assert!(matches!(error, Error::Other(_)), "{error}");
    assert_eq!(returned[0].name(), "t10");
    assert!(returned[0].fd().try_clone().is_ok());
    let mut blocking = blocking::Service::new(rs_l2tpd::config::Config::new(), vec![])
        .map_err(|(e, _)| e)
        .unwrap();
    assert!(blocking.converge().unwrap().is_empty());
    assert!(tokio::runtime::Handle::try_current().is_err());
    drop(blocking);
}

/// spec: R38, R3, G8, G14, L9
#[test]
#[ignore = "isolated privileged container; only this test thread drops CAP_NET_ADMIN"]
fn library_missing_net_admin_withholds_readiness_and_shutdown_still_succeeds() {
    let fixture = LinuxFixture::new();
    let mut observer_kernel = fixture.kernel;
    let (query, requested) = std::sync::mpsc::sync_channel(0);
    let observer = std::thread::spawn(move || {
        requested.recv().unwrap();
        observer_kernel.tunnel(10)
    });
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Caps {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let mut caps = [Caps::default(); 2];
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_capget, &mut header, caps.as_mut_ptr()) },
        0
    );
    assert_ne!(caps[0].effective & (1 << 12), 0);
    caps[0].effective &= !(1 << 12);
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_capset, &header, caps.as_ptr()) },
        0
    );
    let mut runtime = {
        let _entered = fixture.runtime.enter();
        rs_l2tpd::Runtime::new(vec![]).map_err(|(e, _)| e).unwrap()
    };
    assert!(!runtime.reconcile(library_config(10)));
    assert!(!runtime.ready());
    query.send(()).unwrap();
    assert!(observer.join().unwrap().unwrap().is_none());
    assert!(runtime.shutdown().unwrap());
}

/// spec: R40, G2, G9, G14, L9, L13
#[test]
#[ignore = "isolated privileged container; real socket cleanup and foreign ownership"]
fn library_runtime_drop_closes_active_and_retiring_tunnels_without_touching_foreign_ones() {
    for retiring in [false, true] {
        let mut fixture = LinuxFixture::new();
        let foreign = fixture
            .kernel
            .create_socket(Family::V6, 9000, 9001)
            .unwrap();
        fixture.kernel.register_tunnel(foreign, 9000, 9001).unwrap();
        fixture
            .kernel
            .create_session(&create(9000, 9002, "foreign"))
            .unwrap();
        let foreign_index = index_of("foreign");
        let mut runtime = {
            let _entered = fixture.runtime.enter();
            rs_l2tpd::Runtime::new(vec![]).map_err(|(e, _)| e).unwrap()
        };
        if retiring {
            runtime.set_store_capacity(1);
        }
        assert!(runtime.reconcile(library_config(10)));
        assert!(fixture.kernel.session(10, 110).unwrap().is_some());
        if retiring {
            runtime.reconcile(rs_l2tpd::config::Config::new());
            assert!(fixture.kernel.tunnel(10).unwrap().is_some());
        }
        drop(runtime);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while fixture.kernel.tunnel(10).unwrap().is_some() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(fixture.kernel.session(10, 110).unwrap().is_none());
        assert!(fixture.kernel.tunnel(9000).unwrap().is_some());
        assert!(fixture.kernel.session(9000, 9002).unwrap().is_some());
        assert_eq!(index_of("foreign"), foreign_index);
        fixture.kernel.close(foreign);
    }
}

/// spec: T1, T3, T4, T6, T26, T28, K2, K4, K11, K23, K28, K34
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN, CAP_NET_RAW and L2TP modules"]
fn sockets_bind_connect_and_report_their_source() {
    let mut f = LinuxFixture::new();
    let dev = f.add_link("live-src", false);
    f.set_up(dev, true);
    let v6 = f.k().create_socket(Family::V6, 9301, 9302).unwrap();
    assert!(!f.k().only_v6(v6).unwrap());
    assert!(!f.k().scratch_only_v6().unwrap());
    let v4 = f.k().create_socket(Family::V4, 9303, 9304).unwrap();
    f.k().bind_index(v4, dev).unwrap();
    let peer = Peer::new("198.51.100.1".parse().unwrap(), None);
    // An ordinary bound device without an address: on-link, no source.
    assert_eq!(
        f.k().connect(v4, &peer).unwrap(),
        "0.0.0.0".parse::<IpAddr>().unwrap()
    );
    let v6peer = Peer::new("2001:db8:93::2".parse().unwrap(), None);
    assert_eq!(errno(f.k().connect(v4, &v6peer)), libc::EAFNOSUPPORT);
    f.add_addr(dev, "198.51.100.9".parse().unwrap());
    f.k().disconnect(v4).unwrap();
    f.k().bind_index(v4, dev).unwrap();
    assert_eq!(
        f.k().connect(v4, &peer).unwrap(),
        "198.51.100.9".parse::<IpAddr>().unwrap()
    );
    f.k().close(v4);
    f.k().close(v6);
}

/// spec: K17, K19, K25, K37, P14, S28
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN, CAP_NET_RAW and L2TP modules"]
fn a_handed_over_socket_keeps_its_tunnel() {
    let mut f = LinuxFixture::new();
    for (family, id) in [(Family::V6, 9311), (Family::V4, 9313)] {
        let socket = f.k().create_socket(family, id, id + 1).unwrap();
        f.k().register_tunnel(socket, id, id + 1).unwrap();
        let info = f.k().tunnel(id).unwrap().unwrap();
        assert_eq!((info.tunnel_id(), info.peer_tunnel_id()), (id, id + 1));
        let fd = f.k().clone_fd(socket).unwrap();
        f.k().close(socket);
        let adopted = f.k().adopt(fd).unwrap();
        assert_eq!(adopted.family(), family);
        assert_eq!(
            (adopted.tunnel_id(), adopted.peer_tunnel_id()),
            (id, id + 1)
        );
        f.settle();
        assert!(f.k().tunnel(id).unwrap().is_some(), "K37");
        f.k().close(adopted.socket());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let gone = loop {
            f.settle();
            if f.k().tunnel(id).unwrap().is_none() {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
        };
        assert!(gone, "K17");
    }
}

/// spec: S3, S4, S8, S22, K16, K19, K20, K35
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN, CAP_NET_RAW and L2TP modules"]
fn sessions_are_captured_scanned_and_deleted() {
    let mut f = LinuxFixture::new();
    let socket = f.k().create_socket(Family::V6, 9321, 9321).unwrap();
    f.k().register_tunnel(socket, 9321, 9321).unwrap();
    let mut first = create(9321, 93211, "live-sa");
    first = first.with_cookie(Some(rs_l2tpd::kernel::Cookie::new(&[1, 2, 3, 4]).unwrap()));
    let registration = f.k().create_session(&first).unwrap();
    assert_eq!(registration.index(), index_of("live-sa"));
    let set = HwAddr::new([0x02, 0, 0x5e, 0, 0x53, 0x93]).unwrap();
    f.k().set_hwaddr(registration.index(), set).unwrap();
    assert_eq!(f.k().ether_addr(registration.index()).unwrap(), Some(set));
    f.set_up(registration.index(), true);
    let other = HwAddr::new([0x02, 0, 0x5e, 0, 0x53, 0x94]).unwrap();
    assert_eq!(
        errno(f.k().set_hwaddr(registration.index(), other)),
        libc::EBUSY,
        "K31"
    );
    // An unchanged address is not a change (net/core/dev.c:9035-9039).
    f.k().set_hwaddr(registration.index(), set).unwrap();
    let again = f.k().create_session(&create(9321, 93212, "live-sa"));
    assert!(matches!(errno(again), libc::EEXIST | libc::ENFILE), "K20");
    let second = f
        .k()
        .create_session(&create(9321, 93213, "live-sb"))
        .unwrap();
    assert_ne!(second.incarnation(), registration.incarnation());
    let mut seen = Vec::new();
    f.k()
        .scan_sessions(Some(9321), &mut |s| seen.push(s.clone()))
        .unwrap();
    seen.sort_by_key(|s| s.session_id());
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].ifname(), Some(name("live-sa")));
    assert_eq!(seen[0].peer_session_id(), 93212);
    assert_eq!(seen[0].cookie(), first.cookie().into());
    assert_eq!(seen[1].cookie(), None.into());
    let mut all = 0;
    f.k().scan_sessions(None, &mut |_| all += 1).unwrap();
    assert!(all >= 2);
    f.k().delete_session_by_name(&name("live-sb")).unwrap();
    f.k().delete_session(9321, 93211).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let gone = loop {
        f.settle();
        if f.k().session(9321, 93211).unwrap().is_none()
            && f.k().session(9321, 93213).unwrap().is_none()
        {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
    };
    assert!(gone);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while f.k().prove(&registration) != Proof::Removed || f.k().prove(&second) != Proof::Removed {
        assert!(
            std::time::Instant::now() < deadline,
            "session absence and device removal are separate observations"
        );
        std::thread::yield_now();
    }
    f.k().release(&registration);
    assert_eq!(f.k().prove(&registration), Proof::Lost);
    assert_eq!(errno(f.k().delete_session(9321, 93211)), libc::ENODEV);
    f.k().close(socket);
}

/// spec: A5, K9, K31, K32, V12, E20
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN, CAP_NET_RAW and L2TP modules"]
fn links_are_found_by_name_and_dumped() {
    let mut f = LinuxFixture::new();
    let vrf = f.add_link("live-vrf", true);
    let dummy = f.add_link("live-dummy", false);
    f.set_master(dummy, vrf);
    f.set_up(dummy, true);
    f.add_addr(dummy, "203.0.113.5".parse().unwrap());
    let link = f.k().link_by_name(&name("live-vrf")).unwrap().unwrap();
    assert_eq!((link.index(), link.vrf(), link.up()), (vrf, true, false));
    let link = f.k().link_by_name(&name("live-dummy")).unwrap().unwrap();
    assert_eq!(
        (link.index(), link.vrf(), link.up(), link.master()),
        (dummy, false, true, Some(vrf))
    );
    assert!(f.k().link_by_name(&name("live-none")).unwrap().is_none());
    assert!(f.k().ether_addr(dummy).unwrap().is_some());
    assert_eq!(f.k().ether_addr(index_of("lo")).unwrap(), None);
    assert_eq!(errno(f.k().rename(dummy, &name("lo"))), libc::EEXIST);
    f.k().rename(dummy, &name("live-dummy2")).unwrap();
    assert_eq!(name_of(dummy), "live-dummy2");
    let links = f.k().dump_links().unwrap();
    assert!(
        links
            .iter()
            .any(|l| l.index() == dummy && l.name() == name("live-dummy2"))
    );
    assert!(links.iter().any(|l| l.index() == vrf && l.vrf()));
    let addrs = f.k().dump_addrs().unwrap();
    assert!(
        addrs
            .iter()
            .any(|a| a.index() == dummy && a.addr() == "203.0.113.5".parse::<IpAddr>().unwrap())
    );
    assert!(
        addrs
            .iter()
            .any(|a| a.addr() == "127.0.0.1".parse::<IpAddr>().unwrap())
    );
}

/// spec: A5, E5, E6, E7, E22, K7, K10
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN, CAP_NET_RAW and L2TP modules"]
fn the_monitor_reports_removals() {
    let mut f = LinuxFixture::new();
    let mut monitor = f.k().monitor().unwrap();
    let index = f.add_link("live-mon", false);
    f.add_addr(index, "2001:db8:94::1".parse().unwrap());
    let added = f.wait_notice(
        &mut *monitor,
        &mut |n| matches!(n, Notice::AddrNew(a) if a.index() == index && a.addr().is_ipv6()),
    );
    assert!(added.is_some());
    ip(&["addr", "del", "2001:db8:94::1/64", "dev", "live-mon"]);
    let removed = f.wait_notice(
        &mut *monitor,
        &mut |n| matches!(n, Notice::AddrDel(a) if a.index() == index),
    );
    assert!(removed.is_some());
    ip(&["link", "del", "live-mon"]);
    let gone = f.wait_notice(
        &mut *monitor,
        &mut |n| matches!(n, Notice::LinkDel(l) if l.index() == index && l.name() == name("live-mon")),
    );
    assert!(gone.is_some());
}

/// spec: K17, K41, E27
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN, CAP_NET_RAW and L2TP modules"]
fn a_closed_socket_is_not_announced() {
    let mut f = LinuxFixture::new();
    let mut events = f.k().l2tp_events().unwrap();
    let socket = f.k().create_socket(Family::V6, 9331, 9331).unwrap();
    f.k().register_tunnel(socket, 9331, 9331).unwrap();
    f.k()
        .create_session(&create(9331, 93311, "live-ann"))
        .unwrap();
    f.k().close(socket);
    let seen = f.wait_notice(&mut *events, &mut |n| {
        matches!(
            n,
            Notice::TunnelDeleted { tunnel_id: 9331 }
                | Notice::SessionDeleted {
                    tunnel_id: 9331,
                    ..
                }
        )
    });
    assert_eq!(seen, None);
}

/// spec: K42, M18, S9, S19, S23, S24, R11, R31, A16
#[test]
#[ignore = "isolated network namespaces with CAP_NET_ADMIN and L2TP modules"]
fn a_reused_index_and_creation_name_never_revive_an_old_registration() {
    let mut f = LinuxFixture::new();
    let socket = f.k().create_socket(Family::V6, 9341, 9342).unwrap();
    f.k().register_tunnel(socket, 9341, 9342).unwrap();
    let original = f
        .k()
        .create_session(&create(9341, 93411, "reuse-stage"))
        .unwrap();
    assert_eq!(f.k().prove(&original), Proof::Proved);
    let (ready, namespace) = std::sync::mpsc::channel();
    let (finish, finished) = std::sync::mpsc::channel();
    let child = std::thread::spawn(move || {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        ready.send(nix::unistd::gettid().as_raw()).unwrap();
        finished.recv_timeout(Duration::from_secs(10)).unwrap();
    });
    let tid = namespace.recv_timeout(Duration::from_secs(5)).unwrap();
    ip(&[
        "link",
        "set",
        "dev",
        "reuse-stage",
        "netns",
        &tid.to_string(),
    ]);
    ip(&[
        "link",
        "add",
        "name",
        "reuse-stage",
        "index",
        &original.index().to_string(),
        "type",
        "dummy",
    ]);
    assert_eq!(index_of("reuse-stage"), original.index());
    assert_eq!(f.k().prove(&original), Proof::Removed);
    assert!(
        f.k().session(9341, 93411).unwrap().is_some(),
        "moved, not deleted"
    );
    let other = f
        .k()
        .create_session(&create(9341, 93412, "reuse-other"))
        .unwrap();
    assert_eq!(other.generation(), original.generation());
    assert_ne!(other.incarnation(), original.incarnation());
    assert_eq!(f.k().prove(&other), Proof::Proved);
    assert_eq!(f.k().prove(&original), Proof::Removed);
    finish.send(()).unwrap();
    child.join().unwrap();
    f.k().close(socket);
}

/// spec: K23, T26, L12
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN and L2TP modules"]
fn a_tunable_write_changes_only_fresh_sockets() {
    let mut f = LinuxFixture::new();
    std::fs::write("/proc/sys/net/ipv6/bindv6only", "1").unwrap();
    let old = f.k().create_socket(Family::V6, 9351, 9352).unwrap();
    assert!(f.k().only_v6(old).unwrap());
    std::fs::write("/proc/sys/net/ipv6/bindv6only", "0").unwrap();
    assert!(f.k().only_v6(old).unwrap());
    let new = f.k().create_socket(Family::V6, 9353, 9354).unwrap();
    assert!(!f.k().only_v6(new).unwrap());
    f.k().close(old);
    f.k().close(new);
}

fn packets(device: &str, direction: &str, field: usize) -> u64 {
    ip(&["-s", "link", "show", "dev", device])
        .lines()
        .skip_while(|line| !line.trim_start().starts_with(direction))
        .nth(1)
        .unwrap()
        .split_whitespace()
        .nth(field)
        .unwrap()
        .parse()
        .unwrap()
}

/// spec: K5, K15, S14, T1, R15, R24, R25
#[test]
#[ignore = "isolated namespace with CAP_NET_ADMIN, CAP_NET_RAW and L2TP modules"]
fn disconnected_sessions_drop_outbound_but_receive_only_matching_cookies() {
    let mut f = LinuxFixture::new();
    let socket = f.k().create_socket(Family::V6, 9371, 9372).unwrap();
    f.k().register_tunnel(socket, 9371, 9372).unwrap();
    let mut session = create(9371, 93711, "frames");
    session = session.with_peer_cookie(Some(rs_l2tpd::kernel::Cookie::new(&[1, 2, 3, 4]).unwrap()));
    f.k().create_session(&session).unwrap();
    ip(&["link", "set", "dev", "frames", "addrgenmode", "none"]);
    ip(&["link", "set", "dev", "frames", "up"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "frames"]);
    let before = packets("frames", "TX:", 3);
    std::net::UdpSocket::bind("192.0.2.1:0")
        .unwrap()
        .send_to(b"drop", "192.0.2.2:9")
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while packets("frames", "TX:", 3) <= before {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    let receiver_before = packets("frames", "RX:", 1);
    let raw = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(115)),
    )
    .unwrap();
    raw.bind(
        &"127.0.0.2:0"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
    )
    .unwrap();
    let mut ethernet = vec![0xff; 6];
    ethernet.extend([2, 0, 0x5e, 0, 0x53, 1, 0x88, 0xb5]);
    ethernet.resize(60, 0);
    for (id, cookie) in [
        (93711u32, &[][..]),
        (93711, &[9, 9, 9, 9][..]),
        (93712, &[1, 2, 3, 4][..]),
        (93711, &[1, 2, 3, 4][..]),
    ] {
        let mut payload = id.to_be_bytes().to_vec();
        payload.extend(cookie);
        payload.extend(&ethernet);
        raw.send_to(
            &payload,
            &"127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        )
        .unwrap();
        if id != 93711 || cookie != [1, 2, 3, 4] {
            let negative_window = std::time::Instant::now() + Duration::from_millis(100);
            while std::time::Instant::now() < negative_window {
                assert_eq!(packets("frames", "RX:", 1), receiver_before);
                std::thread::yield_now();
            }
        }
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while packets("frames", "RX:", 1) == receiver_before {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert_eq!(packets("frames", "RX:", 1), receiver_before + 1);
    f.k().close(socket);
}

/// spec: K25, T29, O9
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN and L2TP modules"]
fn the_kernel_keeps_the_previous_ipv6_peer_after_disconnect() {
    let mut f = LinuxFixture::new();
    let device = f.add_link("record", false);
    f.set_up(device, true);
    f.add_addr(device, "2001:db8:99::1".parse().unwrap());
    let socket = f.k().create_socket(Family::V6, 9391, 9392).unwrap();
    f.k().register_tunnel(socket, 9391, 9392).unwrap();
    f.k().bind_index(socket, device).unwrap();
    f.k()
        .connect(socket, &Peer::new("2001:db8:99::2".parse().unwrap(), None))
        .unwrap();
    f.k().disconnect(socket).unwrap();
    let record = ip(&["l2tp", "show", "tunnel"]);
    assert!(
        record
            .to_ascii_lowercase()
            .contains("from :: to 2001:db8:99::2"),
        "{record}"
    );
    f.k().close(socket);
}

/// spec: L5, L8, L9, P16
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN, CAP_NET_RAW and L2TP modules"]
fn services_converge_and_orderly_shutdown_on_linux() {
    use rs_l2tpd::config::{Config, SessionConfig, TunnelConfig};
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    let config = |id, interface| {
        let mut config = Config::new();
        config
            .insert_tunnel(
                "wan",
                TunnelConfig::builder(id)
                    .ip_version(Family::V6)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        config
            .insert_session(
                "lan",
                SessionConfig::builder("wan", id + 1, name(interface))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        config
    };
    let gone = || {
        assert!(ip(&["l2tp", "show", "tunnel"]).trim().is_empty());
        assert!(!ip(&["-o", "link", "show"]).contains("phase4-"));
    };
    let mut service = rs_l2tpd::blocking::Service::new(config(9490, "phase4-block"), vec![])
        .map_err(|(e, _)| e)
        .unwrap();
    service.converge().unwrap();
    assert!(ip(&["-o", "link", "show"]).contains("phase4-block"));
    drop(service);
    gone();

    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    engine.block_on(async {
        let mut service = rs_l2tpd::service::Service::new(config(9492, "phase4-tokio"), vec![])
            .map_err(|(e, _)| e)
            .unwrap();
        service.converge().await.unwrap();
        assert!(ip(&["-o", "link", "show"]).contains("phase4-tokio"));
        service.control().shutdown();
        service.run(Ok, |_| Ok(())).await.unwrap();
    });
    gone();

    engine.block_on(async {
        let mut runtime = rs_l2tpd::Runtime::new(vec![]).map_err(|(e, _)| e).unwrap();
        runtime.reconcile(config(9494, "phase4-runtime"));
        assert!(ip(&["-o", "link", "show"]).contains("phase4-runtime"));
        drop(runtime);
    });
    // Runtime drop closes the sockets without the orderly wait used by services.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !ip(&["l2tp", "show", "tunnel"]).trim().is_empty() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    gone();
}

/// spec: K9, K26, T21, T27, G1
#[test]
#[ignore = "isolated privileged container"]
fn completion_scoped_failure_lookup_and_random_refusal() {
    let mut f = LinuxFixture::new();
    let _old = f.add_link("scope-old", false); // Down: route lookup fails after scope binding.
    let socket = f
        .kernel
        .create_socket(Family::V6, 0x44001, 0x44002)
        .unwrap();
    f.kernel.register_tunnel(socket, 0x44001, 0x44002).unwrap();
    let peer = Peer::new("fe80::1".parse().unwrap(), Some(name("scope-old")));
    assert!(f.kernel.connect(socket, &peer).is_err());
    let next = f.add_link("scope-new", false);
    f.set_up(next, true);
    f.add_addr(next, "fe80::2".parse().unwrap());
    assert_eq!(
        f.kernel.link_by_index(next).unwrap().unwrap().name(),
        name("scope-new")
    );
    assert!(f.kernel.link_by_index(i32::MAX as u32).unwrap().is_none());
    assert_eq!(
        errno(f.kernel.connect(
            socket,
            &Peer::new("fe80::1".parse().unwrap(), Some(name("scope-new")))
        )),
        libc::EINVAL
    );
    f.kernel.disconnect(socket).unwrap();
    f.kernel
        .connect(
            socket,
            &Peer::new("fe80::1".parse().unwrap(), Some(name("scope-new"))),
        )
        .unwrap();
    f.kernel.close(socket);

    // Initialize getrandom's backend before filtering so this exercises its
    // fallible syscall path rather than its safe /dev/urandom fallback.
    f.kernel.random().unwrap();
    // kernel: kernel/seccomp.c seccomp_run_filters; drivers/char/random.c getrandom.
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
            jf: 1,
            k: libc::SYS_getrandom as u32,
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
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) },
        0
    );
    assert_eq!(errno(f.kernel.random()), libc::EPERM);
}

/// spec: S4, S7, S27, E3, E27, G22
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN and L2TP modules"]
fn event_recreation_uses_the_configured_creation_name_on_linux() {
    use rs_l2tpd::config::{Config, SessionConfig, TunnelConfig};
    use rs_l2tpd::reconciler::{IphostResolve, Reconciler, Source};

    let mut f = LinuxFixture::new();
    for source in [Source::Monitor, Source::L2tp] {
        let mut r = Reconciler::new(LinuxKernel::new().unwrap(), Box::<IphostResolve>::default());
        let mut subscription = match source {
            Source::Monitor => r.kernel_mut().monitor().unwrap(),
            Source::L2tp => r.kernel_mut().l2tp_events().unwrap(),
            _ => unreachable!(),
        };
        let mut config = Config::new();
        config
            .insert_tunnel(
                "a",
                TunnelConfig::builder(9510)
                    .ip_version(Family::V6)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        config
            .insert_session(
                "s",
                SessionConfig::builder("a", 9511, name("direct-live"))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert!(r.reconcile(config));
        let first = index_of("direct-live");
        ip(&[
            "l2tp",
            "del",
            "session",
            "tunnel_id",
            "9510",
            "session_id",
            "9511",
        ]);
        let notice = f
            .wait_notice(subscription.as_mut(), &mut |notice| match notice {
                Notice::LinkDel(link) => link.index() == first,
                Notice::SessionDeleted {
                    tunnel_id,
                    session_id,
                } => *tunnel_id == 9510 && *session_id == 9511,
                _ => false,
            })
            .expect("session deletion notification");
        r.handle(source, notice);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let recreated = loop {
            if let Some(session) = r.kernel_mut().session(9510, 9511).unwrap()
                && r.kernel_mut()
                    .link_by_name(&name("direct-live"))
                    .unwrap()
                    .is_some_and(|link| link.index() != first)
            {
                break session;
            }
            assert!(std::time::Instant::now() < deadline);
            r.tick();
            std::thread::yield_now();
        };
        assert_eq!(recreated.ifname(), Some(name("direct-live")), "{source:?}");
        assert!(r.shutdown());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while r.kernel_mut().tunnel(9510).unwrap().is_some() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
    }
}

/// spec: K33
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN"]
fn lowering_a_device_discards_ipv6_addresses_unless_preserved() {
    let mut f = LinuxFixture::new();
    let dev = f.add_link("down-v6", false);
    f.set_up(dev, true);
    let addr: IpAddr = "2001:db8:33::1".parse().unwrap();
    f.add_addr(dev, addr);
    let has_addr = |f: &mut LinuxFixture| {
        f.k()
            .dump_addrs()
            .unwrap()
            .iter()
            .any(|a| a.index() == dev && a.addr() == addr)
    };
    assert!(has_addr(&mut f));
    f.set_up(dev, false);
    assert!(!has_addr(&mut f));
    std::fs::write("/proc/sys/net/ipv6/conf/down-v6/keep_addr_on_down", "1").unwrap();
    f.set_up(dev, true);
    f.add_addr(dev, addr);
    f.set_up(dev, false);
    assert!(has_addr(&mut f));
}

/// spec: T5, K44, L2
#[test]
#[ignore = "live kernel in an isolated network namespace"]
fn tunnel_sockets_enable_fragmentation_before_connect() {
    use std::os::fd::AsRawFd;
    let mut f = LinuxFixture::new();
    for (n, family) in [Family::V4, Family::V6].into_iter().enumerate() {
        let socket = f.kernel.create_socket(family, 900 + n as u32, 990).unwrap();
        let fd = f.kernel.clone_fd(socket).unwrap();
        let mut options = vec![(libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)];
        if family == Family::V6 {
            options.extend([
                (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER),
                (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG),
            ]);
        }
        for (level, option) in options {
            let mut value: libc::c_int = -1;
            let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
            let result = unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    level,
                    option,
                    (&mut value as *mut libc::c_int).cast(),
                    &mut length,
                )
            };
            assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
            assert_eq!(length as usize, std::mem::size_of_val(&value));
            assert_eq!(value, 0, "{family:?}, level={level}, option={option}");
        }
        f.kernel.close(socket);
    }
}
