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
        std::thread::sleep(Duration::from_millis(10));
    }
    fn net_raw(&self) -> bool {
        true
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
    SessionCreate {
        tunnel_id,
        session_id,
        peer_session_id: session_id + 1,
        cookie: None,
        peer_cookie: None,
        ifname: name(ifname),
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
    let peer = Peer {
        addr: "198.51.100.1".parse().unwrap(),
        zone: None,
    };
    // An ordinary bound device without an address: on-link, no source.
    assert_eq!(
        f.k().connect(v4, &peer).unwrap(),
        "0.0.0.0".parse::<IpAddr>().unwrap()
    );
    let v6peer = Peer {
        addr: "2001:db8:93::2".parse().unwrap(),
        zone: None,
    };
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
        assert_eq!((info.tunnel_id, info.peer_tunnel_id), (id, id + 1));
        let fd = f.k().clone_fd(socket).unwrap();
        f.k().close(socket);
        let adopted = f.k().adopt(fd).unwrap();
        assert_eq!(adopted.family, family);
        assert_eq!((adopted.tunnel_id, adopted.peer_tunnel_id), (id, id + 1));
        f.settle();
        assert!(f.k().tunnel(id).unwrap().is_some(), "K37");
        f.k().close(adopted.socket);
        let gone = (0..200).any(|_| {
            f.settle();
            f.k().tunnel(id).unwrap().is_none()
        });
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
    first.cookie = Some(rs_l2tpd::kernel::Cookie::new(&[1, 2, 3, 4]).unwrap());
    let registration = f.k().create_session(&first).unwrap();
    assert_eq!(registration.index, index_of("live-sa"));
    let set = HwAddr::new([0x02, 0, 0x5e, 0, 0x53, 0x93]).unwrap();
    f.k().set_hwaddr(registration.index, set).unwrap();
    assert_eq!(f.k().ether_addr(registration.index).unwrap(), Some(set));
    f.set_up(registration.index, true);
    let other = HwAddr::new([0x02, 0, 0x5e, 0, 0x53, 0x94]).unwrap();
    assert_eq!(
        errno(f.k().set_hwaddr(registration.index, other)),
        libc::EBUSY,
        "K31"
    );
    // An unchanged address is not a change (net/core/dev.c:9035-9039).
    f.k().set_hwaddr(registration.index, set).unwrap();
    let again = f.k().create_session(&create(9321, 93212, "live-sa"));
    assert!(matches!(errno(again), libc::EEXIST | libc::ENFILE), "K20");
    let second = f
        .k()
        .create_session(&create(9321, 93213, "live-sb"))
        .unwrap();
    assert_ne!(second.incarnation, registration.incarnation);
    let mut seen = Vec::new();
    f.k()
        .scan_sessions(Some(9321), &mut |s| seen.push(s.clone()))
        .unwrap();
    seen.sort_by_key(|s| s.session_id);
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].ifname, Some(name("live-sa")));
    assert_eq!(seen[0].peer_session_id, 93212);
    assert_eq!(seen[0].cookie, first.cookie.into());
    assert_eq!(seen[1].cookie, None.into());
    let mut all = 0;
    f.k().scan_sessions(None, &mut |_| all += 1).unwrap();
    assert!(all >= 2);
    f.k().delete_session_by_name(&name("live-sb")).unwrap();
    f.k().delete_session(9321, 93211).unwrap();
    let gone = (0..200).any(|_| {
        f.settle();
        f.k().session(9321, 93211).unwrap().is_none()
            && f.k().session(9321, 93213).unwrap().is_none()
    });
    assert!(gone);
    assert_eq!(f.k().prove(&registration), Proof::Removed);
    assert_eq!(f.k().prove(&second), Proof::Removed);
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
    assert_eq!((link.index, link.vrf, link.up), (vrf, true, false));
    let link = f.k().link_by_name(&name("live-dummy")).unwrap().unwrap();
    assert_eq!(
        (link.index, link.vrf, link.up, link.master),
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
            .any(|l| l.index == dummy && l.name == name("live-dummy2"))
    );
    assert!(links.iter().any(|l| l.index == vrf && l.vrf));
    let addrs = f.k().dump_addrs().unwrap();
    assert!(
        addrs
            .iter()
            .any(|a| a.index == dummy && a.addr == "203.0.113.5".parse::<IpAddr>().unwrap())
    );
    assert!(
        addrs
            .iter()
            .any(|a| a.addr == "127.0.0.1".parse::<IpAddr>().unwrap())
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
        &mut |n| matches!(n, Notice::AddrNew(a) if a.index == index && a.addr.is_ipv6()),
    );
    assert!(added.is_some());
    ip(&["addr", "del", "2001:db8:94::1/64", "dev", "live-mon"]);
    let removed = f.wait_notice(
        &mut *monitor,
        &mut |n| matches!(n, Notice::AddrDel(a) if a.index == index),
    );
    assert!(removed.is_some());
    ip(&["link", "del", "live-mon"]);
    let gone = f.wait_notice(
        &mut *monitor,
        &mut |n| matches!(n, Notice::LinkDel(l) if l.index == index && l.name == name("live-mon")),
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
