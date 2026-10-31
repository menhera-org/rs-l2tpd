//! The conformance suite against the fake kernel (docs/testing.md); the
//! same cases run against the real kernel in `linux.rs`.

#[path = "conformance.rs"]
mod conformance;

use std::net::IpAddr;
use std::task::{Context, Poll, Waker};

use conformance::Fixture;
use rs_l2tpd::kernel::fake::FakeKernel;
use rs_l2tpd::kernel::{
    Family, HwAddr, Kernel, L2tpIfName, Notice, Peer, Proof, Registration, SessionCreate, SocketId,
    Subscription,
};

struct FakeFixture(FakeKernel);

impl Fixture for FakeFixture {
    fn k(&mut self) -> &mut dyn Kernel {
        &mut self.0
    }
    fn add_link(&mut self, name: &str, vrf: bool) -> u32 {
        self.0.add_link(name, vrf)
    }
    fn set_up(&mut self, index: u32, up: bool) {
        self.0.set_up(index, up)
    }
    fn set_master(&mut self, index: u32, master: u32) {
        self.0.set_master(index, Some(master))
    }
    fn add_addr(&mut self, index: u32, addr: IpAddr) {
        self.0.add_addr(index, addr)
    }
    fn rename_link(&mut self, index: u32, name: &str) {
        self.0.rename_link(index, name)
    }
    fn settle(&mut self) {
        self.0.tick()
    }
    fn net_raw(&self) -> bool {
        self.0.net_raw()
    }
    fn send_frame(&mut self, index: u32) {
        self.0.send_frame(index);
    }
    fn tx_drops(&mut self, index: u32) -> u64 {
        self.0.tx_drops(index)
    }
    fn wait_notice(
        &mut self,
        sub: &mut dyn Subscription,
        want: &mut dyn FnMut(&Notice) -> bool,
    ) -> Option<Notice> {
        let mut cx = Context::from_waker(Waker::noop());
        while let Poll::Ready(notice) = sub.poll_notice(&mut cx) {
            if want(&notice) {
                return Some(notice);
            }
        }
        None
    }
}

/// spec: K16, K17, K18, K19, K20, K22, K24, K26, K27, K28, K31, K34, K35, K37, K41, S9, S19, S28, E5, T7, O5
#[test]
fn conformance_on_the_fake_kernel() {
    for (net_raw, asynchronous) in [(false, false), (false, true), (true, false), (true, true)] {
        for (case, run) in conformance::CASES {
            let mut kernel = FakeKernel::new(7);
            kernel.set_net_raw(net_raw);
            kernel.set_async_session_delete(asynchronous);
            eprintln!(
                "case {case}: inet6={} bindv6only={} only_v6_error={:?} net_raw={} async_delete={} tunnel_delete_delay={:?}",
                kernel.inet6(),
                kernel.bindv6only(),
                kernel.only_v6_error(),
                kernel.net_raw(),
                kernel.async_session_delete(),
                kernel.tunnel_delete_delay(),
            );
            run(&mut FakeFixture(kernel));
        }
    }
}

fn name(text: &str) -> L2tpIfName {
    L2tpIfName::new(text.as_bytes()).unwrap()
}

fn peer(text: &str, zone: Option<&str>) -> Peer {
    Peer::new(text.parse().unwrap(), zone.map(name))
}

fn errno<T: std::fmt::Debug>(result: std::io::Result<T>) -> i32 {
    result.unwrap_err().raw_os_error().unwrap()
}

#[test]
fn an_external_descriptor_keeps_frame_delivery_until_the_last_reference_closes() {
    let mut k = FakeKernel::new(7);
    assert!(!k.transmits(100));
    let socket = k.create_socket(Family::V4, 100, 200).unwrap();
    k.register_tunnel(socket, 100, 200).unwrap();
    let r = k
        .create_session(&SessionCreate::new(
            100,
            101,
            201,
            None,
            None,
            name("frames"),
        ))
        .unwrap();
    assert_eq!(
        k.connect(socket, &peer("192.0.2.2", None)).unwrap(),
        "0.0.0.0".parse::<IpAddr>().unwrap()
    );
    k.send_frame(r.index());
    assert_eq!(k.tx_drops(r.index()), 0);
    let external = k.clone_fd(socket).unwrap();
    k.close(socket);
    k.close(socket);
    k.tick();
    assert!(k.transmits(100));
    assert_eq!(k.tunnel(100).unwrap().unwrap().peer_tunnel_id(), 200);
    k.send_frame(r.index());
    assert_eq!(k.tx_drops(r.index()), 0);
    drop(external);
    assert!(!k.transmits(100));
    k.send_frame(r.index());
    assert_eq!(k.tx_drops(r.index()), 1);
    k.tick();
    assert!(k.tunnel(100).unwrap().is_none());
    assert_eq!(k.prove(&r), Proof::Removed);
    k.release(&r);
    assert_eq!(k.prove(&r), Proof::Lost);
}

#[test]
fn invalid_handles_and_fixture_identity_mistakes_preserve_existing_objects() {
    let mut k = FakeKernel::new(7);
    let missing = SocketId::new(u64::MAX);
    assert_eq!(errno(k.only_v6(missing)), nix::libc::EBADF);
    assert_eq!(
        errno(k.connect(missing, &peer("2001:db8::2", None))),
        nix::libc::EBADF
    );
    assert_eq!(errno(k.bind_index(missing, 0)), nix::libc::EBADF);
    assert_eq!(errno(k.disconnect(missing)), nix::libc::EBADF);
    assert_eq!(errno(k.clone_fd(missing)), nix::libc::EBADF);
    k.close(missing);
    let socket = k.create_socket(Family::V4, 100, 200).unwrap();
    assert_eq!(errno(k.only_v6(socket)), nix::libc::ENOPROTOOPT);
    // The fake deliberately rejects a daemon's mismatched socket metadata.
    assert_eq!(
        errno(k.register_tunnel(socket, 101, 200)),
        nix::libc::EINVAL
    );
    assert_eq!(
        errno(k.register_tunnel(socket, 100, 201)),
        nix::libc::EINVAL
    );
    k.register_tunnel(socket, 100, 200).unwrap();
    assert_eq!(errno(k.bind_index(socket, 0)), nix::libc::ENODEV);
    assert_eq!(
        errno(k.create_session(&SessionCreate::new(101, 1, 2, None, None, name("missing")))),
        nix::libc::ENODEV
    );
    assert_eq!(errno(k.rename(0, &name("missing"))), nix::libc::ENODEV);
    let mac = HwAddr::new([2, 0, 0, 0, 0, 1]).unwrap();
    assert_eq!(errno(k.set_hwaddr(0, mac)), nix::libc::ENODEV);
    assert_eq!(errno(k.ether_addr(0)), nix::libc::ENODEV);
    assert_eq!(k.tunnel(100).unwrap().unwrap().peer_tunnel_id(), 200);
    let unregistered = k.create_socket(Family::V6, 300, 400).unwrap();
    k.set_only_v6_error(Some(nix::errno::Errno::EPERM));
    assert_eq!(errno(k.only_v6(unregistered)), nix::libc::EPERM);
    k.set_only_v6_error(None);
    assert!(!k.only_v6(unregistered).unwrap());
    k.close(unregistered);
    assert_eq!(errno(k.clone_fd(unregistered)), nix::libc::EBADF);
    k.set_inet6(false);
    assert_eq!(errno(k.scratch_only_v6()), nix::libc::EAFNOSUPPORT);
    assert_eq!(
        errno(k.create_socket(Family::V6, 500, 600)),
        nix::libc::EAFNOSUPPORT
    );
    k.close(socket);
    k.tick();
    assert_eq!(k.open_sockets(), 0);
}

#[test]
fn link_local_scope_checks_precede_source_selection_and_disconnect_releases_the_cache() {
    let mut k = FakeKernel::new(7);
    let a = k.add_link("scope-a", false);
    let b = k.add_link("scope-b", false);
    k.add_addr(a, "192.0.2.1".parse().unwrap());
    k.add_addr(a, "2001:db8::1".parse().unwrap());
    k.add_addr(a, "fe80::1".parse().unwrap());
    let v4 = k.create_socket(Family::V4, 100, 200).unwrap();
    assert_eq!(
        errno(k.connect(v4, &peer("2001:db8::2", None))),
        nix::libc::EAFNOSUPPORT
    );
    k.close(v4);
    let socket = k.create_socket(Family::V6, 300, 400).unwrap();
    assert_eq!(
        errno(k.connect(socket, &peer("fe80::2", None))),
        nix::libc::EINVAL
    );
    assert_eq!(
        errno(k.connect(socket, &peer("fe80::2", Some("missing")))),
        nix::libc::ENODEV
    );
    k.bind_index(socket, a).unwrap();
    assert_eq!(
        errno(k.connect(socket, &peer("fe80::2", Some("scope-b")))),
        nix::libc::EINVAL
    );
    assert_eq!(k.binding(socket), Some(a));
    assert_eq!(
        k.connect(socket, &peer("fe80::2", None)).unwrap(),
        "fe80::1".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        k.connect(socket, &peer("2001:db8::2", None)).unwrap(),
        "fe80::1".parse::<IpAddr>().unwrap()
    );
    k.disconnect(socket).unwrap();
    assert_eq!(k.binding(socket), None);
    assert_eq!(k.connection(socket), None);
    k.bind_index(socket, a).unwrap();
    assert_eq!(
        k.connect(socket, &peer("2001:db8::2", None)).unwrap(),
        "2001:db8::1".parse::<IpAddr>().unwrap()
    );
    k.disconnect(socket).unwrap();
    k.bind_index(socket, b).unwrap();
    assert_eq!(
        errno(k.connect(socket, &peer("2001:db8::2", None))),
        nix::libc::EADDRNOTAVAIL
    );
    k.close(socket);
}

#[test]
fn replacing_one_tunnel_invalidates_only_its_registrations() {
    let mut k = FakeKernel::new(7);
    let mut sockets = Vec::new();
    let mut registrations = Vec::new();
    for id in [100, 200] {
        let socket = k.create_socket(Family::V6, id, id).unwrap();
        k.register_tunnel(socket, id, id).unwrap();
        let registration = k
            .create_session(&SessionCreate::new(
                id,
                id,
                id,
                None,
                None,
                name(&format!("proof{id}")),
            ))
            .unwrap();
        sockets.push(socket);
        registrations.push(registration);
    }
    let replaced = k.operator_replace_tunnel(100, 300);
    assert_eq!(k.prove(&registrations[0]), Proof::Removed);
    assert_eq!(k.prove(&registrations[1]), Proof::Proved);
    let r = &registrations[1];
    assert_eq!(
        k.prove(&Registration::new(
            r.index(),
            r.generation() + 1,
            r.incarnation()
        )),
        Proof::Lost
    );
    assert_eq!(
        k.prove(&Registration::new(
            r.index() + 1,
            r.generation(),
            r.incarnation()
        )),
        Proof::Removed
    );
    assert_eq!(k.tunnel(100).unwrap().unwrap().peer_tunnel_id(), 300);
    k.release(&registrations[0]);
    assert_eq!(k.prove(&registrations[0]), Proof::Lost);
    k.close(sockets[0]);
    k.tick();
    assert!(k.tunnel(100).unwrap().is_some());
    assert_eq!(k.prove(&registrations[1]), Proof::Proved);
    k.close(replaced);
    k.close(sockets[1]);
    k.tick();
    assert!(k.tunnel(100).unwrap().is_none());
    assert!(k.tunnel(200).unwrap().is_none());
}
