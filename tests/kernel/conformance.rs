//! The conformance suite (docs/testing.md): operation cases shared by the
//! fake kernel and the real one. Each case drives the fixture's `Kernel`
//! and changes the host only through the fixture's controls, which the
//! daemon itself never has. A fact the fake gets wrong fails its live run.

use std::io;
use std::net::IpAddr;

use rs_l2tpd::kernel::{
    Family, HwAddr, Kernel, L2tpIfName, Notice, Peer, Proof, SessionCreate, Subscription,
};

/// The kernel under test with the host controls and observations a test
/// needs and the daemon must not have.
pub trait Fixture {
    /// The kernel under test.
    fn k(&mut self) -> &mut dyn Kernel;
    /// Adds a dummy device, or a VRF, and returns its index.
    fn add_link(&mut self, name: &str, vrf: bool) -> u32;
    /// Brings a device up or down.
    fn set_up(&mut self, index: u32, up: bool);
    /// Enslaves a device to a controller.
    fn set_master(&mut self, index: u32, master: u32);
    /// Adds an address, with its subnet's prefix (/24, /64), no DAD.
    fn add_addr(&mut self, index: u32, addr: IpAddr);
    /// Renames a device, as another manager would.
    fn rename_link(&mut self, index: u32, name: &str);
    /// Lets the kernel's queued work run (K17, K18).
    fn settle(&mut self);
    /// Whether the daemon holds `CAP_NET_RAW` (K22).
    fn net_raw(&self) -> bool;
    /// Sends a frame through the session device.
    fn send_frame(&mut self, index: u32);
    /// Reads that device's transmit drops.
    fn tx_drops(&mut self, index: u32) -> u64;
    /// The next notice of `sub` matching `want`, waiting a bounded time.
    fn wait_notice(
        &mut self,
        sub: &mut dyn Subscription,
        want: &mut dyn FnMut(&Notice) -> bool,
    ) -> Option<Notice>;
}

fn name(text: &str) -> L2tpIfName {
    L2tpIfName::new(text.as_bytes()).unwrap()
}

fn errno<T: std::fmt::Debug>(result: io::Result<T>) -> i32 {
    result.unwrap_err().raw_os_error().unwrap()
}

fn tunnel(k: &mut dyn Kernel, id: u32) -> rs_l2tpd::kernel::SocketId {
    let socket = k.create_socket(Family::V6, id, id).unwrap();
    k.register_tunnel(socket, id, id).unwrap();
    socket
}

fn create(tunnel_id: u32, session_id: u32, ifname: &str) -> SessionCreate {
    SessionCreate::new(tunnel_id, session_id, session_id, None, None, name(ifname))
}

/// Polls `check` after letting the kernel work, a bounded number of times.
fn eventually(f: &mut dyn Fixture, mut check: impl FnMut(&mut dyn Kernel) -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        f.settle();
        if check(f.k()) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
    }
}

/// A tunnel identifier is refused while bound or registered (K19, T7).
pub fn tunnel_identifiers_are_unique(f: &mut dyn Fixture) {
    let first = tunnel(f.k(), 9101);
    assert_eq!(
        errno(f.k().create_socket(Family::V6, 9101, 9101)),
        nix::libc::EADDRINUSE
    );
    let other = f.k().create_socket(Family::V6, 9102, 9102).unwrap();
    assert_eq!(
        errno(f.k().register_tunnel(other, 9101, 9101)),
        nix::libc::EEXIST
    );
    assert_eq!(
        f.k().tunnel(9101).unwrap().map(|t| t.peer_tunnel_id()),
        Some(9101)
    );
    f.k().close(other);
    f.k().close(first);
}

/// A session identifier is refused in every tunnel of the namespace (K19).
pub fn session_identifiers_are_unique_in_the_namespace(f: &mut dyn Fixture) {
    let a = tunnel(f.k(), 9111);
    let b = tunnel(f.k(), 9112);
    f.k()
        .create_session(&create(9111, 91111, "conf-sa"))
        .unwrap();
    assert_eq!(
        errno(f.k().create_session(&create(9112, 91111, "conf-sb"))),
        nix::libc::EEXIST
    );
    assert!(f.k().session(9112, 91111).unwrap().is_none());
    assert_eq!(errno(f.k().delete_session(9112, 91111)), nix::libc::ENODEV);
    assert!(f.k().session(9111, 91111).unwrap().is_some());
    f.k().close(a);
    f.k().close(b);
    assert!(eventually(f, |k| k.tunnel(9111).unwrap().is_none()));
}

/// A session whose name is taken is not created (K20).
pub fn a_taken_name_creates_no_session(f: &mut dyn Fixture) {
    f.add_link("conf-taken", false);
    let socket = tunnel(f.k(), 9121);
    assert!(
        f.k()
            .create_session(&create(9121, 91211, "conf-taken"))
            .is_err()
    );
    let mut seen = 0;
    f.k().scan_sessions(Some(9121), &mut |_| seen += 1).unwrap();
    assert_eq!(seen, 0);
    f.k().close(socket);
}

/// The stored name is the creation name, kept across renames, and a
/// deletion by name takes a session that stored it (K16).
pub fn the_stored_name_is_the_creation_name(f: &mut dyn Fixture) {
    let socket = tunnel(f.k(), 9131);
    let registration = f
        .k()
        .create_session(&create(9131, 91311, "conf-stage"))
        .unwrap();
    f.rename_link(registration.index(), "conf-renamed");
    let info = f.k().session(9131, 91311).unwrap().unwrap();
    assert_eq!(info.ifname(), Some(name("conf-stage")));
    assert_eq!(
        f.k()
            .link_by_name(&name("conf-renamed"))
            .unwrap()
            .map(|l| l.index()),
        Some(registration.index())
    );
    f.k().delete_session_by_name(&name("conf-stage")).unwrap();
    assert!(eventually(f, |k| k.session(9131, 91311).unwrap().is_none()));
    f.k().close(socket);
}

/// Closing the socket deletes the tunnel and its sessions, later (K17).
pub fn closing_the_socket_deletes_the_tunnel(f: &mut dyn Fixture) {
    let socket = tunnel(f.k(), 9141);
    let registration = f
        .k()
        .create_session(&create(9141, 91411, "conf-close"))
        .unwrap();
    f.k().close(socket);
    assert!(eventually(f, |k| k.tunnel(9141).unwrap().is_none()));
    assert!(f.k().session(9141, 91411).unwrap().is_none());
    assert_eq!(f.k().prove(&registration), Proof::Removed);
}

/// A session identifier is free again once the deletion finished (K18).
pub fn a_deleted_session_identifier_is_released(f: &mut dyn Fixture) {
    let socket = tunnel(f.k(), 9151);
    f.k()
        .create_session(&create(9151, 91511, "conf-reuse"))
        .unwrap();
    f.k().delete_session(9151, 91511).unwrap();
    assert!(eventually(f, |k| k
        .create_session(&create(9151, 91511, "conf-reuse"))
        .is_ok()));
    f.k().close(socket);
}

/// A registration is proved until its device leaves (S9, S19).
pub fn a_registration_is_proved_until_removal(f: &mut dyn Fixture) {
    let socket = tunnel(f.k(), 9161);
    let registration = f
        .k()
        .create_session(&create(9161, 91611, "conf-proof"))
        .unwrap();
    assert_eq!(f.k().prove(&registration), Proof::Proved);
    f.rename_link(registration.index(), "conf-proof2");
    assert_eq!(f.k().prove(&registration), Proof::Proved);
    f.k().delete_session(9161, 91611).unwrap();
    assert!(eventually(f, |k| k.prove(&registration) == Proof::Removed));
    f.k().release(&registration);
    f.k().close(socket);
}

/// A binding is replaced only with `CAP_NET_RAW`; a disconnect clears it
/// (K22, T10, T21).
pub fn a_binding_is_set_on_an_unbound_socket(f: &mut dyn Fixture) {
    let a = f.add_link("conf-bind-a", false);
    let b = f.add_link("conf-bind-b", false);
    let socket = f.k().create_socket(Family::V6, 9171, 9171).unwrap();
    f.k().bind_index(socket, a).unwrap();
    let rebound = f.k().bind_index(socket, b);
    if f.net_raw() {
        rebound.unwrap();
    } else {
        assert_eq!(errno(rebound), nix::libc::EPERM);
    }
    f.k().disconnect(socket).unwrap();
    f.k().bind_index(socket, b).unwrap();
    f.k().close(socket);
}

/// A connect through a bound device selects its address; an IPv4 peer of
/// an `AF_INET6` socket is mapped; a connected socket refuses an IPv6
/// peer after a mapped one until disconnected (K24, K28, T21, T28).
pub fn connect_selects_the_source_of_the_device(f: &mut dyn Fixture) {
    let device = f.add_link("conf-conn", false);
    f.set_up(device, true);
    f.add_addr(device, "192.0.2.1".parse().unwrap());
    f.add_addr(device, "2001:db8:91::1".parse().unwrap());
    let socket = f.k().create_socket(Family::V6, 9181, 9181).unwrap();
    f.k().register_tunnel(socket, 9181, 9181).unwrap();
    f.k().bind_index(socket, device).unwrap();
    let v4 = Peer::new("192.0.2.2".parse().unwrap(), None);
    let source = f.k().connect(socket, &v4).unwrap();
    assert_eq!(
        source.to_canonical(),
        "192.0.2.1".parse::<IpAddr>().unwrap()
    );
    assert!(
        source.is_ipv6(),
        "an AF_INET6 socket reports the mapped form"
    );
    let v6 = Peer::new("2001:db8:91::2".parse().unwrap(), None);
    assert_eq!(errno(f.k().connect(socket, &v6)), nix::libc::EAFNOSUPPORT);
    f.k().disconnect(socket).unwrap();
    f.k().bind_index(socket, device).unwrap();
    assert_eq!(
        f.k().connect(socket, &v6).unwrap(),
        "2001:db8:91::1".parse::<IpAddr>().unwrap()
    );
    f.k().close(socket);
}

/// Without an IPv6 address in the socket's L3 domain an IPv6 connect
/// fails `EADDRNOTAVAIL` (K26, K34).
pub fn no_ipv6_source_is_eaddrnotavail(f: &mut dyn Fixture) {
    let vrf = f.add_link("conf-vrf", true);
    f.set_up(vrf, true);
    let socket = f.k().create_socket(Family::V6, 9191, 9191).unwrap();
    f.k().bind_index(socket, vrf).unwrap();
    let peer = Peer::new("2001:db8:92::2".parse().unwrap(), None);
    assert_eq!(
        errno(f.k().connect(socket, &peer)),
        nix::libc::EADDRNOTAVAIL
    );
    f.k().close(socket);
}

/// A zoned link-local peer is connected through the zone device, which
/// must be the bound device or a member of the bound VRF (K27).
pub fn a_link_local_zone_must_match_the_binding(f: &mut dyn Fixture) {
    let vrf = f.add_link("conf-llvrf", true);
    let member = f.add_link("conf-llm", false);
    let outsider = f.add_link("conf-llo", false);
    for index in [vrf, member, outsider] {
        f.set_up(index, true);
    }
    f.set_master(member, vrf);
    f.add_addr(member, "fe80::91:1".parse().unwrap());
    f.add_addr(outsider, "fe80::92:1".parse().unwrap());
    let socket = f.k().create_socket(Family::V6, 9201, 9201).unwrap();
    f.k().bind_index(socket, vrf).unwrap();
    let peer = |zone: &str| Peer::new("fe80::91:2".parse().unwrap(), Some(name(zone)));
    assert_eq!(
        errno(f.k().connect(socket, &peer("conf-llo"))),
        nix::libc::EINVAL
    );
    assert_eq!(
        f.k().connect(socket, &peer("conf-llm")).unwrap(),
        "fe80::91:1".parse::<IpAddr>().unwrap()
    );
    f.k().close(socket);
}

/// A hardware address is refused while the session device is up; a
/// rename is not (K31).
pub fn a_hardware_address_needs_the_device_down(f: &mut dyn Fixture) {
    let socket = tunnel(f.k(), 9211);
    let registration = f
        .k()
        .create_session(&create(9211, 92111, "conf-mac"))
        .unwrap();
    let addr = HwAddr::new([0x02, 0, 0x5e, 0, 0x53, 0x91]).unwrap();
    f.k().set_hwaddr(registration.index(), addr).unwrap();
    assert_eq!(f.k().ether_addr(registration.index()).unwrap(), Some(addr));
    f.set_up(registration.index(), true);
    let other = HwAddr::new([0x02, 0, 0x5e, 0, 0x53, 0x92]).unwrap();
    assert_eq!(
        errno(f.k().set_hwaddr(registration.index(), other)),
        nix::libc::EBUSY
    );
    // The same address is no change (net/core/dev.c, dev_set_mac_address).
    f.k().set_hwaddr(registration.index(), addr).unwrap();
    f.k()
        .rename(registration.index(), &name("conf-mac-up"))
        .unwrap();
    f.k().close(socket);
}

/// The event monitor reports devices of family `AF_UNSPEC` and addresses
/// (A5, E5).
pub fn the_monitor_reports_links_and_addresses(f: &mut dyn Fixture) {
    let mut monitor = f.k().monitor().unwrap();
    let index = f.add_link("conf-mon", false);
    let seen = f.wait_notice(
        &mut *monitor,
        &mut |n| matches!(n, Notice::LinkNew(l) if l.index() == index),
    );
    assert!(seen.is_some());
    f.add_addr(index, "192.0.2.91".parse().unwrap());
    let seen = f.wait_notice(
        &mut *monitor,
        &mut |n| matches!(n, Notice::AddrNew(a) if a.index() == index),
    );
    assert!(seen.is_some());
}

/// A deletion commanded over netlink is announced on the `l2tp` group;
/// closing a socket is not (K41).
pub fn deletions_are_announced(f: &mut dyn Fixture) {
    let mut events = f.k().l2tp_events().unwrap();
    let socket = tunnel(f.k(), 9221);
    f.k()
        .create_session(&create(9221, 92211, "conf-ann"))
        .unwrap();
    f.k().delete_session(9221, 92211).unwrap();
    let seen = f.wait_notice(&mut *events, &mut |n| {
        matches!(
            n,
            Notice::SessionDeleted {
                tunnel_id: 9221,
                session_id: 92211
            }
        )
    });
    assert!(seen.is_some());
    f.k().close(socket);
}

/// A disconnected socket really drops an emitted frame (K5).
pub fn disconnected_sessions_count_frame_drops(f: &mut dyn Fixture) {
    let socket = tunnel(f.k(), 9231);
    let registration = f
        .k()
        .create_session(&create(9231, 92311, "conf-drop"))
        .unwrap();
    f.add_addr(registration.index(), "192.0.2.1".parse().unwrap());
    f.set_up(registration.index(), true);
    let before = f.tx_drops(registration.index());
    f.send_frame(registration.index());
    assert!(f.tx_drops(registration.index()) > before);
    f.k().close(socket);
}

/// A case of the suite.
pub type Case = fn(&mut dyn Fixture);

/// Every case, by name, for the runners.
pub const CASES: &[(&str, Case)] = &[
    (
        "disconnected_sessions_count_frame_drops",
        disconnected_sessions_count_frame_drops,
    ),
    (
        "tunnel_identifiers_are_unique",
        tunnel_identifiers_are_unique,
    ),
    (
        "session_identifiers_are_unique_in_the_namespace",
        session_identifiers_are_unique_in_the_namespace,
    ),
    (
        "a_taken_name_creates_no_session",
        a_taken_name_creates_no_session,
    ),
    (
        "the_stored_name_is_the_creation_name",
        the_stored_name_is_the_creation_name,
    ),
    (
        "closing_the_socket_deletes_the_tunnel",
        closing_the_socket_deletes_the_tunnel,
    ),
    (
        "a_deleted_session_identifier_is_released",
        a_deleted_session_identifier_is_released,
    ),
    (
        "a_registration_is_proved_until_removal",
        a_registration_is_proved_until_removal,
    ),
    (
        "a_binding_is_set_on_an_unbound_socket",
        a_binding_is_set_on_an_unbound_socket,
    ),
    (
        "connect_selects_the_source_of_the_device",
        connect_selects_the_source_of_the_device,
    ),
    (
        "no_ipv6_source_is_eaddrnotavail",
        no_ipv6_source_is_eaddrnotavail,
    ),
    (
        "a_link_local_zone_must_match_the_binding",
        a_link_local_zone_must_match_the_binding,
    ),
    (
        "a_hardware_address_needs_the_device_down",
        a_hardware_address_needs_the_device_down,
    ),
    (
        "the_monitor_reports_links_and_addresses",
        the_monitor_reports_links_and_addresses,
    ),
    ("deletions_are_announced", deletions_are_announced),
];
