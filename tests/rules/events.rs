//! Events (docs/spec/events.md) over the fake kernel.

use super::{TUNNEL, config, deliver, ops, reconciler};

/// An address added to the bind device reconnects the connected tunnel
/// for a fresh source; one elsewhere touches nothing (E6, M16).
/// spec: E6, T19, M16
#[test]
fn an_address_on_the_bind_device_reconnects() {
    let (mut r, _) = reconciler();
    let wan = r.kernel_mut().add_link("wan0", false);
    let other = r.kernel_mut().add_link("lan0", false);
    r.kernel_mut().add_addr(wan, "192.0.2.1".parse().unwrap());
    r.reconcile(config(&format!("{TUNNEL}bind_interface = \"wan0\"\n")));
    deliver(&mut r);
    ops(&mut r);
    r.kernel_mut()
        .add_addr(other, "198.51.100.1".parse().unwrap());
    deliver(&mut r);
    assert_eq!(ops(&mut r), Vec::<String>::new());
    r.kernel_mut().add_addr(wan, "192.0.2.9".parse().unwrap());
    deliver(&mut r);
    let after = ops(&mut r);
    assert!(
        after.iter().any(|o| o.starts_with("disconnect")),
        "{after:?}"
    );
    assert!(after.iter().any(|o| o.starts_with("connect")), "{after:?}");
}

/// An unbound tunnel reconnects when the address it selected as its
/// source is removed, whatever device it was on (E7).
/// spec: E7, T19
#[test]
fn an_unbound_tunnel_follows_its_removed_source() {
    let (mut r, _) = reconciler();
    let a = r.kernel_mut().add_link("eth0", false);
    let b = r.kernel_mut().add_link("eth1", false);
    r.kernel_mut().add_addr(a, "192.0.2.1".parse().unwrap());
    r.kernel_mut().add_addr(b, "192.0.2.7".parse().unwrap());
    r.reconcile(config(TUNNEL));
    deliver(&mut r);
    let socket = r.kernel().tunnel_socket(10).unwrap();
    ops(&mut r);
    r.kernel_mut().del_addr(b, "192.0.2.7".parse().unwrap());
    deliver(&mut r);
    assert_eq!(ops(&mut r), Vec::<String>::new(), "not its source");
    r.kernel_mut().del_addr(a, "192.0.2.1".parse().unwrap());
    r.kernel_mut().add_addr(b, "192.0.2.8".parse().unwrap());
    deliver(&mut r);
    assert_eq!(
        r.kernel().connection(socket).map(|(_, s)| s),
        Some("192.0.2.8".parse().unwrap())
    );
}

/// The bind device disappearing disconnects the tunnel at once (E3, T12).
/// spec: E3, T12, T11
#[test]
fn a_vanished_bind_device_disconnects() {
    let (mut r, _) = reconciler();
    let wan = r.kernel_mut().add_link("wan0", false);
    r.kernel_mut().add_addr(wan, "192.0.2.1".parse().unwrap());
    r.reconcile(config(&format!("{TUNNEL}bind_interface = \"wan0\"\n")));
    deliver(&mut r);
    let socket = r.kernel().tunnel_socket(10).unwrap();
    assert!(r.kernel().connection(socket).is_some());
    r.kernel_mut().remove_link(wan);
    deliver(&mut r);
    assert_eq!(r.kernel().connection(socket), None);
    assert!(!r.kernel().transmits(10));
}
