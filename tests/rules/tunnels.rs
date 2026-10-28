//! Tunnels (docs/spec/tunnels.md) over the fake kernel.

use std::net::IpAddr;

use rs_l2tpd::kernel::Kernel;

use super::{TUNNEL, config, ops, reconciler};

/// A tunnel is created on an unconnected dual-stack socket, registered,
/// then connected to its literal peer; an IPv4 peer is mapped (T1, T3,
/// T6, T28).
/// spec: T1, T3, T6, T28
#[test]
fn a_tunnel_is_created_then_connected() {
    let (mut r, _) = reconciler();
    let device = r.kernel_mut().add_link("eth0", false);
    r.kernel_mut()
        .add_addr(device, "192.0.2.1".parse().unwrap());
    assert!(r.reconcile(config(TUNNEL)));
    assert_eq!(
        ops(&mut r),
        ["socket 1 V6 10", "register 10", "connect 1 192.0.2.2"]
    );
    let socket = r.kernel().tunnel_socket(10).unwrap();
    assert_eq!(
        r.kernel().connection(socket),
        Some((
            "192.0.2.2".parse::<IpAddr>().unwrap(),
            "192.0.2.1".parse().unwrap()
        ))
    );
    assert!(r.ready());
}

/// An identical reload changes nothing in the kernel (M2, E17).
/// spec: M2, E17, G18
#[test]
fn an_identical_reload_issues_no_operation() {
    let (mut r, _) = reconciler();
    let device = r.kernel_mut().add_link("eth0", false);
    r.kernel_mut()
        .add_addr(device, "192.0.2.1".parse().unwrap());
    assert!(r.reconcile(config(TUNNEL)));
    ops(&mut r);
    assert!(r.reconcile(config(TUNNEL)));
    assert_eq!(ops(&mut r), Vec::<String>::new());
}

/// Shutdown closes every socket (P16, T8).
/// spec: P16, T8
#[test]
fn shutdown_closes_the_sockets() {
    let (mut r, _) = reconciler();
    r.reconcile(config(TUNNEL));
    assert!(r.shutdown());
    r.kernel_mut().tick();
    assert_eq!(r.kernel().open_sockets(), 0);
    assert!(r.kernel_mut().tunnel(10).unwrap().is_none());
}
