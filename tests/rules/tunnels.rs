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

/// A tunnel whose bind device is absent is created unbound and
/// disconnected, then bound and connected when the device appears (T13,
/// E1, T21).
/// spec: T13, E1, T21, T6
#[test]
fn an_absent_bind_device_is_waited_for() {
    let (mut r, _) = reconciler();
    let text = format!("{TUNNEL}bind_interface = \"wan0\"\n");
    assert!(r.reconcile(config(&text)));
    let socket = r.kernel().tunnel_socket(10).unwrap();
    assert_eq!(r.kernel().connection(socket), None);
    assert!(r.ready());
    let wan = r.kernel_mut().add_link("wan0", false);
    r.kernel_mut().add_addr(wan, "192.0.2.1".parse().unwrap());
    ops(&mut r);
    super::deliver(&mut r);
    assert_eq!(r.kernel().binding(socket), Some(wan));
    assert!(r.kernel().connection(socket).is_some());
    assert!(ops(&mut r).iter().any(|o| o.starts_with("bind ")));
}

/// A refused connect leaves the tunnel disconnected with the peer
/// pending, retried every second until it succeeds (T16, E13).
/// spec: T16, E13, M14
#[test]
fn a_refused_peer_is_retried_every_second() {
    let (mut r, _) = reconciler();
    let device = r.kernel_mut().add_link("eth0", false);
    r.kernel_mut()
        .add_addr(device, "192.0.2.1".parse().unwrap());
    r.kernel_mut().refuse(
        "192.0.2.2".parse().unwrap(),
        Some(nix::errno::Errno::ENETUNREACH),
    );
    r.reconcile(config(TUNNEL));
    let socket = r.kernel().tunnel_socket(10).unwrap();
    assert_eq!(r.kernel().connection(socket), None);
    assert!(r.ready(), "readiness does not wait for a peer");
    super::run_for(&mut r, 3);
    assert_eq!(
        ops(&mut r)
            .iter()
            .filter(|o| o.starts_with("connect"))
            .count(),
        4
    );
    r.kernel_mut().refuse("192.0.2.2".parse().unwrap(), None);
    super::run_for(&mut r, 1);
    assert!(r.kernel().connection(socket).is_some());
    ops(&mut r);
    super::run_for(&mut r, 3);
    let after = ops(&mut r);
    assert!(!after.iter().any(|o| o.starts_with("connect")), "{after:?}");
}

/// A changed remote_addr is a reconnect on the same socket (T22, T28).
/// spec: T22, T28, M12
#[test]
fn a_changed_peer_keeps_the_socket() {
    let (mut r, _) = reconciler();
    let device = r.kernel_mut().add_link("eth0", false);
    r.kernel_mut()
        .add_addr(device, "192.0.2.1".parse().unwrap());
    r.reconcile(config(TUNNEL));
    let socket = r.kernel().tunnel_socket(10).unwrap();
    ops(&mut r);
    r.reconcile(config(&TUNNEL.replace("192.0.2.2", "192.0.2.3")));
    assert_eq!(
        ops(&mut r),
        [
            format!("disconnect {}", socket.0),
            format!("connect {} 192.0.2.3", socket.0)
        ]
    );
    assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
}

/// A changed peer_tunnel_id re-creates the tunnel after the old one left
/// the kernel (T23, T24, T8).
/// spec: T23, T24, T8
#[test]
fn a_changed_kernel_identity_recreates_after_the_deletion() {
    let (mut r, _) = reconciler();
    r.reconcile(config(TUNNEL));
    let old = r.kernel().tunnel_socket(10).unwrap();
    ops(&mut r);
    let changed = TUNNEL.replace("peer_tunnel_id = 20", "peer_tunnel_id = 21");
    assert!(!r.reconcile(config(&changed)), "waits for the kernel");
    assert_eq!(ops(&mut r), [format!("close {}", old.0)]);
    super::run_for(&mut r, 1);
    let new = r.kernel().tunnel_socket(10).unwrap();
    assert_ne!(new, old);
    assert!(r.ready());
}

/// Ten refusals leave a tunnel out; it is retried every thirty seconds
/// and created once the identifier is free (T25, E14).
/// spec: T25, E14, M13
#[test]
fn a_conflict_leaves_the_tunnel_out_after_ten_attempts() {
    let (mut r, _) = reconciler();
    let foreign = r
        .kernel_mut()
        .create_socket(rs_l2tpd::kernel::Family::V6, 10, 99)
        .unwrap();
    r.kernel_mut().register_tunnel(foreign, 10, 99).unwrap();
    assert!(!r.reconcile(config(TUNNEL)));
    super::run_for(&mut r, 12);
    assert_eq!(r.left_out(), ["a"]);
    assert!(r.ready(), "a left-out entry is not eligible");
    r.kernel_mut().close(foreign);
    super::run_for(&mut r, 30);
    assert!(r.kernel().tunnel_socket(10).is_some());
    assert!(r.left_out().is_empty());
}
