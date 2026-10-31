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
        [
            "socket 1 V6 10",
            "register 10",
            "disconnect 1",
            "connect 1 192.0.2.2"
        ]
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
            format!("disconnect {}", socket.get()),
            format!("connect {} 192.0.2.3", socket.get())
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
    assert_eq!(ops(&mut r), [format!("close {}", old.get())]);
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

fn tunable_request(
    r: &mut rs_l2tpd::reconciler::Reconciler<rs_l2tpd::kernel::fake::FakeKernel>,
) -> (u64, std::time::Instant) {
    let requests = r.take_requests();
    let writes: Vec<_> = requests
        .into_iter()
        .filter_map(|request| match request {
            rs_l2tpd::reconciler::Request::WriteBindv6only { id, deadline } => Some((id, deadline)),
            _ => None,
        })
        .collect();
    assert_eq!(writes.len(), 1);
    writes[0]
}

/// spec: L12, T26, P8, P25, E25
#[test]
fn tunable_success_waits_and_opens_fresh_sockets_for_all_waiters() {
    use std::time::Duration;
    let (mut r, _) = reconciler();
    r.kernel_mut().set_bindv6only(true);
    let text = format!(
        "{TUNNEL}\n[tunnels.b]\ntunnel_id = 11\nip_version = 'V6'\nremote_addr = '2001:db8::2'\n"
    );
    assert!(!r.reconcile(config(&text)));
    assert!(!r.ready());
    assert_eq!(r.kernel().open_sockets(), 0);
    let (id, deadline) = tunable_request(&mut r);
    r.kernel_mut()
        .advance(Duration::from_secs(5) - Duration::from_nanos(1));
    r.tick();
    assert!(r.kernel_mut().tunnel(10).unwrap().is_none());
    assert!(r.take_requests().is_empty(), "coalesced");
    r.kernel_mut().set_bindv6only(false);
    r.tunable_written(id, true);
    assert!(r.ready());
    for tid in [10, 11] {
        let socket = r.kernel().tunnel_socket(tid).unwrap();
        assert!(!r.kernel().only_v6(socket).unwrap());
    }
    assert!(r.kernel().now() < deadline);
    let socket = r.kernel().tunnel_socket(10).unwrap();
    r.tunable_written(id, true);
    assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
}

/// spec: L12, T26, P25
#[test]
fn failed_expired_and_still_v6only_writes_use_the_fallback_once() {
    for outcome in [0, 1, 2] {
        let (mut r, _) = reconciler();
        r.kernel_mut().set_bindv6only(true);
        let text = format!(
            "{TUNNEL}\n[tunnels.b]\ntunnel_id = 11\nip_version = 'V6'\nremote_addr = '2001:db8::2'\n"
        );
        r.reconcile(config(&text));
        let (id, _) = tunable_request(&mut r);
        if outcome == 0 {
            r.tunable_written(id, false);
        } else if outcome == 1 {
            super::run_for(&mut r, 5);
        } else {
            r.tunable_written(id, true);
        }
        assert!(r.ready());
        let v4 = r.kernel().tunnel_socket(10).unwrap();
        assert!(r.kernel().only_v6(v4).is_err(), "AF_INET fallback");
        let v6 = r.kernel().tunnel_socket(11).unwrap();
        assert!(r.kernel().only_v6(v6).unwrap());
        r.kernel_mut().set_bindv6only(false);
        r.tunable_written(id, true);
        super::run_for(&mut r, 2);
        assert_eq!(r.kernel().tunnel_socket(10), Some(v4));
        assert_eq!(r.kernel().tunnel_socket(11), Some(v6));
        assert!(
            !r.take_requests()
                .iter()
                .any(|r| matches!(r, rs_l2tpd::reconciler::Request::WriteBindv6only { .. }))
        );
    }
}

/// spec: L12, T26
#[test]
fn shutdown_cancels_the_tunable_handshake() {
    let (mut r, _) = reconciler();
    r.kernel_mut().set_bindv6only(true);
    r.reconcile(config(TUNNEL));
    let (id, _) = tunable_request(&mut r);
    assert!(r.shutdown());
    r.tunable_written(id, true);
    super::run_for(&mut r, 10);
    assert_eq!(r.kernel().open_sockets(), 0);
}

/// spec: T2, T16, T17, T20, M13, E8, G5
#[test]
fn every_transient_connect_errno_retries_the_new_peer_in_place() {
    use nix::errno::Errno;
    for error in [
        Errno::ENETUNREACH,
        Errno::EHOSTUNREACH,
        Errno::EACCES,
        Errno::EINVAL,
        Errno::EADDRNOTAVAIL,
        Errno::ENODEV,
        Errno::ENETDOWN,
    ] {
        let (mut r, _) = reconciler();
        let dev = r.kernel_mut().add_link("wan", false);
        r.kernel_mut().add_addr(dev, "192.0.2.1".parse().unwrap());
        r.reconcile(config(TUNNEL));
        let socket = r.kernel().tunnel_socket(10).unwrap();
        let next = "192.0.2.3".parse().unwrap();
        r.kernel_mut().refuse(next, Some(error));
        r.reconcile(config(&TUNNEL.replace("192.0.2.2", "192.0.2.3")));
        assert!(r.kernel().connection(socket).is_none(), "{error}");
        assert!(r.ready());
        let due = r.next_deadline().unwrap();
        assert_eq!(
            due.duration_since(r.kernel().now()),
            std::time::Duration::from_secs(1)
        );
        super::run_for(&mut r, 1);
        assert!(r.kernel().connection(socket).is_none());
        r.kernel_mut().refuse(next, None);
        super::run_for(&mut r, 1);
        assert_eq!(r.kernel().connection(socket).unwrap().0, next);
        assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
    }
}

/// spec: T4, T5, T26, M17
#[test]
fn socket_family_fallback_never_recreates_existing_tunnels() {
    for error in [
        nix::errno::Errno::EAFNOSUPPORT,
        nix::errno::Errno::EPROTONOSUPPORT,
    ] {
        let (mut r, _) = reconciler();
        r.kernel_mut().fail_next("socket", error);
        r.reconcile(config(TUNNEL));
        let socket = r.kernel().tunnel_socket(10).unwrap();
        assert!(r.kernel().only_v6(socket).is_err());
        let next = format!("{TUNNEL}\n[tunnels.b]\ntunnel_id=11\nremote_addr='192.0.2.3'");
        r.reconcile(config(&next));
        let fresh = r.kernel().tunnel_socket(11).unwrap();
        assert!(!r.kernel().only_v6(fresh).unwrap());
        assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
    }
}

/// spec: T26, L12
#[test]
fn failed_readback_never_registers_a_socket_as_dual_stack() {
    let (mut r, _) = reconciler();
    r.kernel_mut()
        .set_only_v6_error(Some(nix::errno::Errno::EIO));
    assert!(!r.reconcile(config(TUNNEL)));
    assert!(r.kernel_mut().tunnel(10).unwrap().is_none());
    assert_eq!(r.kernel().open_sockets(), 0);
    r.kernel_mut().set_only_v6_error(None);
    super::run_for(&mut r, 1);
    assert!(r.ready());
}

/// spec: T10, T11, T12, T27, E1, E2, E3, E4
#[test]
fn zone_and_vrf_dependencies_are_followed_independently() {
    let (mut r, _) = reconciler();
    let vrf = r.kernel_mut().add_link("blue", true);
    let zone = r.kernel_mut().add_link("wan", false);
    r.kernel_mut().set_master(zone, Some(vrf));
    r.kernel_mut().add_addr(zone, "fe80::1".parse().unwrap());
    let text =
        TUNNEL.replace("192.0.2.2", "fe80::2%wan") + "ip_version='V6'\nbind_interface='blue'";
    r.reconcile(config(&text));
    let socket = r.kernel().tunnel_socket(10).unwrap();
    assert_eq!(r.kernel().binding(socket), Some(zone));
    super::deliver(&mut r);
    r.kernel_mut().set_master(zone, None);
    super::deliver(&mut r);
    assert!(r.kernel().connection(socket).is_none());
    r.kernel_mut().set_master(zone, Some(vrf));
    super::deliver(&mut r);
    assert!(r.kernel().connection(socket).is_some());
    r.kernel_mut().rename_link(zone, "old-wan");
    super::deliver(&mut r);
    assert!(r.kernel().connection(socket).is_none());
    let new_zone = r.kernel_mut().add_link("wan", false);
    r.kernel_mut().set_master(new_zone, Some(vrf));
    r.kernel_mut()
        .add_addr(new_zone, "fe80::3".parse().unwrap());
    super::deliver(&mut r);
    assert_eq!(r.kernel().binding(socket), Some(new_zone));
    assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
}

/// spec: T25, E14, E17
#[test]
fn an_explicit_reload_retries_a_left_out_entry_before_its_slow_timer() {
    let (mut r, _) = reconciler();
    let foreign = r
        .kernel_mut()
        .create_socket(rs_l2tpd::kernel::Family::V6, 10, 99)
        .unwrap();
    r.kernel_mut().register_tunnel(foreign, 10, 99).unwrap();
    r.reconcile(config(TUNNEL));
    super::run_for(&mut r, 9);
    assert!(!r.left_out().is_empty());
    r.kernel_mut().close(foreign);
    r.kernel_mut().tick();
    assert!(r.reconcile(config(TUNNEL)));
    assert!(r.left_out().is_empty());
}

/// spec: T9, M9, R17
#[test]
fn cleanup_cannot_delete_a_foreign_replacement_tunnel() {
    let (mut r, _) = reconciler();
    r.reconcile(config(TUNNEL));
    let old = r.kernel().tunnel_socket(10).unwrap();
    let replacement = r.kernel_mut().operator_replace_tunnel(10, 99);
    super::deliver(&mut r);
    ops(&mut r);
    assert!(r.shutdown());
    r.kernel_mut().tick();
    assert_eq!(ops(&mut r), [format!("close {}", old.get())]);
    assert_eq!(r.kernel().tunnel_socket(10), Some(replacement));
    assert_eq!(
        r.kernel_mut().tunnel(10).unwrap().unwrap().peer_tunnel_id(),
        99
    );
}

/// spec: T8, T24, K17, M14
#[test]
fn delayed_tunnel_cleanup_withholds_replacement_until_release() {
    let (mut r, _) = reconciler();
    r.kernel_mut()
        .set_tunnel_delete_delay(std::time::Duration::from_secs(2));
    r.reconcile(config(TUNNEL));
    let old = r.kernel().tunnel_socket(10).unwrap();
    assert!(!r.reconcile(config(
        &TUNNEL.replace("peer_tunnel_id = 20", "peer_tunnel_id = 21")
    )));
    super::run_for(&mut r, 1);
    assert!(!r.ready());
    assert_eq!(r.kernel().open_sockets(), 0);
    super::run_for(&mut r, 1);
    assert!(r.ready());
    assert_ne!(r.kernel().tunnel_socket(10), Some(old));
}
