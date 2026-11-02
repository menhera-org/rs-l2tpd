//! Events (docs/spec/events.md) over the fake kernel.

use super::{TUNNEL, config, deliver, ops, reconciler};
use rs_l2tpd::kernel::{AddrInfo, Kernel, Notice};
use rs_l2tpd::reconciler::Source;

/// spec: E3, E6, E7, M16, G13, G23
#[test]
fn repeated_address_removal_and_unusable_vrf_member_loss_issue_no_reconnect() {
    let (mut r, _) = reconciler();
    let vrf = r.kernel_mut().add_link("blue", true);
    let member = r.kernel_mut().add_link("member", false);
    r.kernel_mut().set_master(member, Some(vrf));
    let address = "2001:db8::1".parse().unwrap();
    let text = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nip_version='V6'\nremote_addr='2001:db8::2'\nbind_interface='blue'\n";
    assert!(r.reconcile(config(text)));
    deliver(&mut r);
    let socket = r.kernel().tunnel_socket(10).unwrap();
    assert!(r.kernel().connection(socket).is_none());
    ops(&mut r);
    r.kernel_mut().remove_link(member);
    deliver(&mut r);
    assert!(
        ops(&mut r).is_empty(),
        "a disconnected tunnel needs no source reselection"
    );
    let member = r.kernel_mut().add_link("member", false);
    r.kernel_mut().set_master(member, Some(vrf));
    r.kernel_mut().add_addr(member, address);
    deliver(&mut r);
    super::run_for(&mut r, 1);
    assert_eq!(
        r.kernel().connection(socket).map(|(_, source)| source),
        Some(address)
    );
    r.kernel_mut().del_addr(member, address);
    deliver(&mut r);
    assert!(r.kernel().connection(socket).is_none());
    ops(&mut r);
    for _ in 0..3 {
        r.handle(
            Source::Monitor,
            Notice::AddrDel(AddrInfo::new(member, address)),
        );
    }
    assert!(ops(&mut r).is_empty());
    assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
}

/// spec: R35, E20, E21, M18
#[test]
fn a_link_address_burst_coalesces_loss_and_recovers_the_final_source() {
    let (mut r, _) = reconciler();
    let wan = r.kernel_mut().add_link("wan", false);
    let old = "192.0.2.1".parse().unwrap();
    let new = "192.0.2.9".parse().unwrap();
    r.kernel_mut().add_addr(wan, old);
    let text = format!(
        "{TUNNEL}bind_interface='wan'\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'"
    );
    assert!(r.reconcile(config(&text)));
    deliver(&mut r);
    let socket = r.kernel().tunnel_socket(10).unwrap();
    let session = r.kernel().session_index(10, 100);
    ops(&mut r);
    r.kernel_mut().set_monitor_capacity(4);
    for _ in 0..1000 {
        let foreign = r.kernel_mut().add_link("foreign", false);
        r.kernel_mut().add_addr(foreign, old);
        r.kernel_mut().remove_link(foreign);
    }
    r.kernel_mut().del_addr(wan, old);
    r.kernel_mut().add_addr(wan, new);
    let notices = r.kernel_mut().take_monitor();
    assert_eq!(
        notices.iter().filter(|n| matches!(n, Notice::Loss)).count(),
        1
    );
    assert!(notices.len() <= 5);
    for notice in notices {
        r.handle(Source::Monitor, notice);
    }
    assert!(r.ready());
    assert_eq!(r.kernel().session_index(10, 100), session);
    assert_eq!(
        r.kernel().connection(socket).map(|(_, source)| source),
        Some(new)
    );
    assert_eq!(
        ops(&mut r),
        [
            format!("disconnect {}", socket.get()),
            format!("bind {} {wan}", socket.get()),
            format!("connect {} 192.0.2.2", socket.get())
        ]
    );
    assert_eq!(r.next_deadline(), None);
    assert!(r.kernel_mut().take_monitor().is_empty());
}

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

/// spec: E3, E4, E6, E7, T19, G5, G17
#[test]
fn vrf_address_removal_reselects_only_the_affected_family_and_member_loss_recovers() {
    let (mut r, _) = reconciler();
    let vrf = r.kernel_mut().add_link("blue", true);
    let first = r.kernel_mut().add_link("first", false);
    let second = r.kernel_mut().add_link("second", false);
    let outside = r.kernel_mut().add_link("outside", false);
    r.kernel_mut().set_master(first, Some(vrf));
    r.kernel_mut().set_master(second, Some(vrf));
    let [a4, a6, b4, b6, u4] = [
        "192.0.2.1",
        "2001:db8:1::1",
        "192.0.2.9",
        "2001:db8:1::9",
        "198.51.100.1",
    ]
    .map(|address| address.parse().unwrap());
    for (index, address) in [
        (first, a4),
        (first, a6),
        (second, b4),
        (second, b6),
        (outside, u4),
    ] {
        r.kernel_mut().add_addr(index, address);
    }
    let text = format!(
        "{TUNNEL}bind_interface='blue'\n[tunnels.v6]\ntunnel_id=11\nremote_addr='2001:db8:1::2'\nip_version='V6'\nbind_interface='blue'\n[tunnels.unbound]\ntunnel_id=12\nremote_addr='198.51.100.2'\n[sessions.v4]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'\n[sessions.v6]\ntunnel_name='v6'\nsession_id=101\ninterface_name='l2tp6'\n"
    );
    assert!(r.reconcile(config(&text)));
    deliver(&mut r);
    let v4 = r.kernel().tunnel_socket(10).unwrap();
    let v6 = r.kernel().tunnel_socket(11).unwrap();
    let unbound = r.kernel().tunnel_socket(12).unwrap();
    let sessions = (
        r.kernel().session_index(10, 100).unwrap(),
        r.kernel().session_index(11, 101).unwrap(),
    );
    assert_eq!(
        r.kernel().connection(v4).map(|(_, source)| source),
        Some(a4)
    );
    assert_eq!(
        r.kernel().connection(v6).map(|(_, source)| source),
        Some(a6)
    );
    assert_eq!(
        r.kernel().connection(unbound).map(|(_, source)| source),
        Some(u4)
    );
    ops(&mut r);
    for (address, socket, expected) in [(a4, v4, b4), (a6, v6, b6)] {
        r.kernel_mut().del_addr(first, address);
        deliver(&mut r);
        assert_eq!(
            r.kernel().connection(socket).map(|(_, source)| source),
            Some(expected)
        );
        let trace = ops(&mut r);
        assert_eq!(
            trace
                .iter()
                .filter(|op| op.starts_with("disconnect "))
                .count(),
            1
        );
        assert!(trace.contains(&format!("disconnect {}", socket.get())));
        assert!(!trace.iter().any(|op| op.starts_with("close")
            || op.starts_with("create")
            || op.starts_with("delete")));
        assert_eq!(
            r.kernel().connection(unbound).map(|(_, source)| source),
            Some(u4)
        );
    }
    r.kernel_mut().add_addr(first, a4);
    deliver(&mut r);
    assert!(r.kernel().connection(v4).is_some());
    assert!(ops(&mut r).contains(&format!("disconnect {}", v4.get())));
    r.kernel_mut().remove_link(second);
    deliver(&mut r);
    assert_eq!(
        r.kernel().connection(v4).map(|(_, source)| source),
        Some(a4)
    );
    assert!(r.kernel().connection(v6).is_none());
    assert_eq!(
        r.kernel().connection(unbound).map(|(_, source)| source),
        Some(u4)
    );
    let trace = ops(&mut r);
    assert_eq!(
        trace
            .iter()
            .filter(|op| op.starts_with("disconnect "))
            .count(),
        2
    );
    assert!(
        !trace.iter().any(|op| op.starts_with("close")
            || op.starts_with("create")
            || op.starts_with("delete"))
    );

    let replacement = r.kernel_mut().add_link("second", false);
    r.kernel_mut().set_master(replacement, Some(vrf));
    r.kernel_mut().add_addr(replacement, b6);
    deliver(&mut r);
    super::run_for(&mut r, 1);
    assert_eq!(
        r.kernel().connection(v6).map(|(_, source)| source),
        Some(b6)
    );
    assert_eq!(
        r.kernel().connection(v4).map(|(_, source)| source),
        Some(a4)
    );
    assert_eq!(
        r.kernel().connection(unbound).map(|(_, source)| source),
        Some(u4)
    );
    assert_eq!(r.kernel().tunnel_socket(10), Some(v4));
    assert_eq!(r.kernel().tunnel_socket(11), Some(v6));
    assert_eq!(r.kernel().tunnel_socket(12), Some(unbound));
    assert_eq!(
        (
            r.kernel().session_index(10, 100),
            r.kernel().session_index(11, 101)
        ),
        (Some(sessions.0), Some(sessions.1))
    );
    assert!(r.ready());
    assert_eq!(r.next_deadline(), None);
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

/// spec: M3, M4, M5, M7, E12, G6
#[test]
fn one_failed_creation_does_not_block_an_independent_entry() {
    let (mut r, _) = reconciler();
    let text = format!("{TUNNEL}\n[tunnels.b]\ntunnel_id=11\nremote_addr='192.0.2.3'");
    r.kernel_mut().fail_next("socket", nix::errno::Errno::EPERM);
    assert!(!r.reconcile(config(&text)));
    assert!(r.kernel_mut().tunnel(10).unwrap().is_none());
    let sibling = r.kernel().tunnel_socket(11).unwrap();
    super::run_for(&mut r, 1);
    assert!(r.ready());
    assert_eq!(r.kernel().tunnel_socket(11), Some(sibling));
}

/// spec: E20, E21, M18
#[test]
fn a_failed_monitor_or_l2tp_scan_stays_pending_until_it_succeeds() {
    for (source, operation) in [
        (Source::Monitor, "dump"),
        (Source::L2tp, "tunnel"),
        (Source::L2tp, "session"),
    ] {
        let (mut r, _) = reconciler();
        let device = r.kernel_mut().add_link("wan", false);
        r.kernel_mut()
            .add_addr(device, "192.0.2.1".parse().unwrap());
        r.reconcile(config(&format!(
            "{TUNNEL}\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'"
        )));
        deliver(&mut r);
        let socket = r.kernel().tunnel_socket(10).unwrap();
        let session = r.kernel().session_index(10, 100).unwrap();
        ops(&mut r);
        r.kernel_mut().fail_next(operation, nix::errno::Errno::EIO);
        r.handle(source, Notice::Loss);
        assert!(r.ready());
        assert!(r.next_deadline().is_some());
        super::run_for(&mut r, 1);
        assert!(r.ready());
        assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
        assert_eq!(r.kernel().session_index(10, 100), Some(session));
        assert!(!ops(&mut r).iter().any(|op| op.starts_with("delete")
            || op.starts_with("create")
            || op.starts_with("close")));
        assert_eq!(r.next_deadline(), None);
    }
}

/// spec: E1, E4, E20, E21, T12, M18
#[test]
fn a_failed_new_vrf_inventory_keeps_monitor_recovery_pending() {
    let (mut r, _) = reconciler();
    r.reconcile(config(&(TUNNEL.to_owned() + "bind_interface='wan'")));
    let socket = r.kernel().tunnel_socket(10).unwrap();
    let vrf = r.kernel_mut().add_link("wan", true);
    let member = r.kernel_mut().add_link("member", false);
    r.kernel_mut().set_master(member, Some(vrf));
    let source = "192.0.2.1".parse().unwrap();
    r.kernel_mut().add_addr(member, source);
    let link = r.kernel_mut().link_by_index(vrf).unwrap().unwrap();
    r.kernel_mut().take_monitor();
    ops(&mut r);
    r.kernel_mut().fail_next("dump", nix::errno::Errno::EIO);
    r.handle(Source::Monitor, Notice::LinkNew(link));
    assert!(r.next_deadline().is_some());
    super::run_for(&mut r, 1);
    assert!(r.ready());
    assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
    assert_eq!(r.kernel().binding(socket), Some(vrf));
    assert_eq!(
        r.kernel().connection(socket).map(|(_, source)| source),
        Some(source)
    );
    assert!(!ops(&mut r).iter().any(|op| op.starts_with("close")));
    assert_eq!(r.next_deadline(), None);
}

/// spec: E6, E8, T18, T20, M14, M15
#[test]
fn unrelated_address_events_never_connect_or_postpone_a_pending_peer() {
    let (mut r, _) = reconciler();
    let wan = r.kernel_mut().add_link("wan", false);
    r.kernel_mut().add_addr(wan, "192.0.2.1".parse().unwrap());
    r.kernel_mut().refuse(
        "192.0.2.2".parse().unwrap(),
        Some(nix::errno::Errno::ENETUNREACH),
    );
    r.reconcile(config(&(TUNNEL.to_owned() + "bind_interface='wan'")));
    let due = r.next_deadline();
    ops(&mut r);
    for address in ["192.0.2.4", "2001:db8::1"] {
        r.handle(
            Source::Monitor,
            Notice::AddrNew(AddrInfo::new(wan, address.parse().unwrap())),
        );
        assert_eq!(r.next_deadline(), due);
        assert!(ops(&mut r).is_empty());
    }
    r.kernel_mut().refuse("192.0.2.2".parse().unwrap(), None);
    super::run_for(&mut r, 1);
    assert!(r.kernel().transmits(10));
}

/// spec: E27, K41, S29, M9
#[test]
fn foreign_same_identifier_announcements_only_queue_verification() {
    let (mut r, _) = reconciler();
    let dev = r.kernel_mut().add_link("wan", false);
    r.kernel_mut().add_addr(dev, "192.0.2.1".parse().unwrap());
    let text =
        format!("{TUNNEL}\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'");
    r.reconcile(config(&text));
    let index = r.kernel().session_index(10, 100);
    ops(&mut r);
    for _ in 0..100 {
        r.handle(
            Source::L2tp,
            Notice::SessionDeleted {
                tunnel_id: 10,
                session_id: 100,
            },
        );
    }
    super::run_for(&mut r, 2);
    assert!(r.ready());
    assert_eq!(r.kernel().session_index(10, 100), index);
    assert!(ops(&mut r).is_empty());
}

/// spec: E18, E19, M3
#[test]
fn a_new_configuration_supersedes_an_incomplete_one_and_shutdown_removes_progress() {
    let (mut r, _) = reconciler();
    r.kernel_mut().fail_next("socket", nix::errno::Errno::EPERM);
    assert!(!r.reconcile(config(TUNNEL)));
    let latest = config(&TUNNEL.replace("tunnel_id = 10", "tunnel_id = 11"));
    r.reconcile(latest.clone());
    super::run_for(&mut r, 1);
    assert_eq!(r.accepted(), &latest);
    assert!(r.kernel_mut().tunnel(10).unwrap().is_none());
    assert!(r.kernel_mut().tunnel(11).unwrap().is_some());
    assert!(r.shutdown());
    r.kernel_mut().tick();
    assert_eq!(r.kernel().open_sockets(), 0);
}

/// spec: M16, E4, E6
#[test]
fn unrelated_events_query_no_kernel_objects_even_with_many_entries() {
    let (mut r, _) = reconciler();
    let text = (1..=100).map(|id| format!("[tunnels.t{id}]\ntunnel_id={id}\nremote_addr='192.0.2.2'\nbind_interface='wan{id}'\n")).collect::<String>();
    r.reconcile(config(&text));
    ops(&mut r);
    r.kernel_mut().fail_next("link", nix::errno::Errno::EIO);
    r.kernel_mut().fail_next("session", nix::errno::Errno::EIO);
    for id in 1000..1100 {
        r.handle(
            Source::Monitor,
            Notice::LinkNew(rs_l2tpd::kernel::LinkInfo::new(
                id,
                rs_l2tpd::kernel::L2tpIfName::new(format!("foreign{id}").as_bytes()).unwrap(),
                true,
                false,
                None,
            )),
        );
        r.handle(
            Source::Monitor,
            Notice::AddrNew(AddrInfo::new(id, "192.0.2.9".parse().unwrap())),
        );
    }
    assert!(ops(&mut r).is_empty());
    assert_eq!(
        r.kernel_mut()
            .link_by_name(&rs_l2tpd::kernel::L2tpIfName::new(b"unused").unwrap())
            .unwrap_err()
            .raw_os_error(),
        Some(nix::libc::EIO)
    );
    assert_eq!(
        r.kernel_mut().session(1, 100).unwrap_err().raw_os_error(),
        Some(nix::libc::EIO)
    );
}

/// spec: M14, M15, V4, E27
#[test]
fn event_traffic_does_not_move_the_absolute_poll_deadline() {
    let (mut r, _) = reconciler();
    r.reconcile(config(
        &(TUNNEL.replace("192.0.2.2", "peer.example") + "ip_version='V4'"),
    ));
    let due = r.next_deadline().unwrap();
    for _ in 0..5 {
        r.kernel_mut()
            .advance(std::time::Duration::from_millis(100));
        r.handle(
            Source::Monitor,
            Notice::AddrNew(AddrInfo::new(999, "192.0.2.1".parse().unwrap())),
        );
        assert_eq!(r.next_deadline(), Some(due));
    }
}

/// spec: M16, E4, E6
#[test]
fn a_cached_master_is_not_queried_again_on_each_converge() {
    for vrf in [false, true] {
        let (mut r, _) = reconciler();
        let parent = r.kernel_mut().add_link("parent", vrf);
        let device = r.kernel_mut().add_link("wan", false);
        r.kernel_mut().set_master(device, Some(parent));
        r.kernel_mut()
            .add_addr(device, "192.0.2.1".parse().unwrap());
        r.reconcile(config(&(TUNNEL.to_owned() + "bind_interface='wan'")));
        deliver(&mut r);
        assert!(r.kernel().transmits(10));
        r.kernel_mut()
            .fail_next("link_index", nix::errno::Errno::EIO);
        r.kernel_mut()
            .add_addr(device, "192.0.2.9".parse().unwrap());
        deliver(&mut r);
        assert!(r.kernel().transmits(10));
        assert_eq!(
            r.kernel_mut()
                .link_by_index(parent)
                .unwrap_err()
                .raw_os_error(),
            Some(nix::libc::EIO),
            "the cached master's query was not issued"
        );
    }
}

/// spec: E27, S27, M3, M5, M16, G23
#[test]
fn a_session_deletion_retries_only_that_entry_before_the_global_retry() {
    let (mut r, _) = reconciler();
    let text = format!(
        "{TUNNEL}\n[sessions.a]\ntunnel_name='a'\nsession_id=100\ninterface_name='n0'\n[sessions.b]\ntunnel_name='a'\nsession_id=101\ninterface_name='n1'\n"
    );
    r.kernel_mut().fail_next("create", nix::errno::Errno::EIO);
    assert!(!r.reconcile(config(&text)));
    assert!(r.kernel().session_index(10, 100).is_none());
    let removed = r.kernel().session_index(10, 101).unwrap();
    r.kernel_mut().operator_delete_session(10, 101);
    r.kernel_mut().tick();
    ops(&mut r);
    r.handle(
        Source::L2tp,
        Notice::SessionDeleted {
            tunnel_id: 10,
            session_id: 101,
        },
    );
    let replacement = r.kernel().session_index(10, 101).unwrap();
    assert_ne!(replacement, removed);
    assert!(
        r.kernel().session_index(10, 100).is_none(),
        "unrelated creation must wait for its own retry"
    );
    assert!(
        !ops(&mut r)
            .iter()
            .any(|op| op.starts_with("create 10 100 "))
    );
    r.kernel_mut().advance(std::time::Duration::from_secs(1));
    r.tick();
    assert!(r.kernel().session_index(10, 100).is_some());
    assert_eq!(r.kernel().session_index(10, 101), Some(replacement));
}

/// spec: E20, E12, M14, G5
#[test]
fn event_verification_l2tp_query_errors_remain_pending_until_a_complete_pass() {
    for operation in ["tunnel", "session"] {
        let (mut r, _) = reconciler();
        let wan = r.kernel_mut().add_link("wan", false);
        r.kernel_mut().add_addr(wan, "192.0.2.1".parse().unwrap());
        let text = format!(
            "{TUNNEL}\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'\n"
        );
        assert!(r.reconcile(config(&text)));
        deliver(&mut r);
        let socket = r.kernel().tunnel_socket(10).unwrap();
        assert!(r.kernel().connection(socket).is_some());
        let session = r.kernel().session_index(10, 100).unwrap();
        ops(&mut r);
        r.kernel_mut().fail_next(operation, nix::errno::Errno::EIO);
        r.handle(Source::L2tp, Notice::Loss);
        assert!(r.ready());
        assert_eq!(
            r.next_deadline().unwrap().duration_since(r.kernel().now()),
            std::time::Duration::from_secs(1)
        );
        r.kernel_mut().fail_next(operation, nix::errno::Errno::EIO);
        super::run_for(&mut r, 1);
        assert_eq!(
            r.next_deadline().unwrap().duration_since(r.kernel().now()),
            std::time::Duration::from_secs(1)
        );
        super::run_for(&mut r, 1);
        assert_eq!(r.next_deadline(), None);
        assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
        assert_eq!(r.kernel().session_index(10, 100), Some(session));
        assert!(ops(&mut r).is_empty());
    }
}

/// spec: E27, E12, S27, S29, K41, G2, G5
#[test]
fn event_verification_session_query_errors_preserve_identity_until_absence_is_confirmed() {
    for removed in [false, true] {
        let (mut r, _) = reconciler();
        let wan = r.kernel_mut().add_link("wan", false);
        r.kernel_mut().add_addr(wan, "192.0.2.1".parse().unwrap());
        let text = format!(
            "{TUNNEL}\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'\n"
        );
        assert!(r.reconcile(config(&text)));
        deliver(&mut r);
        let socket = r.kernel().tunnel_socket(10).unwrap();
        assert!(r.kernel().connection(socket).is_some());
        let session = r.kernel().session_index(10, 100).unwrap();
        ops(&mut r);
        r.kernel_mut().fail_next("session", nix::errno::Errno::EIO);
        r.handle(
            Source::L2tp,
            Notice::SessionDeleted {
                tunnel_id: 10,
                session_id: 100,
            },
        );
        assert!(r.ready());
        assert_eq!(r.kernel().session_index(10, 100), Some(session));
        assert!(ops(&mut r).is_empty());
        assert_eq!(
            r.next_deadline().unwrap().duration_since(r.kernel().now()),
            std::time::Duration::from_secs(1)
        );
        r.kernel_mut().fail_next("session", nix::errno::Errno::EIO);
        super::run_for(&mut r, 1);
        assert!(r.next_deadline().is_some());
        if removed {
            r.kernel_mut().operator_delete_session(10, 100);
        }
        super::run_for(&mut r, 1);
        assert!(r.ready());
        if removed {
            assert_eq!(r.next_deadline(), None);
        } else {
            assert_eq!(
                r.next_deadline().unwrap().duration_since(r.kernel().now()),
                std::time::Duration::from_secs(1)
            );
        }
        assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
        let current = r.kernel().session_index(10, 100).unwrap();
        assert_eq!(current == session, !removed);
        assert_eq!(
            r.kernel().link(current).unwrap().name().to_string_lossy(),
            "l2tp0"
        );
        let trace = ops(&mut r);
        if removed {
            assert_eq!(
                trace.iter().filter(|op| op.starts_with("create ")).count(),
                1
            );
        } else {
            assert!(trace.is_empty());
        }
        assert!(
            !trace
                .iter()
                .any(|op| op.starts_with("close ") || op.starts_with("delete "))
        );
        if !removed {
            assert!(r.reconcile(config(TUNNEL)));
            super::run_for(&mut r, 2);
            assert_eq!(r.next_deadline(), None);
            assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
            assert!(r.kernel().session_index(10, 100).is_none());
        }
    }
}

/// spec: E20, E12, S12, M14, G2, G4
#[test]
fn event_verification_monitor_loss_retries_a_refused_deferred_mac_without_replacing_the_session() {
    use rs_l2tpd::kernel::HwAddr;
    let (mut r, _) = reconciler();
    let wan = r.kernel_mut().add_link("wan", false);
    r.kernel_mut().add_addr(wan, "192.0.2.1".parse().unwrap());
    let text = format!(
        "{TUNNEL}\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'\ninterface_hwaddr='02:00:5e:00:53:01'\n"
    );
    assert!(r.reconcile(config(&text)));
    deliver(&mut r);
    let socket = r.kernel().tunnel_socket(10).unwrap();
    assert!(r.kernel().connection(socket).is_some());
    let index = r.kernel().session_index(10, 100).unwrap();
    let original = r.kernel_mut().ether_addr(index).unwrap();
    r.kernel_mut().set_up(index, true);
    assert!(r.reconcile(config(&text.replace("53:01", "53:02"))));
    assert_eq!(r.kernel_mut().ether_addr(index).unwrap(), original);
    r.kernel_mut().set_up(index, false);
    r.kernel_mut().take_monitor();
    ops(&mut r);
    r.kernel_mut().fail_next("hwaddr", nix::errno::Errno::EIO);
    r.kernel_mut().fail_next("hwaddr", nix::errno::Errno::EIO);
    r.handle(Source::Monitor, Notice::Loss);
    // Readiness reports existing objects while enforcement retries continue.
    assert!(r.ready());
    assert_eq!(r.kernel_mut().ether_addr(index).unwrap(), original);
    assert_eq!(
        r.next_deadline().unwrap().duration_since(r.kernel().now()),
        std::time::Duration::from_secs(1)
    );
    super::run_for(&mut r, 1);
    assert!(r.ready());
    assert_eq!(r.next_deadline(), None);
    assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
    assert_eq!(r.kernel().session_index(10, 100), Some(index));
    assert!(!r.kernel().link(index).unwrap().up());
    assert_eq!(
        r.kernel_mut().ether_addr(index).unwrap(),
        Some(HwAddr::new([2, 0, 0x5e, 0, 0x53, 2]).unwrap())
    );
    let trace = ops(&mut r);
    assert_eq!(
        trace.iter().filter(|op| op.starts_with("hwaddr ")).count(),
        1
    );
    assert!(!trace.iter().any(|op| op.starts_with("close ")
        || op.starts_with("delete ")
        || op.starts_with("create ")
        || op.starts_with("rename ")));
}

/// spec: E3, E12, E27, S8, S12, S27, S29, G2, G5
#[test]
fn event_verification_recreation_retries_failed_publication_on_the_same_new_index() {
    for source in [Source::Monitor, Source::L2tp] {
        let (mut r, _) = reconciler();
        let wan = r.kernel_mut().add_link("wan", false);
        r.kernel_mut().add_addr(wan, "192.0.2.1".parse().unwrap());
        let text = format!(
            "{TUNNEL}\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'\ninterface_hwaddr='02:00:5e:00:53:01'\n"
        );
        assert!(r.reconcile(config(&text)));
        deliver(&mut r);
        let socket = r.kernel().tunnel_socket(10).unwrap();
        assert!(r.kernel().connection(socket).is_some());
        let original = r.kernel().session_index(10, 100).unwrap();
        r.kernel_mut().operator_delete_session(10, 100);
        r.kernel_mut().tick();
        let notices = r.kernel_mut().take_monitor();
        r.kernel_mut().take_l2tp();
        r.kernel_mut().fail_next("rename", nix::errno::Errno::EIO);
        if source == Source::Monitor {
            for notice in notices {
                r.handle(Source::Monitor, notice);
            }
        } else {
            r.handle(
                Source::L2tp,
                Notice::SessionDeleted {
                    tunnel_id: 10,
                    session_id: 100,
                },
            );
        }
        let pending = r.kernel().session_index(10, 100).unwrap();
        assert_ne!(pending, original);
        assert!(
            r.kernel()
                .link(pending)
                .unwrap()
                .name()
                .to_string_lossy()
                .starts_with("rsl2tp-t")
        );
        // Readiness reports existing objects while enforcement retries continue.
        assert!(r.ready());
        assert_eq!(
            r.next_deadline().unwrap().duration_since(r.kernel().now()),
            std::time::Duration::from_secs(1)
        );
        ops(&mut r);
        super::run_for(&mut r, 1);
        assert!(r.ready());
        assert_eq!(r.next_deadline(), None);
        assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
        assert_eq!(r.kernel().session_index(10, 100), Some(pending));
        assert_eq!(
            r.kernel().link(pending).unwrap().name().to_string_lossy(),
            "l2tp0"
        );
        assert_eq!(ops(&mut r), [format!("rename {pending} l2tp0")]);
    }
}

/// spec: E27, S27, S29, K18, K41, G2, G5
#[test]
fn event_verification_keeps_querying_while_the_announced_session_deletion_is_still_queued() {
    let (mut r, _) = reconciler();
    let wan = r.kernel_mut().add_link("wan", false);
    r.kernel_mut().add_addr(wan, "192.0.2.1".parse().unwrap());
    let text = format!(
        "{TUNNEL}\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'\n"
    );
    assert!(r.reconcile(config(&text)));
    deliver(&mut r);
    let socket = r.kernel().tunnel_socket(10).unwrap();
    let original = r.kernel().session_index(10, 100).unwrap();
    ops(&mut r);
    r.kernel_mut().operator_delete_session(10, 100);
    for notice in r.kernel_mut().take_l2tp() {
        r.handle(Source::L2tp, notice);
    }
    // Advance the daemon's clock while withholding the kernel's queued work.
    for _ in 0..3 {
        r.kernel_mut().advance(std::time::Duration::from_secs(1));
        r.tick();
        assert!(r.ready());
        assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
        assert_eq!(r.kernel().session_index(10, 100), Some(original));
        assert_eq!(
            r.next_deadline().unwrap().duration_since(r.kernel().now()),
            std::time::Duration::from_secs(1)
        );
        assert!(ops(&mut r).is_empty());
    }
    r.kernel_mut().tick();
    r.kernel_mut().take_monitor();
    r.kernel_mut().take_l2tp();
    r.kernel_mut().advance(std::time::Duration::from_secs(1));
    r.tick();
    assert!(r.ready());
    assert_eq!(r.next_deadline(), None);
    assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
    let replacement = r.kernel().session_index(10, 100).unwrap();
    assert_ne!(replacement, original);
    assert_eq!(
        r.kernel()
            .link(replacement)
            .unwrap()
            .name()
            .to_string_lossy(),
        "l2tp0"
    );
    assert_eq!(ops(&mut r), ["create 10 100 l2tp0"]);
}
