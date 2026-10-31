use super::{TUNNEL, config, reconciler, run_for};
use rs_l2tpd::config::Config;
use rs_l2tpd::kernel::{Family, Kernel};
use rs_l2tpd::reconciler::Request;
use std::os::fd::OwnedFd;

fn stored(requests: Vec<Request>) -> OwnedFd {
    requests
        .into_iter()
        .find_map(|r| match r {
            Request::StoreSocket {
                name,
                tunnel_id,
                fd,
            } => {
                assert_eq!(name, format!("t{tunnel_id}"));
                Some(fd)
            }
            _ => None,
        })
        .expect("stored descriptor")
}

fn withdrawal(requests: Vec<Request>, want: &str) -> u64 {
    requests
        .into_iter()
        .find_map(|r| match r {
            Request::ForgetSocket { name, id, .. } => {
                assert_eq!(name, want);
                Some(id)
            }
            _ => None,
        })
        .expect("withdrawal request")
}

/// spec: L13, P14, K37, T8, T24, M14, A8
#[test]
fn withdrawal_precedes_close_and_replacement_storage() {
    let (mut r, _) = reconciler();
    r.set_store_capacity(1);
    r.reconcile(config(TUNNEL));
    let manager = stored(r.take_requests());
    let old = r.kernel().tunnel_socket(10).unwrap();
    let changed = config(&TUNNEL.replace("peer_tunnel_id = 20", "peer_tunnel_id = 21"));
    assert!(!r.reconcile(changed));
    let id = withdrawal(r.take_requests(), "t10");
    assert_eq!(r.kernel().open_sockets(), 1, "waits before close");
    drop(manager);
    r.socket_forgotten(id, true);
    assert_eq!(r.kernel().open_sockets(), 0);
    run_for(&mut r, 1);
    let replacement = r.kernel().tunnel_socket(10).unwrap();
    assert_ne!(replacement, old);
    let _new_manager = stored(r.take_requests());
    r.socket_forgotten(id, true);
    assert_eq!(
        r.kernel().open_sockets(),
        1,
        "stale acknowledgement ignored"
    );
}

/// spec: L13, P14, M14
#[test]
fn missing_and_failed_barriers_keep_retirement_bounded_and_block_reuse() {
    let (mut r, _) = reconciler();
    r.set_store_capacity(1);
    r.reconcile(config(TUNNEL));
    let manager = stored(r.take_requests());
    r.reconcile(config(
        &TUNNEL.replace("peer_tunnel_id = 20", "peer_tunnel_id = 21"),
    ));
    let first = withdrawal(r.take_requests(), "t10");
    run_for(&mut r, 2);
    assert_eq!(
        r.kernel().open_sockets(),
        0,
        "deadline closes local duplicate"
    );
    assert!(
        r.kernel_mut().tunnel(10).unwrap().is_some(),
        "store still owns a reference"
    );
    r.socket_forgotten(first, true);
    run_for(&mut r, 1);
    let second = withdrawal(r.take_requests(), "t10");
    assert_ne!(first, second);
    r.socket_forgotten(second, false);
    run_for(&mut r, 1);
    let third = withdrawal(r.take_requests(), "t10");
    drop(manager);
    r.socket_forgotten(third, true);
    run_for(&mut r, 1);
    assert!(r.ready());
    let _manager = stored(r.take_requests());
}

/// spec: P14, L13, S28
#[test]
fn adoption_retries_uncertainty_and_retires_a_changed_peer_by_exact_name() {
    let (mut r, _) = reconciler();
    r.set_store_capacity(1);
    let socket = r.kernel_mut().create_socket(Family::V6, 10, 20).unwrap();
    r.kernel_mut().register_tunnel(socket, 10, 20).unwrap();
    let fd = r.kernel().clone_fd(socket).unwrap();
    let manager = fd.try_clone().unwrap();
    r.kernel_mut().close(socket);
    r.inherit("t10".into(), fd);
    r.kernel_mut()
        .fail_next("adopt", nix::errno::Errno::ETIMEDOUT);
    assert!(!r.reconcile(config(TUNNEL)));
    assert!(r.take_requests().is_empty());
    run_for(&mut r, 1);
    assert!(r.ready());
    assert_eq!(r.kernel().open_sockets(), 1);
    r.reconcile(config(
        &TUNNEL.replace("peer_tunnel_id = 20", "peer_tunnel_id = 21"),
    ));
    let id = withdrawal(r.take_requests(), "t10");
    drop(manager);
    r.socket_forgotten(id, true);
    run_for(&mut r, 1);
    assert!(r.ready());
}

/// spec: P14, S28, L13, A14
#[test]
fn an_incomplete_adopted_session_dump_keeps_ownership_for_retry() {
    let (mut r, _) = reconciler();
    let socket = r.kernel_mut().create_socket(Family::V6, 10, 20).unwrap();
    r.kernel_mut().register_tunnel(socket, 10, 20).unwrap();
    let fd = r.kernel().clone_fd(socket).unwrap();
    r.kernel_mut().close(socket);
    r.adopt(10, fd).unwrap();
    r.kernel_mut().fail_next("scan", nix::errno::Errno::EIO);
    super::ops(&mut r);
    assert!(!r.reconcile(config(TUNNEL)));
    assert!(r.kernel_mut().tunnel(10).unwrap().is_some());
    assert!(r.take_requests().is_empty());
    run_for(&mut r, 1);
    assert!(r.ready());
    assert_eq!(r.kernel().open_sockets(), 1);
    let trace = super::ops(&mut r);
    assert!(
        !trace
            .iter()
            .any(|op| op.starts_with("socket ") || op.starts_with("register "))
    );
    assert!(!r.shutdown());
    run_for(&mut r, 1);
    assert!(r.shutdown());
    assert!(r.kernel_mut().tunnel(10).unwrap().is_none());
}

/// spec: P14, L13, P17
#[test]
fn malformed_names_and_shutdown_keep_cleanup_authority() {
    use std::os::unix::net::UnixStream;
    let (mut r, _) = reconciler();
    r.set_store_capacity(1);
    let (fd, _peer) = UnixStream::pair().unwrap();
    r.inherit("original-name".into(), fd.into());
    r.reconcile(Config::new());
    let id = withdrawal(r.take_requests(), "original-name");
    assert!(!r.shutdown());
    run_for(&mut r, 2);
    assert_eq!(r.kernel().open_sockets(), 0);
    assert_eq!(r.next_deadline(), None, "bounded final attempt");
    assert!(
        !r.shutdown(),
        "residual store reference reported as failure"
    );
    r.socket_forgotten(id, true); // expired, cannot claim cleanup
    assert!(!r.shutdown());
}

/// spec: L13, G23
#[test]
fn full_store_keeps_new_sockets_locally_owned() {
    let (mut r, _) = reconciler();
    r.set_store_capacity(1);
    r.reconcile(config(&format!(
        "{TUNNEL}\n[tunnels.b]\ntunnel_id=11\nremote_addr='192.0.2.3'"
    )));
    let requests = r.take_requests();
    assert_eq!(
        requests
            .iter()
            .filter(|r| matches!(r, Request::StoreSocket { .. }))
            .count(),
        1
    );
    assert!(r.ready());
    assert_eq!(r.kernel().open_sockets(), 2);
}

/// spec: S28, M17, L13, P14
#[test]
fn adopted_matching_sessions_keep_manager_names_and_are_never_reproved() {
    let (mut r, _) = reconciler();
    let socket = r.kernel_mut().create_socket(Family::V6, 10, 20).unwrap();
    r.kernel_mut().register_tunnel(socket, 10, 20).unwrap();
    let registration = r
        .kernel_mut()
        .create_session(&rs_l2tpd::kernel::SessionCreate::new(
            10,
            100,
            100,
            Some(rs_l2tpd::kernel::Cookie::new(&[0, 0x11, 0x22, 0x33]).unwrap()),
            Some(rs_l2tpd::kernel::Cookie::new(&[0, 0x11, 0x22, 0x33]).unwrap()),
            rs_l2tpd::kernel::L2tpIfName::new(b"rsl2tp-t112233").unwrap(),
        ))
        .unwrap();
    r.kernel_mut()
        .rename_link(registration.index(), "manager-name");
    let fd = r.kernel().clone_fd(socket).unwrap();
    r.kernel_mut().close(socket);
    r.inherit("t10".into(), fd);
    super::ops(&mut r);
    let text = format!(
        "{TUNNEL}\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'\ncookie='00112233'"
    );
    assert!(r.reconcile(config(&text)));
    assert!(r.ready());
    assert_eq!(
        r.kernel().session_index(10, 100),
        Some(registration.index())
    );
    assert_eq!(
        r.kernel()
            .link(registration.index())
            .unwrap()
            .name()
            .to_string_lossy(),
        "manager-name"
    );
    assert!(
        !super::ops(&mut r).iter().any(|op| op.starts_with("create ")
            || op.starts_with("rename ")
            || op.starts_with("hwaddr "))
    );
}

/// spec: S28, K18, K35
#[test]
fn unmatched_adopted_sessions_are_deleted_before_identifier_reuse() {
    let (mut r, _) = reconciler();
    let socket = r.kernel_mut().create_socket(Family::V6, 10, 20).unwrap();
    r.kernel_mut().register_tunnel(socket, 10, 20).unwrap();
    let old = r
        .kernel_mut()
        .foreign_session(rs_l2tpd::kernel::SessionInfo::new(
            10,
            100,
            0,
            rs_l2tpd::kernel::ReportedCookie::new(&[1, 2, 3, 4, 5]).unwrap(),
            None.into(),
            Some(rs_l2tpd::kernel::L2tpIfName::new(b"unmatched").unwrap()),
        ));
    let fd = r.kernel().clone_fd(socket).unwrap();
    r.kernel_mut().close(socket);
    r.inherit("t10".into(), fd);
    super::ops(&mut r);
    let text =
        format!("{TUNNEL}\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'");
    assert!(!r.reconcile(config(&text)));
    assert!(
        !super::ops(&mut r)
            .iter()
            .any(|op| op.starts_with("create "))
    );
    assert_eq!(r.kernel().session_index(10, 100), Some(old));
    run_for(&mut r, 1);
    assert!(r.ready());
    assert_ne!(r.kernel().session_index(10, 100), Some(old));
}
