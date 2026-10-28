//! Sessions (docs/spec/sessions.md) over the fake kernel.

use rs_l2tpd::kernel::fake::FakeKernel;
use rs_l2tpd::reconciler::Reconciler;

use super::{Answers, TUNNEL, config, deliver, ops, run_for};

/// A reconciler on a host with an address, so that the tunnel connects.
fn reconciler() -> (Reconciler<FakeKernel>, Answers) {
    let (mut r, answers) = super::reconciler();
    let device = r.kernel_mut().add_link("eth0", false);
    r.kernel_mut()
        .add_addr(device, "192.0.2.1".parse().unwrap());
    (r, answers)
}

fn with_session(extra: &str) -> String {
    format!(
        "{TUNNEL}\n[sessions.s]\ntunnel_name = \"a\"\nsession_id = 100\ninterface_name = \"l2tp0\"\n{extra}"
    )
}

/// A session is staged under an rsl2tp-t name, given its address while
/// down, then published under its configured name (S4, S8).
/// spec: S4, S8, S3, S12
#[test]
fn a_session_is_staged_then_published() {
    let (mut r, _) = reconciler();
    assert!(r.reconcile(config(&with_session(
        "interface_hwaddr = \"02:00:5e:00:53:01\"\n"
    ))));
    let ops = ops(&mut r);
    let create = ops.iter().find(|o| o.starts_with("create ")).unwrap();
    assert!(create.starts_with("create 10 100 rsl2tp-t"), "{create}");
    let index = r.kernel().session_index(10, 100).unwrap();
    let hw = ops.iter().position(|o| o.starts_with("hwaddr")).unwrap();
    let rename = ops
        .iter()
        .position(|o| o == &format!("rename {index} l2tp0"))
        .unwrap();
    assert!(hw < rename, "the address precedes publication: {ops:?}");
    assert_eq!(
        r.kernel().link(index).unwrap().name.to_string_lossy(),
        "l2tp0"
    );
    assert!(r.ready());
}

/// A configured name held by a foreign device is retried every second
/// with the session kept under its staging name (S7).
/// spec: S7, S6
#[test]
fn a_taken_name_is_retried_and_the_session_kept() {
    let (mut r, _) = reconciler();
    let foreign = r.kernel_mut().add_link("l2tp0", false);
    assert!(!r.reconcile(config(&with_session(""))));
    let index = r.kernel().session_index(10, 100).unwrap();
    run_for(&mut r, 2);
    assert_eq!(r.kernel().session_index(10, 100), Some(index));
    r.kernel_mut().remove_link(foreign);
    run_for(&mut r, 1);
    assert_eq!(
        r.kernel().link(index).unwrap().name.to_string_lossy(),
        "l2tp0"
    );
}

/// A new address for an up device is deferred, never by lowering it, and
/// applied once it is seen down (S12, E4, K31).
/// spec: S12, E4, S2
#[test]
fn a_hardware_address_waits_for_the_device_to_go_down() {
    let (mut r, _) = reconciler();
    r.reconcile(config(&with_session("")));
    let index = r.kernel().session_index(10, 100).unwrap();
    r.kernel_mut().set_up(index, true);
    deliver(&mut r);
    let addr = "02:00:5e:00:53:02";
    assert!(r.reconcile(config(&with_session(&format!(
        "interface_hwaddr = \"{addr}\"\n"
    )))));
    assert_ne!(r.kernel().hwaddr(index).unwrap().to_string(), addr);
    assert!(r.kernel().link(index).unwrap().up, "never lowered");
    r.kernel_mut().set_up(index, false);
    deliver(&mut r);
    assert_eq!(r.kernel().hwaddr(index).unwrap().to_string(), addr);
}

/// A rename by another manager is kept (S10, M19).
/// spec: S10, M19, E2
#[test]
fn another_managers_rename_is_kept() {
    let (mut r, _) = reconciler();
    r.reconcile(config(&with_session("")));
    let index = r.kernel().session_index(10, 100).unwrap();
    r.kernel_mut().rename_link(index, "lan7");
    deliver(&mut r);
    ops(&mut r);
    assert!(r.reconcile(config(&with_session(""))));
    assert_eq!(ops(&mut r), Vec::<String>::new());
    assert_eq!(
        r.kernel().link(index).unwrap().name.to_string_lossy(),
        "lan7"
    );
}

/// Two sessions exchange names through a temporary rsl2tp-r name (S11).
/// spec: S11, M6
#[test]
fn sessions_swap_names() {
    let (mut r, _) = reconciler();
    let two = |x: &str, y: &str| {
        format!(
            "{TUNNEL}\n[sessions.s]\ntunnel_name = \"a\"\nsession_id = 100\ninterface_name = \"{x}\"\n[sessions.t]\ntunnel_name = \"a\"\nsession_id = 101\ninterface_name = \"{y}\"\n"
        )
    };
    r.reconcile(config(&two("x0", "y0")));
    let (s, t) = (
        r.kernel().session_index(10, 100).unwrap(),
        r.kernel().session_index(10, 101).unwrap(),
    );
    ops(&mut r);
    assert!(r.reconcile(config(&two("y0", "x0"))));
    assert!(ops(&mut r).iter().any(|o| o.contains(" rsl2tp-r")));
    assert_eq!(r.kernel().link(s).unwrap().name.to_string_lossy(), "y0");
    assert_eq!(r.kernel().link(t).unwrap().name.to_string_lossy(), "x0");
}

/// A cookie change re-creates the session (S15, S17).
/// spec: S15, S17, M17
#[test]
fn a_cookie_change_recreates_the_session() {
    let (mut r, _) = reconciler();
    r.reconcile(config(&with_session("")));
    let old = r.kernel().session_index(10, 100).unwrap();
    r.reconcile(config(&with_session("cookie = \"0011223344556677\"\n")));
    run_for(&mut r, 2);
    let new = r.kernel().session_index(10, 100).unwrap();
    assert_ne!(old, new);
    assert!(r.ready());
}

/// An operator's deletion is announced, verified and the session created
/// again (S27, S29, E27).
/// spec: S27, S29, E27
#[test]
fn an_externally_deleted_session_is_created_again() {
    let (mut r, _) = reconciler();
    r.reconcile(config(&with_session("")));
    let old = r.kernel().session_index(10, 100).unwrap();
    r.kernel_mut().operator_delete_session(10, 100);
    deliver(&mut r);
    run_for(&mut r, 2);
    deliver(&mut r);
    let new = r.kernel().session_index(10, 100).unwrap();
    assert_ne!(old, new);
}

/// After the lifetime subscription lost notifications a published
/// session is unmanageable: a rename is skipped, nothing deleted (S20).
/// spec: S20, M18, S19
#[test]
fn a_lost_identity_skips_changes() {
    let (mut r, _) = reconciler();
    r.reconcile(config(&with_session("")));
    let index = r.kernel().session_index(10, 100).unwrap();
    r.kernel_mut().lose_lifetime();
    ops(&mut r);
    assert!(r.reconcile(config(&with_session("").replace("l2tp0", "l2tp1"))));
    assert_eq!(ops(&mut r), Vec::<String>::new());
    assert_eq!(
        r.kernel().link(index).unwrap().name.to_string_lossy(),
        "l2tp0"
    );
}
