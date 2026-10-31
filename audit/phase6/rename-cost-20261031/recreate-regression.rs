
/// spec: E27, S27, M3, M5, M16, G23
#[test]
fn a_session_deletion_retries_only_that_entry_before_the_global_retry() {
    let (mut r, _) = reconciler();
    let text = format!("{TUNNEL}\n[sessions.a]\ntunnel_name='a'\nsession_id=100\ninterface_name='n0'\n[sessions.b]\ntunnel_name='a'\nsession_id=101\ninterface_name='n1'\n");
    r.kernel_mut().fail_next("create", nix::errno::Errno::EIO);
    assert!(!r.reconcile(config(&text)));
    assert!(r.kernel().session_index(10, 100).is_none());
    let removed = r.kernel().session_index(10, 101).unwrap();
    r.kernel_mut().operator_delete_session(10, 101);
    r.kernel_mut().tick();
    ops(&mut r);
    r.handle(Source::L2tp, Notice::SessionDeleted { tunnel_id: 10, session_id: 101 });
    let replacement = r.kernel().session_index(10, 101).unwrap();
    assert_ne!(replacement, removed);
    assert!(r.kernel().session_index(10, 100).is_none(), "unrelated creation must wait for its own retry");
    assert!(!ops(&mut r).iter().any(|op| op.starts_with("create 10 100 ")));
    r.kernel_mut().advance(std::time::Duration::from_secs(1));
    r.tick();
    assert!(r.kernel().session_index(10, 100).is_some());
    assert_eq!(r.kernel().session_index(10, 101), Some(replacement));
}
