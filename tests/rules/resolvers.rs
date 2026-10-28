//! Resolvers (docs/spec/resolvers.md) over the fake kernel.

use rs_l2tpd::reconciler::ResolverSpec;

use super::{config, ops, reconciler, run_for};

const NAMED: &str = r#"
[tunnels.a]
tunnel_id = 10
remote_addr = "peer.example"
ip_version = "V4"
"#;

/// A host name is looked up through the system resolver; the tunnel is
/// disconnected until an answer exists, then connected to it (V3, T14,
/// V8).
/// spec: V3, T14, V8, E10
#[test]
fn an_answer_connects_the_tunnel() {
    let (mut r, answers) = reconciler();
    let eth = r.kernel_mut().add_link("eth0", false);
    r.kernel_mut().add_addr(eth, "192.0.2.1".parse().unwrap());
    assert!(r.reconcile(config(NAMED)));
    assert!(r.ready());
    let watching = answers.watching();
    assert_eq!(watching.len(), 1);
    assert_eq!(watching[0].resolver, ResolverSpec::System);
    let socket = r.kernel().tunnel_socket(10).unwrap();
    assert_eq!(r.kernel().connection(socket), None);
    answers.answer("peer.example", &["2001:db8::1", "192.0.2.2"]);
    run_for(&mut r, 1);
    assert_eq!(
        r.kernel().connection(socket).map(|(p, _)| p),
        Some("192.0.2.2".parse().unwrap())
    );
}

/// The selected address stays while the answer holds it, whatever the
/// order; a failed or negative lookup keeps it in force (V5, V6).
/// spec: V5, V6
#[test]
fn the_selected_address_is_retained() {
    let (mut r, answers) = reconciler();
    let eth = r.kernel_mut().add_link("eth0", false);
    r.kernel_mut().add_addr(eth, "192.0.2.1".parse().unwrap());
    r.reconcile(config(NAMED));
    answers.answer("peer.example", &["192.0.2.2", "192.0.2.3"]);
    run_for(&mut r, 1);
    ops(&mut r);
    answers.answer("peer.example", &["192.0.2.3", "192.0.2.2"]);
    answers.answer("peer.example", &[]);
    run_for(&mut r, 1);
    assert_eq!(ops(&mut r), Vec::<String>::new());
    answers.answer("peer.example", &["192.0.2.4"]);
    run_for(&mut r, 1);
    assert!(ops(&mut r).iter().any(|o| o.ends_with("192.0.2.4")));
}

/// A changed host name discards the answers in force and looks up anew;
/// a late result of the old lookup is ignored (V7, E11).
/// spec: V7, E10, E11
#[test]
fn a_changed_host_name_discards_answers() {
    let (mut r, answers) = reconciler();
    let eth = r.kernel_mut().add_link("eth0", false);
    r.kernel_mut().add_addr(eth, "192.0.2.1".parse().unwrap());
    r.reconcile(config(NAMED));
    answers.answer("peer.example", &["192.0.2.2"]);
    run_for(&mut r, 1);
    let socket = r.kernel().tunnel_socket(10).unwrap();
    r.reconcile(config(&NAMED.replace("peer.example", "other.example")));
    assert_eq!(
        r.kernel().connection(socket),
        None,
        "no peer the configuration no longer names (T17)"
    );
    assert_eq!(answers.watching()[0].host, "other.example");
    run_for(&mut r, 1);
    assert_eq!(r.kernel().connection(socket), None);
}

/// A resolver whose bind device is a VRF waits and is retried every
/// thirty seconds; its tunnel stays accepted (V9, C16).
/// spec: V9, C16, M13
#[test]
fn a_vrf_bind_device_holds_the_resolver_back() {
    let (mut r, answers) = reconciler();
    let vrf = r.kernel_mut().add_link("wan0", true);
    let text = format!(
        "{NAMED}resolver_name = \"r\"\n[resolvers.r]\naddresses = [\"192.0.2.53\"]\nbind_interface = \"wan0\"\n"
    );
    assert!(r.reconcile(config(&text)));
    assert!(answers.watching().is_empty());
    r.kernel_mut().remove_link(vrf);
    r.kernel_mut().add_link("wan0", false);
    run_for(&mut r, 30);
    assert_eq!(answers.watching().len(), 1);
}
