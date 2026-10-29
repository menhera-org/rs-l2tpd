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

/// spec: V7, V9, V11, V13, E20
#[test]
fn unchanged_discovery_survives_monitor_loss_and_invalid_replacements_stop_it() {
    use rs_l2tpd::kernel::Notice;
    use rs_l2tpd::reconciler::Source;
    let (mut r, answers) = reconciler();
    let wan = r.kernel_mut().add_link("wan", false);
    let text =
        format!("{NAMED}resolver_name='r'\n[resolvers.r]\nmethod='ra'\nbind_interface='wan'");
    r.reconcile(config(&text));
    let id = answers.watching()[0].id;
    r.handle(Source::Monitor, Notice::Loss);
    assert_eq!(answers.watching()[0].id, id, "unchanged discovery retained");
    r.kernel_mut().rename_link(wan, "old-wan");
    super::deliver(&mut r);
    assert!(answers.watching().is_empty(), "old-name dependency stopped");
    let vrf = r.kernel_mut().add_link("wan", true);
    super::deliver(&mut r);
    assert!(answers.watching().is_empty());
    r.kernel_mut().remove_link(vrf);
    r.kernel_mut().add_link("wan", false);
    super::deliver(&mut r);
    assert_ne!(answers.watching()[0].id, id);
}

/// spec: V9, C16, V13
#[test]
fn resolver_zones_require_a_non_vrf_matching_bind_link() {
    for with_bind in [false, true] {
        let (mut r, answers) = reconciler();
        let zone = r.kernel_mut().add_link("zone", true);
        let bind = r.kernel_mut().add_link("wan", false);
        let text = format!(
            "{NAMED}resolver_name='r'\n[resolvers.r]\naddresses=['[fe80::53%zone]:5353']\n{}",
            if with_bind {
                "bind_interface='wan'"
            } else {
                ""
            }
        );
        r.reconcile(config(&text));
        assert!(answers.watching().is_empty());
        r.kernel_mut().remove_link(zone);
        let zone = r.kernel_mut().add_link("zone", false);
        super::deliver(&mut r);
        assert_eq!(answers.watching().is_empty(), with_bind);
        if with_bind {
            r.kernel_mut().rename_link(bind, "old-wan");
            r.kernel_mut().rename_link(zone, "wan");
            r.kernel_mut().add_link_at(bind, "zone", false);
            super::deliver(&mut r);
            assert!(
                answers.watching().is_empty(),
                "different indexes still mismatch"
            );
        } else {
            let ResolverSpec::Static { servers, .. } = &answers.watching()[0].resolver else {
                panic!()
            };
            let std::net::SocketAddr::V6(server) = servers[0] else {
                panic!()
            };
            assert_eq!(server.scope_id(), zone);
        }
    }
}

/// spec: V12, V14, M14
#[test]
fn a_missing_default_duid_uses_ra_then_retries_and_keeps_its_identity() {
    let (mut r, answers) = reconciler();
    let wan = r.kernel_mut().add_link("wan", false);
    r.kernel_mut().clear_link_hwaddr(wan);
    let text =
        format!("{NAMED}resolver_name='r'\n[resolvers.r]\nmethod='ipv6'\nbind_interface='wan'");
    r.reconcile(config(&text));
    assert!(matches!(
        answers.watching()[0].resolver,
        ResolverSpec::Ra { .. }
    ));
    let mac = rs_l2tpd::kernel::HwAddr::new([2, 0, 0x5e, 0, 0x53, 1]).unwrap();
    r.kernel_mut().set_link_hwaddr(wan, mac);
    run_for(&mut r, 29);
    assert!(matches!(
        answers.watching()[0].resolver,
        ResolverSpec::Ra { .. }
    ));
    run_for(&mut r, 1);
    assert!(
        matches!(answers.watching()[0].resolver, ResolverSpec::Ipv6 { client_id: rs_l2tpd::reconciler::ClientId::DuidLl(addr), .. } if addr == mac.octets())
    );
    let id = answers.watching()[0].id;
    let changed = rs_l2tpd::kernel::HwAddr::new([2, 0, 0x5e, 0, 0x53, 2]).unwrap();
    r.kernel_mut().set_link_hwaddr(wan, changed);
    super::deliver(&mut r);
    assert_eq!(
        answers.watching()[0].id,
        id,
        "DUID held for discovery lifetime"
    );
}

/// spec: V7, E10, E11
#[test]
fn resolver_configuration_generations_discard_already_queued_answers() {
    let (mut r, answers) = reconciler();
    let dev = r.kernel_mut().add_link("wan", false);
    r.kernel_mut().add_addr(dev, "192.0.2.1".parse().unwrap());
    let text = format!("{NAMED}resolver_name='r'\n[resolvers.r]\naddresses=['192.0.2.53']");
    r.reconcile(config(&text));
    let old = answers.watching()[0].id;
    answers.answer("peer.example", &["192.0.2.2"]);
    r.reconcile(config(&text.replace("192.0.2.53", "192.0.2.54")));
    let socket = r.kernel().tunnel_socket(10).unwrap();
    assert_ne!(answers.watching()[0].id, old);
    run_for(&mut r, 1);
    assert!(r.kernel().connection(socket).is_none());
    answers.answer("peer.example", &["192.0.2.3"]);
    run_for(&mut r, 1);
    assert_eq!(
        r.kernel().connection(socket).unwrap().0.to_string(),
        "192.0.2.3"
    );
}

/// spec: T15, T17, V7, E10
#[test]
fn an_unreachable_new_answer_never_restores_the_previous_peer() {
    let (mut r, answers) = reconciler();
    let dev = r.kernel_mut().add_link("wan", false);
    r.kernel_mut().add_addr(dev, "192.0.2.1".parse().unwrap());
    r.reconcile(config(NAMED));
    answers.answer("peer.example", &["192.0.2.2"]);
    run_for(&mut r, 1);
    let socket = r.kernel().tunnel_socket(10).unwrap();
    let next = "192.0.2.3".parse().unwrap();
    r.kernel_mut()
        .refuse(next, Some(nix::errno::Errno::EHOSTUNREACH));
    answers.answer("peer.example", &["192.0.2.3"]);
    run_for(&mut r, 1);
    assert!(r.kernel().connection(socket).is_none());
    run_for(&mut r, 2);
    assert!(r.kernel().connection(socket).is_none());
    r.kernel_mut().refuse(next, None);
    run_for(&mut r, 1);
    assert_eq!(r.kernel().connection(socket).unwrap().0, next);
}
