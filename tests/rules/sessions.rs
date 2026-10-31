//! Sessions (docs/spec/sessions.md) over the fake kernel.

use rs_l2tpd::kernel::Kernel;
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
/// spec: S1, S4, S8, S3, S12, R19, A8, O9
#[test]
fn a_session_is_staged_then_published() {
    let text = with_session("interface_hwaddr = \"02:00:5e:00:53:01\"\n");
    let candidate = {
        let (mut probe, _) = reconciler();
        assert!(probe.reconcile(config(&text)));
        probe
            .kernel_mut()
            .session(10, 100)
            .unwrap()
            .unwrap()
            .ifname()
            .unwrap()
    };
    let (mut r, _) = reconciler();
    let foreign = r.kernel_mut().add_link(&candidate.to_string_lossy(), false);
    let foreign_before = r.kernel().link(foreign).unwrap().clone();
    assert!(r.reconcile(config(&text)));
    let ops = ops(&mut r);
    let create = ops.iter().find(|o| o.starts_with("create ")).unwrap();
    assert!(
        ops.iter().position(|o| o == "register 10").unwrap()
            < ops.iter().position(|o| o.starts_with("create ")).unwrap()
    );
    assert!(create.starts_with("create 10 100 rsl2tp-t"), "{create}");
    assert!(!create.ends_with(&candidate.to_string_lossy().to_string()));
    assert_eq!(r.kernel().link(foreign), Some(&foreign_before));
    let index = r.kernel().session_index(10, 100).unwrap();
    let hw = ops.iter().position(|o| o.starts_with("hwaddr")).unwrap();
    let rename = ops
        .iter()
        .position(|o| o == &format!("rename {index} l2tp0"))
        .unwrap();
    assert!(hw < rename, "the address precedes publication: {ops:?}");
    assert_eq!(
        r.kernel().link(index).unwrap().name().to_string_lossy(),
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
        r.kernel().link(index).unwrap().name().to_string_lossy(),
        "l2tp0"
    );
}

/// A new address for an up device is deferred, never by lowering it, and
/// applied once it is seen down (S12, E4, K31).
/// spec: S12, E4, S2, R23, R29
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
    assert!(r.kernel().link(index).unwrap().up(), "never lowered");
    r.kernel_mut().set_up(index, false);
    deliver(&mut r);
    assert_eq!(r.kernel().hwaddr(index).unwrap().to_string(), addr);
}

/// A rename by another manager is kept (S10, M19).
/// spec: S10, M19, E2, R28, A16
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
        r.kernel().link(index).unwrap().name().to_string_lossy(),
        "lan7"
    );
}

/// Two sessions exchange names through a temporary rsl2tp-r name (S11).
/// spec: S11, M6, R19, O9
#[test]
fn sessions_swap_names() {
    let two = |x: &str, y: &str| {
        format!(
            "{TUNNEL}\n[sessions.s]\ntunnel_name = \"a\"\nsession_id = 100\ninterface_name = \"{x}\"\n[sessions.t]\ntunnel_name = \"a\"\nsession_id = 101\ninterface_name = \"{y}\"\n"
        )
    };
    let candidate = {
        let (mut probe, _) = reconciler();
        assert!(probe.reconcile(config(&two("x0", "y0"))));
        ops(&mut probe);
        assert!(probe.reconcile(config(&two("y0", "x0"))));
        ops(&mut probe)
            .into_iter()
            .find_map(|op| {
                let name = op.split_whitespace().last()?;
                name.starts_with("rsl2tp-r").then(|| name.to_string())
            })
            .unwrap()
    };
    let (mut r, _) = reconciler();
    let foreign = r.kernel_mut().add_link(&candidate, false);
    let foreign_before = r.kernel().link(foreign).unwrap().clone();
    r.reconcile(config(&two("x0", "y0")));
    let (s, t) = (
        r.kernel().session_index(10, 100).unwrap(),
        r.kernel().session_index(10, 101).unwrap(),
    );
    ops(&mut r);
    assert!(r.reconcile(config(&two("y0", "x0"))));
    let operations = ops(&mut r);
    assert!(operations.iter().any(|o| o.contains(" rsl2tp-r")));
    assert!(
        !operations
            .iter()
            .any(|o| o.ends_with(&format!(" {candidate}")))
    );
    assert_eq!(r.kernel().link(foreign), Some(&foreign_before));
    assert_eq!(r.kernel().link(s).unwrap().name().to_string_lossy(), "y0");
    assert_eq!(r.kernel().link(t).unwrap().name().to_string_lossy(), "x0");
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
/// spec: S27, S29, E27, R18
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
        r.kernel().link(index).unwrap().name().to_string_lossy(),
        "l2tp0"
    );
}

/// spec: S23, S24, S22, M18, A16, A17
#[test]
fn staged_loss_never_modifies_a_reused_index_and_name() {
    for ambiguous in [false, true] {
        let (mut r, _) = reconciler();
        r.kernel_mut().add_link("l2tp0", false);
        r.reconcile(config(&with_session("")));
        let index = r.kernel().session_index(10, 100).unwrap();
        let temp = r.kernel().link(index).unwrap().name();
        r.kernel_mut().lose_lifetime();
        r.kernel_mut().remove_link(index);
        r.kernel_mut()
            .add_link_at(index, &temp.to_string_lossy(), false);
        if ambiguous {
            let mut info = r.kernel_mut().session(10, 100).unwrap().unwrap();
            info = info.with_tunnel_id(99).with_session_id(999);
            let foreign = r.kernel_mut().foreign_session(info);
            r.kernel_mut().rename_link(foreign, "foreign");
        }
        ops(&mut r);
        r.reconcile(config(&with_session(
            "interface_hwaddr = '02:00:5e:00:53:99'",
        )));
        let operations = ops(&mut r);
        assert!(
            !operations
                .iter()
                .any(|o| o.starts_with("rename ") || o.starts_with("hwaddr ")),
            "{operations:?}"
        );
        assert_eq!(r.kernel().link(index).unwrap().name(), temp);
        assert!(
            r.kernel_mut().session(10, 100).unwrap().is_some(),
            "absence not yet confirmed"
        );
        if ambiguous {
            run_for(&mut r, 3);
            assert!(r.kernel_mut().session(10, 100).unwrap().is_some());
            assert!(
                !ops(&mut r)
                    .iter()
                    .any(|o| o.starts_with("delete ") || o.starts_with("create "))
            );
        } else {
            r.kernel_mut().tick();
            r.reconcile(config(&with_session("")));
            assert!(r.kernel_mut().session(10, 100).unwrap().is_none());
            r.reconcile(config(&with_session("")));
            assert!(r.kernel_mut().session(10, 100).unwrap().is_some());
        }
    }
}

/// spec: S23, S22
#[test]
fn failed_staged_verification_and_deletion_preserve_the_record() {
    for operation in ["scan", "delete"] {
        let (mut r, _) = reconciler();
        r.kernel_mut().add_link("l2tp0", false);
        r.reconcile(config(&with_session("")));
        let index = r.kernel().session_index(10, 100).unwrap();
        r.kernel_mut().lose_lifetime();
        r.kernel_mut().fail_next(operation, nix::errno::Errno::EIO);
        ops(&mut r);
        r.reconcile(config(&with_session("")));
        assert_eq!(r.kernel().session_index(10, 100), Some(index));
        assert!(!ops(&mut r).iter().any(|op| op.starts_with("delete")));
        run_for(&mut r, 3);
        assert_ne!(r.kernel().session_index(10, 100), Some(index));
    }
}

/// spec: S22, S25, S26, A14
#[test]
fn failed_removal_preserves_the_session_and_its_parent_until_retry() {
    for (lost, operation) in [(false, "delete"), (true, "scan"), (true, "delete")] {
        let (mut r, _) = reconciler();
        r.reconcile(config(&with_session("")));
        let index = r.kernel().session_index(10, 100).unwrap();
        let socket = r.kernel().tunnel_socket(10).unwrap();
        if lost {
            r.kernel_mut().lose_lifetime();
        }
        r.kernel_mut().fail_next(operation, nix::errno::Errno::EIO);
        ops(&mut r);
        assert!(!r.reconcile(config(TUNNEL)));
        assert_eq!(r.kernel().session_index(10, 100), Some(index));
        assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
        assert!(!ops(&mut r).iter().any(|op| op.starts_with("close ")));
        run_for(&mut r, 3);
        assert!(r.kernel_mut().session(10, 100).unwrap().is_none());
        assert!(r.kernel_mut().tunnel(10).unwrap().is_some());
        assert!(r.ready());
    }
}

/// spec: S11, S17, M6, M14
#[test]
fn a_failed_temporary_rename_retries_the_swap_without_recreation() {
    for (operation, error) in [
        ("random", nix::errno::Errno::EIO),
        ("rename", nix::errno::Errno::EIO),
        ("rename", nix::errno::Errno::EEXIST),
    ] {
        let (mut r, _) = reconciler();
        let text = format!(
            "{}\n[sessions.t]\ntunnel_name='a'\nsession_id=101\ninterface_name='l2tp1'",
            with_session("")
        );
        assert!(r.reconcile(config(&text)));
        let first = r.kernel().session_index(10, 100).unwrap();
        let second = r.kernel().session_index(10, 101).unwrap();
        r.kernel_mut().fail_next(operation, error);
        ops(&mut r);
        r.reconcile(config(
            &text
                .replace("l2tp0", "swap")
                .replace("l2tp1", "l2tp0")
                .replace("swap", "l2tp1"),
        ));
        run_for(&mut r, 2);
        assert_eq!(r.kernel().session_index(10, 100), Some(first));
        assert_eq!(r.kernel().session_index(10, 101), Some(second));
        assert_eq!(
            r.kernel().link(first).unwrap().name().to_string_lossy(),
            "l2tp1"
        );
        assert_eq!(
            r.kernel().link(second).unwrap().name().to_string_lossy(),
            "l2tp0"
        );
        assert!(r.ready());
        assert!(
            !ops(&mut r)
                .iter()
                .any(|op| op.starts_with("create ") || op.starts_with("delete "))
        );
    }
}

/// spec: S4, S6, S12, M10, A12
#[test]
fn failed_staging_address_is_retried_before_publication() {
    let (mut r, _) = reconciler();
    r.kernel_mut().fail_next("hwaddr", nix::errno::Errno::EIO);
    r.reconcile(config(&with_session(
        "interface_hwaddr='02:00:5e:00:53:01'",
    )));
    let index = r.kernel().session_index(10, 100).unwrap();
    assert!(
        r.kernel()
            .link(index)
            .unwrap()
            .name()
            .to_string_lossy()
            .starts_with("rsl2tp-t")
    );
    let first = ops(&mut r);
    assert_eq!(
        first.iter().filter(|op| op.starts_with("create ")).count(),
        1
    );
    assert!(!first.iter().any(|op| op.starts_with("rename ")));
    run_for(&mut r, 1);
    assert_eq!(r.kernel().session_index(10, 100), Some(index));
    assert_eq!(
        r.kernel().link(index).unwrap().name().to_string_lossy(),
        "l2tp0"
    );
    assert_eq!(
        r.kernel().hwaddr(index).unwrap().to_string(),
        "02:00:5e:00:53:01"
    );
    assert!(!ops(&mut r).iter().any(|op| op.starts_with("create ")));
}

/// spec: S12, S13, M19
#[test]
fn removing_a_hardware_address_restores_the_creation_address_without_lowering() {
    let (mut r, _) = reconciler();
    r.reconcile(config(&with_session("")));
    let index = r.kernel().session_index(10, 100).unwrap();
    let original = r.kernel().hwaddr(index).unwrap();
    r.reconcile(config(&with_session(
        "interface_hwaddr='02:00:5e:00:53:99'",
    )));
    r.kernel_mut().set_up(index, true);
    deliver(&mut r);
    r.reconcile(config(&with_session("")));
    assert_ne!(r.kernel().hwaddr(index), Some(original));
    assert!(r.kernel().link(index).unwrap().up());
    r.kernel_mut().set_up(index, false);
    deliver(&mut r);
    assert_eq!(r.kernel().hwaddr(index), Some(original));
}

/// spec: S11, M6
#[test]
fn acyclic_and_cross_tunnel_rename_dependencies_converge_in_one_attempt() {
    let (mut r, _) = reconciler();
    let two = |x: &str, y: &str| {
        format!(
            "{TUNNEL}\n[tunnels.b]\ntunnel_id=11\nremote_addr='192.0.2.3'\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='{x}'\n[sessions.t]\ntunnel_name='b'\nsession_id=101\ninterface_name='{y}'"
        )
    };
    r.reconcile(config(&two("x", "y")));
    ops(&mut r);
    assert!(r.reconcile(config(&two("y", "z"))));
    assert!(!ops(&mut r).iter().any(|o| o.contains("rsl2tp-r")));
    assert!(r.reconcile(config(&two("z", "y"))));
    assert!(ops(&mut r).iter().any(|o| o.contains("rsl2tp-r")));
}

/// spec: S21, S24, M9, R11, R31
#[test]
fn a_moved_session_is_forgotten_without_deleting_a_replacement() {
    let (mut r, _) = reconciler();
    r.reconcile(config(&with_session("")));
    let index = r.kernel().session_index(10, 100).unwrap();
    r.kernel_mut().remove_link(index);
    r.kernel_mut().add_link_at(index, "l2tp0", false);
    deliver(&mut r);
    ops(&mut r);
    r.reconcile(config(TUNNEL));
    assert!(!ops(&mut r).iter().any(|o| o.starts_with("delete ")));
    assert!(r.kernel_mut().session(10, 100).unwrap().is_some());
    assert_eq!(
        r.kernel().link(index).unwrap().name().to_string_lossy(),
        "l2tp0"
    );
}

/// spec: S5, S12, S18, M19, R23, R29, R30, R36
#[test]
fn a_manager_can_raise_a_staged_device_and_keep_children_and_address_overrides() {
    let (mut r, _) = reconciler();
    r.kernel_mut().fail_next("hwaddr", nix::errno::Errno::EIO);
    let text = with_session("interface_hwaddr='02:00:5e:00:53:01'");
    r.reconcile(config(&text));
    let index = r.kernel().session_index(10, 100).unwrap();
    r.kernel_mut().set_up(index, true);
    let child = r.kernel_mut().add_link("child", false);
    r.kernel_mut().set_master(child, Some(index));
    let address = "2001:db8::1".parse().unwrap();
    r.kernel_mut().add_addr(child, address);
    assert!(r.reconcile(config(&text)));
    assert!(r.kernel().link(index).unwrap().up());
    assert_eq!(
        r.kernel().link(index).unwrap().name().to_string_lossy(),
        "l2tp0"
    );
    r.kernel_mut().set_up(index, false);
    deliver(&mut r);
    let override_addr = rs_l2tpd::kernel::HwAddr::new([2, 0, 0x5e, 0, 0x53, 9]).unwrap();
    r.kernel_mut().set_link_hwaddr(index, override_addr);
    deliver(&mut r);
    ops(&mut r);
    r.reconcile(config(
        &text
            .replace("l2tp0", "l2tp1")
            .replace("192.0.2.2", "192.0.2.3"),
    ));
    assert_eq!(r.kernel().hwaddr(index), Some(override_addr));
    assert_eq!(r.kernel().link(child).unwrap().master(), Some(index));
    assert!(
        r.kernel_mut()
            .dump_addrs()
            .unwrap()
            .iter()
            .any(|a| a.index() == child && a.addr() == address)
    );
    assert!(!ops(&mut r).iter().any(|op| op.starts_with("hwaddr ")));
}

/// spec: S15, S17, S25, S26, K18, M6
#[test]
fn session_identifier_reuse_waits_for_confirmed_deletion() {
    let (mut r, _) = reconciler();
    r.reconcile(config(&with_session("")));
    let index = r.kernel().session_index(10, 100).unwrap();
    ops(&mut r);
    r.reconcile(config(&with_session("peer_session_id=200")));
    let operations = ops(&mut r);
    assert_eq!(operations, ["delete 10 100"]);
    assert_eq!(r.kernel().session_index(10, 100), Some(index));
    r.kernel_mut().tick();
    run_for(&mut r, 1);
    assert_ne!(r.kernel().session_index(10, 100), Some(index));
    assert!(r.ready());
}

/// spec: S22, S23, S24, M18
#[test]
fn mismatched_stored_records_cannot_authorize_staged_recovery() {
    let (mut r, _) = reconciler();
    r.kernel_mut().add_link("l2tp0", false);
    r.reconcile(config(&with_session("")));
    let old = r.kernel().session_index(10, 100).unwrap();
    let temp = r.kernel().link(old).unwrap().name();
    r.kernel_mut().lose_lifetime();
    r.kernel_mut().remove_link(old);
    r.kernel_mut()
        .add_link_at(old, &temp.to_string_lossy(), false);
    let mut info = r.kernel_mut().session(10, 100).unwrap().unwrap();
    info = info
        .clone()
        .with_peer_session_id(info.peer_session_id() + 1);
    let foreign = r.kernel_mut().foreign_session(info);
    r.kernel_mut().rename_link(foreign, "foreign");
    ops(&mut r);
    r.reconcile(config(&with_session(
        "interface_hwaddr='02:00:5e:00:53:99'",
    )));
    run_for(&mut r, 3);
    assert!(ops(&mut r).is_empty());
    assert_eq!(r.kernel().link(old).unwrap().name(), temp);
    assert_eq!(
        r.kernel_mut()
            .session(10, 100)
            .unwrap()
            .unwrap()
            .peer_session_id(),
        101
    );
}

/// spec: M7, M8, S13, T16, C10
#[test]
fn tolerated_fields_use_a_disconnected_tunnel_and_the_kernel_address() {
    let (mut r, _) = reconciler();
    let text = with_session("interface_hwaddr='ff:ff:ff:ff:ff:ff'")
        .replace("192.0.2.2", "224.0.0.1")
        .replace("remote_addr", "ip_version='V4'\nremote_addr");
    let partial: rs_l2tpd::config::PartialConfig = toml::from_str(&text).unwrap();
    let (accepted, problems) = partial.into_config_lenient();
    assert!(problems.len() >= 2);
    assert!(r.reconcile(accepted));
    assert!(r.ready());
    assert!(!r.kernel().transmits(10));
    let index = r.kernel().session_index(10, 100).unwrap();
    assert!(r.kernel().hwaddr(index).is_some());
    assert!(!ops(&mut r).iter().any(|op| op.starts_with("hwaddr ")));
}

/// spec: S11, S17, M6, M16, G2, G4, G23
#[test]
fn long_reverse_chains_and_cycles_preserve_devices_in_one_reconcile() {
    for count in [1, 100, 300] {
        for cycle in [false, true] {
            let document = |changed: bool| {
                let mut text = TUNNEL.to_owned();
                for n in 0..count {
                    let target = if !changed {
                        n
                    } else if cycle {
                        (n + 1) % count
                    } else {
                        n + 1
                    };
                    text += &format!(
                        "\n[sessions.s{n:04}]\ntunnel_name='a'\nsession_id={}\ninterface_name='n{target}'\n",
                        1000 + n
                    );
                }
                config(&text)
            };
            let (mut r, _) = reconciler();
            assert!(r.reconcile(document(false)));
            let before: Vec<_> = (0..count)
                .map(|n| r.kernel().session_index(10, 1000 + n).unwrap())
                .collect();
            ops(&mut r);
            let changed = document(true);
            let started = std::time::Instant::now();
            assert!(r.reconcile(changed));
            let elapsed = started.elapsed();
            let changes = ops(&mut r);
            assert!(!changes.iter().any(|op| op.starts_with("create ")
                || op.starts_with("delete ")
                || op.starts_with("close ")));
            if !cycle {
                assert!(!changes.iter().any(|op| op.contains("rsl2tp-r")));
            }
            for (n, device) in before.into_iter().enumerate() {
                let n = u32::try_from(n).unwrap();
                let target = if cycle { (n + 1) % count } else { n + 1 };
                assert_eq!(r.kernel().session_index(10, 1000 + n), Some(device));
                assert_eq!(
                    r.kernel().link(device).unwrap().name().to_string_lossy(),
                    format!("n{target}")
                );
            }
            println!(
                "RENAME_COST sessions={count} cycle={cycle} elapsed_ns={} renames={}",
                elapsed.as_nanos(),
                changes
                    .iter()
                    .filter(|op| op.starts_with("rename "))
                    .count()
            );
        }
    }
}
