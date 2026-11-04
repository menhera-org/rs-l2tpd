//! Inventory authority, dependency retention and resource bounds.
use super::*;
use crate::kernel::fake::FakeKernel;
use crate::reconciler::{Lookup, Resolve};
use std::sync::{Arc, Mutex};

/// spec: E6, E7, M16, G12
#[test]
fn a_private_stale_device_index_does_not_reconnect_an_unbound_tunnel_on_address_addition() {
    let mut kernel = FakeKernel::new(42);
    let device = kernel.add_link("wan", false);
    let source = "192.0.2.1".parse().unwrap();
    kernel.add_addr(device, source);
    let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
    let config = toml::from_str(
        "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'",
    )
    .unwrap();
    assert!(r.reconcile(config));
    let socket = r.k.tunnel_socket(10).unwrap();
    let original = r.k.connection(socket);
    assert_eq!(original.as_ref().map(|(_, address)| *address), Some(source));
    assert!(r.tunnels[&10].bound.is_none());
    assert!(r.tunnels[&10].bind_index.is_none() && r.tunnels[&10].zone_index.is_none());
    // Only this private fixture installs a dependency absent from the record.
    r.index.devices.entry(device).or_default().insert(10);
    r.address_devices.insert(device);
    assert!(!r.addresses.contains_key(&device));
    r.k.clear_ops();
    r.handle(
        Source::Monitor,
        Notice::AddrNew(AddrInfo::new(device, source)),
    );
    assert!(r.k.ops().is_empty());
    assert_eq!(r.k.connection(socket), original);
    assert_eq!(r.k.tunnel_socket(10), Some(socket));
}

/// spec: A10, A14, G2, G23
#[test]
fn removing_a_stale_session_reverse_index_preserves_its_new_owner() {
    let mut r = Reconciler::new(
        FakeKernel::new(42),
        Box::new(crate::reconciler::IphostResolve::default()),
    );
    r.index.registrations.insert(100, 7);
    r.index.sessions.insert(7, 101);
    r.k.clear_ops();
    r.unindex_session(100);
    assert!(!r.index.registrations.contains_key(&100));
    assert_eq!(r.index.sessions.get(&7), Some(&101));
    r.unindex_session(100);
    assert_eq!(r.index.sessions.get(&7), Some(&101));
    assert!(r.k.ops().is_empty());
}

#[derive(Clone, Default)]
struct Watches(Arc<Mutex<BTreeSet<u64>>>);
impl Resolve for Watches {
    fn watch(&mut self, lookup: Lookup) -> std::io::Result<()> {
        assert!(self.0.lock().unwrap().insert(lookup.id()));
        Ok(())
    }
    fn unwatch(&mut self, id: u64) {
        self.0.lock().unwrap().remove(&id);
    }
    fn poll(&mut self) -> Vec<(u64, Vec<IpAddr>)> {
        Vec::new()
    }
}

fn drain(r: &mut Reconciler<FakeKernel>) {
    loop {
        let monitor = r.k.take_monitor();
        let l2tp = r.k.take_l2tp();
        if monitor.is_empty() && l2tp.is_empty() {
            break;
        }
        for notice in monitor {
            r.handle(Source::Monitor, notice);
        }
        for notice in l2tp {
            r.handle(Source::L2tp, notice);
        }
    }
    assert!(r.take_requests().is_empty());
}

fn sizes(r: &Reconciler<FakeKernel>) -> [usize; 32] {
    [
        r.wanted_tunnels.len(),
        r.wanted_sessions.len(),
        r.tunnels.len(),
        r.sessions.len(),
        r.reserved.len(),
        r.departing.len(),
        r.deleting_sessions.len(),
        r.unmatched_sessions.len(),
        r.verify_sessions.len(),
        r.verify_tunnels.len(),
        r.conflicts.len(),
        r.conflict_times.len(),
        r.retries.len(),
        r.requests.len(),
        r.request_names.len(),
        r.vrfs.len(),
        r.masters.len(),
        r.members.len(),
        r.members.values().map(BTreeSet::len).sum(),
        r.changed_devices.len(),
        r.changed_bindings.len(),
        r.address_devices.len(),
        r.addresses.len(),
        r.addresses.values().map(BTreeSet::len).sum(),
        r.index.names.len(),
        r.index.names.values().map(BTreeSet::len).sum(),
        r.index.devices.len(),
        r.index.devices.values().map(BTreeSet::len).sum(),
        r.index.sources.len(),
        r.index.sources.values().map(BTreeSet::len).sum(),
        r.index.sessions.len(),
        r.index.registrations.len(),
    ]
}

/// spec: S4, S27, G4, G23
#[test]
fn confirmed_absence_releases_only_the_matching_creation_reservation() {
    let mut r = Reconciler::new(FakeKernel::new(42), Box::new(Watches::default()));
    let own = L2tpIfName::new(b"own").unwrap();
    let other_tunnel = L2tpIfName::new(b"other-tunnel").unwrap();
    let other_session = L2tpIfName::new(b"other-session").unwrap();
    r.reserved.insert(own, (10, 100));
    r.reserved.insert(other_tunnel, (11, 100));
    r.reserved.insert(other_session, (10, 101));
    r.recreate_session(100, Some((other_tunnel, 10)));
    r.recreate_session(100, Some((other_session, 10)));
    r.recreate_session(100, None);
    assert_eq!(r.reserved.len(), 3);
    r.recreate_session(100, Some((own, 10)));
    assert_eq!(r.reserved.len(), 2);
    assert_eq!(r.reserved[&other_tunnel], (11, 100));
    assert_eq!(r.reserved[&other_session], (10, 101));
    assert!(r.k.ops().is_empty());
}

/// spec: G23, M16, V7, S25, T8
#[test]
fn completed_configuration_history_releases_records_indexes_and_watches() {
    let _socket_workload = crate::reconciler::tests::socket_workload();
    let watches = Watches::default();
    let mut kernel = FakeKernel::new(42);
    let base = kernel.add_link("base0", false);
    kernel.add_addr(base, "192.0.2.1".parse().unwrap());
    let base_text = "[host]\nfix_bindv6only=false\n[tunnels.base]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='base0'\n[sessions.base]\ntunnel_name='base'\nsession_id=100\ninterface_name='survivor'\n";
    let baseline: crate::config::Config = toml::from_str(base_text).unwrap();
    let mut r = Reconciler::new(kernel, Box::new(watches.clone()));
    assert!(r.reconcile(baseline.clone()));
    drain(&mut r);
    let survivor = r.k.session_index(10, 100).unwrap();
    let expected = sizes(&r);
    for (epoch, count) in [1, 100, 300, 300, 100, 1, 300, 1].into_iter().enumerate() {
        let mut text = base_text.to_owned();
        let mut devices = Vec::new();
        for n in 0..count {
            let id = 1000 + epoch * 1000 + n;
            let name = format!("wan{epoch}_{n}");
            let device = r.k.add_link(&name, false);
            r.k.add_addr(device, "192.0.2.1".parse().unwrap());
            devices.push(device);
            text += &format!(
                "[tunnels.t{id}]\ntunnel_id={id}\nip_version='V4'\nremote_addr='history.example'\nbind_interface='{name}'\n[sessions.s{id}]\ntunnel_name='t{id}'\nsession_id={}\ninterface_name='s{id}'\n",
                id + 100_000
            );
        }
        assert!(r.reconcile(toml::from_str(&text).unwrap()));
        drain(&mut r);
        assert_eq!(r.tunnels.len(), count + 1);
        assert_eq!(r.sessions.len(), count + 1);
        assert_eq!(watches.0.lock().unwrap().len(), count);
        r.reconcile(baseline.clone());
        for _ in 0..3 {
            r.k.advance(std::time::Duration::from_secs(1));
            r.k.tick();
            drain(&mut r);
            r.tick();
        }
        for device in devices {
            r.k.remove_link(device);
        }
        drain(&mut r);
        assert_eq!(sizes(&r), expected, "retained state after epoch {epoch}");
        assert_eq!(r.accepted(), &baseline);
        assert!(watches.0.lock().unwrap().is_empty());
        assert!(!r.resolvers.any());
        assert_eq!(r.next_deadline(), None);
        assert_eq!(r.k.session_index(10, 100), Some(survivor));
        assert!(r.ready());
        r.k.clear_ops();
        println!("RESOURCE_HISTORY epoch={epoch} removed={count} survivors=1 sizes={expected:?}");
    }
}
/// spec: G23, M16, E4, E20
#[test]
fn current_dependency_inventories_stream_and_release_their_final_reference() {
    for count in [1, 100, 10_000] {
        for vrf in [false, true] {
            let mut kernel = FakeKernel::new(42);
            let members: Vec<_> = (0..count)
                .map(|n| kernel.add_link(&format!("member{n}"), false))
                .collect();
            let wanted = kernel.add_link("wanted", vrf);
            let unrelated = kernel.add_link("unrelated", true);
            for (n, member) in members.iter().copied().enumerate() {
                let addr = IpAddr::from([10, 0, (n >> 8) as u8, n as u8]);
                if vrf {
                    kernel.set_master(member, Some(wanted));
                    kernel.add_addr(member, addr);
                } else {
                    kernel.add_addr(wanted, addr);
                }
                let noise = kernel.add_link(&format!("noise{n}"), false);
                kernel.set_master(noise, Some(unrelated));
                kernel.add_addr(noise, IpAddr::from([198, 19, (n >> 8) as u8, n as u8]));
            }
            kernel.take_monitor();
            let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
            let config = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='wanted'\n";
            assert!(r.reconcile(toml::from_str(config).unwrap()));
            assert_eq!(r.tunnels.len(), 1);
            assert_eq!(r.masters.len(), if vrf { count } else { 0 });
            assert_eq!(
                r.addresses.values().map(BTreeSet::len).sum::<usize>(),
                count
            );
            assert!(!r.vrfs.contains_key(&unrelated));
            let expected = sizes(&r);
            r.handle(Source::Monitor, Notice::Loss);
            assert!(!r.monitor_pending);
            assert_eq!(sizes(&r), expected);
            assert!(!r.addresses.contains_key(&unrelated));
            assert!(r.reconcile(toml::from_str("[host]\nfix_bindv6only=false\n").unwrap()));
            for _ in 0..3 {
                r.k.advance(std::time::Duration::from_secs(1));
                r.k.tick();
                r.tick();
            }
            assert_eq!(sizes(&r), [0; 32], "count={count}, vrf={vrf}");
            assert_eq!(r.next_deadline(), None);
        }
    }
}

/// spec: G23, M16, E4, E20, T10
#[test]
fn bound_member_resync_retains_its_parent_without_sibling_state() {
    for count in [1, 100, 10_000] {
        for vrf in [false, true] {
            let mut kernel = FakeKernel::new(42);
            let member = kernel.add_link("wanted", false);
            let parent = kernel.add_link("parent", vrf);
            kernel.set_master(member, Some(parent));
            let address = "192.0.2.1".parse().unwrap();
            kernel.add_addr(member, address);
            for n in 0..count {
                let sibling = kernel.add_link(&format!("sibling{n}"), false);
                kernel.set_master(sibling, Some(parent));
                kernel.add_addr(sibling, IpAddr::from([198, 19, (n >> 8) as u8, n as u8]));
            }
            kernel.take_monitor();
            let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
            let config = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='wanted'\n";
            assert!(r.reconcile(toml::from_str(config).unwrap()));
            let socket = r.tunnels[&10].socket;
            for resync in [false, true] {
                if resync {
                    r.handle(Source::Monitor, Notice::Loss);
                }
                assert!(!r.monitor_pending);
                assert_eq!(r.masters, BTreeMap::from([(member, parent)]));
                assert_eq!(
                    r.members,
                    BTreeMap::from([(parent, BTreeSet::from([member]))])
                );
                assert_eq!(
                    r.vrfs,
                    if vrf {
                        BTreeMap::from([(parent, false)])
                    } else {
                        BTreeMap::new()
                    }
                );
                assert_eq!(r.address_devices, BTreeSet::from([member]));
                assert_eq!(
                    r.addresses,
                    BTreeMap::from([(member, BTreeSet::from([address]))])
                );
                assert_eq!(r.tunnels[&10].socket, socket);
                assert_eq!(
                    r.k.connection(socket).map(|(_, source)| source),
                    Some(address)
                );
                assert_eq!(r.tunnels[&10].bound, Some(member));
            }
            assert!(r.reconcile(toml::from_str("[host]\nfix_bindv6only=false\n").unwrap()));
            for _ in 0..3 {
                r.k.advance(std::time::Duration::from_secs(1));
                r.k.tick();
                r.tick();
            }
            assert_eq!(sizes(&r), [0; 32], "siblings={count}, vrf={vrf}");
            assert_eq!(r.next_deadline(), None);
        }
    }
}

/// spec: G23, M3, E20, E22
#[test]
fn failed_inventory_completion_never_commits_visited_partial_state() {
    for completed in [0, 1, 2, 3, 4] {
        let mut kernel = FakeKernel::new(42);
        let member = kernel.add_link("member", false);
        let wanted = kernel.add_link("wanted", true);
        kernel.set_master(member, Some(wanted));
        kernel.add_addr(member, "192.0.2.1".parse().unwrap());
        let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
        let config = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='wanted'\n";
        if completed == 0 {
            r.k.fail_after("dump-end", 1, nix::errno::Errno::EIO);
            assert!(!r.reconcile(toml::from_str(config).unwrap()));
            assert!(r.masters.is_empty());
            assert!(r.vrfs.is_empty());
            assert!(r.addresses.is_empty());
            r.k.advance(std::time::Duration::from_secs(1));
            r.tick();
        }
        assert!(r.reconcile(toml::from_str(config).unwrap()));
        r.k.take_monitor();
        let old = (
            r.masters.clone(),
            r.members.clone(),
            r.vrfs.clone(),
            r.addresses.clone(),
            r.address_devices.clone(),
        );
        let added = r.k.add_link("added", false);
        r.k.set_master(added, Some(wanted));
        let address = "192.0.2.2".parse().unwrap();
        r.k.add_addr(added, address);
        r.k.fail_after("dump-end", completed, nix::errno::Errno::EIO);
        r.handle(Source::Monitor, Notice::Loss);
        assert!(r.monitor_pending);
        if completed < 2 {
            assert_eq!(
                (
                    r.masters.clone(),
                    r.members.clone(),
                    r.vrfs.clone(),
                    r.addresses.clone(),
                    r.address_devices.clone()
                ),
                old,
                "failed link pass {completed}",
            );
        } else {
            assert_eq!(r.masters.get(&added), Some(&wanted));
            assert!(r.addresses.is_empty());
            assert!(r.address_devices.is_empty());
        }
        r.k.advance(std::time::Duration::from_secs(1));
        r.tick();
        assert!(!r.monitor_pending);
        assert_eq!(r.masters.get(&added), Some(&wanted));
        assert!(r.addresses[&added].contains(&address));
        assert_eq!(r.addresses.values().map(BTreeSet::len).sum::<usize>(), 2);
        assert_eq!(r.next_deadline(), None);
    }
}

/// spec: E4, M16, G23, T21
#[test]
fn a_new_vrf_inventory_preserves_the_previous_master_until_its_ordered_change() {
    let mut kernel = FakeKernel::new(42);
    let blue = kernel.add_link("blue", true);
    let member = kernel.add_link("member", false);
    kernel.set_up(blue, true);
    kernel.set_up(member, true);
    kernel.set_master(member, Some(blue));
    let source = "2001:db8:1::1".parse().unwrap();
    kernel.add_addr(member, source);
    let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
    let config = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='2001:db8:1::2'\nbind_interface='blue'\n[tunnels.b]\ntunnel_id=20\nremote_addr='2001:db8:1::2'\nbind_interface='red'\n";
    r.reconcile(toml::from_str(config).unwrap());
    r.k.take_monitor();
    assert_eq!(r.masters.get(&member), Some(&blue));
    let red = r.k.add_link("red", true);
    r.k.set_up(red, true);
    r.k.set_master(member, Some(red));
    let link = r.k.link_by_index(red).unwrap().unwrap();
    assert!(!r.vrfs.contains_key(&red));
    r.handle(Source::Monitor, Notice::LinkNew(link));
    assert_eq!(r.masters.get(&member), Some(&blue));
    let member_event = r.k.link_by_index(member).unwrap().unwrap();
    r.handle(Source::Monitor, Notice::LinkNew(member_event));
    assert_eq!(r.masters.get(&member), Some(&red));
    assert!(!r.members.contains_key(&blue));
    assert_eq!(r.members.get(&red), Some(&BTreeSet::from([member])));
    assert!(r.addresses[&member].contains(&source));
    assert!(r.k.connection(r.tunnels[&10].socket).is_none());
    assert_eq!(
        r.k.connection(r.tunnels[&20].socket)
            .map(|(_, source)| source),
        Some(source)
    );
}

/// spec: E4, M16, G23, T21
#[test]
fn binding_a_known_parent_vrf_inventories_its_previously_unwatched_members() {
    let mut kernel = FakeKernel::new(42);
    let vrf = kernel.add_link("blue", true);
    let first = kernel.add_link("member", false);
    let sibling = kernel.add_link("sibling", false);
    for index in [vrf, first, sibling] {
        kernel.set_up(index, true);
    }
    kernel.set_master(first, Some(vrf));
    kernel.set_master(sibling, Some(vrf));
    kernel.add_addr(first, "2001:db8:1::1".parse().unwrap());
    let address = "2001:db8:1::3".parse().unwrap();
    kernel.add_addr(sibling, address);
    let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
    let one = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='2001:db8:1::2'\nbind_interface='member'\n";
    r.reconcile(toml::from_str(one).unwrap());
    assert!(r.vrfs.contains_key(&vrf));
    assert_eq!(r.members.get(&vrf), Some(&BTreeSet::from([first])));
    let both = format!(
        "{one}[tunnels.b]\ntunnel_id=20\nremote_addr='2001:db8:1::2'\nbind_interface='blue'\n"
    );
    r.reconcile(toml::from_str(&both).unwrap());
    assert_eq!(r.members.get(&vrf), Some(&BTreeSet::from([first, sibling])));
    assert!(r.addresses[&sibling].contains(&address));
    assert_eq!(r.vrfs.get(&vrf), Some(&true));
    assert!(r.reconcile(toml::from_str(one).unwrap()));
    assert_eq!(r.vrfs.get(&vrf), Some(&false));
    assert_eq!(r.members.get(&vrf), Some(&BTreeSet::from([first])));
    assert!(!r.addresses.contains_key(&sibling));
    r.k.fail_next("dump", nix::errno::Errno::EIO);
    let parent_event = r.k.link_by_index(vrf).unwrap().unwrap();
    r.handle(Source::Monitor, Notice::LinkNew(parent_event));
    assert!(
        !r.monitor_pending,
        "an unbound parent must not inventory siblings"
    );
    let parent = r.k.link_by_index(vrf).unwrap().unwrap();
    assert_eq!(
        r.remember_device(&parent, true).unwrap_err().raw_os_error(),
        Some(nix::libc::EIO)
    );
    assert_eq!(r.vrfs.get(&vrf), Some(&false));
    assert_eq!(r.members.get(&vrf), Some(&BTreeSet::from([first])));
    let rebound = both.replace("tunnel_id=20", "tunnel_id=30");
    assert!(r.reconcile(toml::from_str(&rebound).unwrap()));
    assert_eq!(r.vrfs.get(&vrf), Some(&true));
    assert_eq!(r.members.get(&vrf), Some(&BTreeSet::from([first, sibling])));
    assert!(r.addresses[&sibling].contains(&address));
    assert!(r.k.connection(r.tunnels[&30].socket).is_some());
    r.k.take_monitor();
    r.k.clear_ops();
    r.k.add_addr(sibling, "2001:db8:1::4".parse().unwrap());
    let notices = r.k.take_monitor();
    assert_eq!(notices.len(), 1);
    for notice in notices {
        r.handle(Source::Monitor, notice);
    }
    assert_eq!(
        r.k.ops()
            .iter()
            .filter(|op| op.starts_with("disconnect "))
            .count(),
        1
    );
    assert_eq!(
        r.k.ops()
            .iter()
            .filter(|op| op.starts_with("connect "))
            .count(),
        1
    );
}
/// spec: E3, E4, T13, G12, G17, M16
#[test]
fn removing_a_vrf_member_reconnects_only_an_already_connected_tunnel() {
    for connected in [false, true] {
        let mut kernel = FakeKernel::new(42);
        let parent = kernel.add_link("red", true);
        let member = kernel.add_link("member", false);
        kernel.set_master(member, Some(parent));
        kernel.add_addr(member, "192.0.2.1".parse().unwrap());
        let peer = "192.0.2.2".parse().unwrap();
        if !connected {
            kernel.refuse(peer, Some(nix::errno::Errno::ENETUNREACH));
        }
        let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
        let text = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='red'\n";
        assert!(r.reconcile(toml::from_str(text).unwrap()));
        drain(&mut r);
        let socket = r.k.tunnel_socket(10).unwrap();
        let deadline = r.next_deadline();
        r.k.clear_ops();
        r.k.remove_link(member);
        drain(&mut r);
        assert_eq!(r.k.tunnel_socket(10), Some(socket));
        assert_eq!(
            r.k.ops()
                .iter()
                .filter(|op| op.starts_with("connect "))
                .count(),
            usize::from(connected),
            "connected={connected}: {:?}",
            r.k.ops(),
        );
        assert_eq!(r.k.connection(socket), None);
        if !connected {
            assert!(r.k.ops().is_empty(), "{:?}", r.k.ops());
            assert_eq!(r.next_deadline(), deadline);
        }
    }
}

/// spec: E6, E7, T10, T27, G12, G17, M16
#[test]
fn member_addresses_affect_only_the_matching_family_and_vrf_domain() {
    for vrf in [false, true] {
        for same_family in [false, true] {
            let mut kernel = FakeKernel::new(42);
            let parent = kernel.add_link("parent", vrf);
            let member = kernel.add_link("member", false);
            kernel.set_master(member, Some(parent));
            kernel.add_addr(parent, "192.0.2.1".parse().unwrap());
            kernel.add_addr(member, "192.0.2.3".parse().unwrap());
            let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
            let text = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='parent'\n[tunnels.b]\ntunnel_id=11\nremote_addr='192.0.2.4'\nbind_interface='member'\n";
            assert!(r.reconcile(toml::from_str(text).unwrap()));
            drain(&mut r);
            let parent_socket = r.k.tunnel_socket(10).unwrap();
            let member_socket = r.k.tunnel_socket(11).unwrap();
            r.k.clear_ops();
            let address = if same_family {
                "192.0.2.5"
            } else {
                "2001:db8::5"
            };
            r.k.add_addr(member, address.parse().unwrap());
            drain(&mut r);
            for (tid, socket, reconnect) in [
                (10, parent_socket, same_family && vrf),
                (11, member_socket, same_family),
            ] {
                assert_eq!(r.k.tunnel_socket(tid), Some(socket));
                assert_eq!(
                    r.k.ops()
                        .iter()
                        .filter(|op| { op.starts_with(&format!("connect {} ", socket.0)) })
                        .count(),
                    usize::from(reconnect),
                    "vrf={vrf}, same_family={same_family}: {:?}",
                    r.k.ops(),
                );
            }
            assert!(!r.k.ops().iter().any(|op| op.starts_with("close ")));
        }
    }
}

/// spec: E3, E4, T10, T13, G12, G17, M16
#[test]
fn removing_a_member_distinguishes_direct_and_parent_bindings() {
    let mut kernel = FakeKernel::new(42);
    let parent = kernel.add_link("red", true);
    let member = kernel.add_link("member", false);
    kernel.set_master(member, Some(parent));
    kernel.add_addr(member, "192.0.2.1".parse().unwrap());
    let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
    let text = "[host]\nfix_bindv6only=false\n[tunnels.parent]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='red'\n[tunnels.member]\ntunnel_id=11\nremote_addr='192.0.2.3'\nbind_interface='member'\n";
    assert!(r.reconcile(toml::from_str(text).unwrap()));
    drain(&mut r);
    let sockets = [
        r.k.tunnel_socket(10).unwrap(),
        r.k.tunnel_socket(11).unwrap(),
    ];
    assert!(
        sockets
            .iter()
            .all(|socket| r.k.connection(*socket).is_some())
    );
    r.k.clear_ops();
    r.k.remove_link(member);
    drain(&mut r);
    for (tid, socket, attempts) in [(10, sockets[0], 1), (11, sockets[1], 0)] {
        assert_eq!(r.k.tunnel_socket(tid), Some(socket));
        assert_eq!(r.k.connection(socket), None);
        assert_eq!(
            r.k.ops()
                .iter()
                .filter(|op| op.starts_with(&format!("connect {} ", socket.0)))
                .count(),
            attempts,
            "{:?}",
            r.k.ops()
        );
    }
    assert_eq!(r.k.binding(sockets[0]), Some(parent));
    assert_eq!(r.k.binding(sockets[1]), None);
    assert!(!r.masters.contains_key(&member));
    assert!(!r.address_devices.contains(&member));
    assert!(!r.k.ops().iter().any(|op| op.starts_with("close ")));
}

/// spec: E6, E7, T10, T28, G12, M16
#[test]
fn removing_a_duplicate_source_on_an_unrelated_device_preserves_bound_tunnels() {
    for (source, peer, zone) in [
        ("192.0.2.1", "192.0.2.2", false),
        ("2001:db8::1", "2001:db8::2", false),
        ("fe80::1", "fe80::2%wanted", true),
    ] {
        let source: IpAddr = source.parse().unwrap();
        let mut kernel = FakeKernel::new(42);
        let wanted = kernel.add_link("wanted", false);
        let unrelated = kernel.add_link("unrelated", false);
        kernel.add_addr(wanted, source);
        kernel.add_addr(unrelated, source);
        let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
        let binding = if zone {
            ""
        } else {
            "bind_interface='wanted'\n"
        };
        let text = format!(
            "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='{peer}'\n{binding}"
        );
        assert!(r.reconcile(toml::from_str(&text).unwrap()));
        drain(&mut r);
        let socket = r.k.tunnel_socket(10).unwrap();
        let connection = r.k.connection(socket).unwrap();
        assert_eq!(connection.1, source);
        let deadline = r.next_deadline();
        r.k.clear_ops();
        r.k.del_addr(unrelated, source);
        drain(&mut r);
        assert_eq!(r.k.connection(socket), Some(connection));
        assert_eq!(r.k.binding(socket), Some(wanted));
        assert_eq!(r.next_deadline(), deadline);
        assert!(r.k.ops().is_empty(), "peer={peer}: {:?}", r.k.ops());
    }
}

/// spec: T21, T22, T27, V5, G4, M17
#[test]
fn a_pending_hostname_clears_the_previous_literal_zone_without_replacing_its_socket() {
    let mut kernel = FakeKernel::new(42);
    let zone = kernel.add_link("zone", false);
    kernel.add_addr(zone, "fe80::1".parse().unwrap());
    let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
    let text = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nip_version='V6'\nremote_addr='fe80::2%zone'\nbind_interface='zone'\n";
    assert!(r.reconcile(toml::from_str(text).unwrap()));
    drain(&mut r);
    let socket = r.k.tunnel_socket(10).unwrap();
    assert!(r.k.connection(socket).is_some());
    assert_eq!(r.tunnels[&10].zone_index, Some(zone));
    r.k.clear_ops();
    assert!(r.reconcile(toml::from_str(&text.replace("fe80::2%zone", "pending.example")).unwrap()));
    drain(&mut r);
    assert_eq!(r.k.tunnel_socket(10), Some(socket));
    assert_eq!(r.k.connection(socket), None);
    assert_eq!(r.k.binding(socket), Some(zone));
    assert_eq!(r.tunnels[&10].zone_index, None);
    assert!(matches!(r.target(10).unwrap(),
        crate::reconciler::ladder::Target::Disconnect { bind: Some(index), pending: None, why: None }
            if index == zone
    ));
    assert_eq!(
        r.k.ops()
            .iter()
            .filter(|op| op.starts_with("disconnect "))
            .count(),
        1
    );
    assert!(!r.k.ops().iter().any(|op| op.starts_with("close ")
        || op.starts_with("open ")
        || op.starts_with("connect ")));
}

/// spec: T21, T27, E4, G4, G17
#[test]
fn a_literal_link_local_zone_connects_without_a_configured_bind_device() {
    let mut kernel = FakeKernel::new(42);
    let zone = kernel.add_link("zone", false);
    kernel.add_addr(zone, "fe80::1".parse().unwrap());
    let mut r = Reconciler::new(kernel, Box::new(Watches::default()));
    let text =
        "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='fe80::2%zone'\n";
    assert!(r.reconcile(toml::from_str(text).unwrap()));
    let socket = r.k.tunnel_socket(10).unwrap();
    assert_eq!(r.k.binding(socket), Some(zone));
    assert_eq!(
        r.k.connection(socket).unwrap().1,
        "fe80::1".parse::<IpAddr>().unwrap()
    );
    assert!(matches!(r.target(10).unwrap(),
        crate::reconciler::ladder::Target::Connect { bind: None, zone: Some(index), .. }
            if index == zone
    ));
    assert!(r.ready());
}
