use super::*;
use crate::config::Config;
use crate::kernel::fake::FakeKernel;
use crate::reconciler::IphostResolve;
use crate::reconciler::records::{Connection, TunnelRecord};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Instant;

/// spec: C14, M6, M16, G23
#[test]
fn wanted_lookup_cost_and_identity_checks() {
    for count in [1, 100, 300, 1000] {
        let mut text = String::new();
        for id in 1..=count {
            text += &format!(
                "[tunnels.t{id:04}]\ntunnel_id={id}\nremote_addr='192.0.2.2'\n[sessions.s{id:04}]\ntunnel_name='t{id:04}'\nsession_id={id}\ninterface_name='s{id}'\n"
            );
        }
        let config: Config = toml::from_str(&text).unwrap();
        let tunnel_name = format!("t{count:04}");
        let session_name = format!("s{count:04}");
        let tunnel = &config.tunnels()[&tunnel_name];
        let session = &config.sessions()[&session_name];
        let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
        // Synthetic records isolate lookup cost without opening count sockets.
        r.tunnels.insert(
            count,
            TunnelRecord {
                name: tunnel_name.clone(),
                config: tunnel.clone(),
                identity: tunnel.identity(),
                socket: crate::kernel::SocketId::new(0),
                family: crate::config::Family::V4,
                bound: None,
                bind_index: None,
                zone_index: None,
                connection: Connection::Disconnected { pending: None },
                stale: false,
            },
        );
        r.sessions.insert(
            count,
            SessionRecord {
                name: session_name.clone(),
                config: session.clone(),
                identity: config.session_identity(&session_name).unwrap(),
                tunnel_id: count,
                state: Identity::Adopted,
                created_as: None,
                current_name: None,
                name_state: Enforce::Pending,
                hwaddr: None,
                hwaddr_state: Enforce::Pending,
                kernel_hwaddr: None,
            },
        );
        r.wanted_tunnels = config
            .tunnels()
            .iter()
            .map(|(n, t)| (t.tunnel_id(), n.clone()))
            .collect();
        r.wanted_sessions = config
            .sessions()
            .iter()
            .map(|(n, s)| (s.session_id(), n.clone()))
            .collect();
        r.accepted = config;
        let scan = || {
            let tunnel = r
                .accepted
                .tunnels()
                .iter()
                .find(|(_, t)| t.identity() == r.tunnels[&count].identity)
                .map(|(n, t)| (n.clone(), t.clone()));
            let session = r
                .accepted
                .sessions()
                .iter()
                .find(|(n, _)| r.accepted.session_identity(n) == Some(r.sessions[&count].identity))
                .map(|(n, s)| (n.clone(), s.clone()));
            (tunnel, session)
        };
        assert_eq!(scan(), (r.tunnel_wanted(count), r.session_wanted(count)));
        let started = Instant::now();
        for _ in 0..500 {
            black_box(scan());
        }
        let scan_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        for _ in 0..500 {
            black_box((r.tunnel_wanted(count), r.session_wanted(count)));
        }
        println!(
            "WANTED_LOOKUP entries={count} queries=500 scan_ns={scan_ns} indexed_ns={}",
            started.elapsed().as_nanos()
        );
        r.tunnels.get_mut(&count).unwrap().identity =
            crate::config::TunnelIdentity::new(count, count + 1);
        assert!(r.tunnel_wanted(count).is_none());
        let cookie = crate::config::Cookie::new(&[1, 2, 3, 4]).unwrap();
        for (tunnel, sid, peer, sent, received) in [
            (count + 1, count, count, None, None),
            (count, count + 1, count, None, None),
            (count, count, count + 1, None, None),
            (count, count, count, Some(cookie), None),
            (count, count, count, None, Some(cookie)),
        ] {
            r.sessions.get_mut(&count).unwrap().identity = crate::config::SessionIdentity::new(
                crate::config::TunnelIdentity::new(tunnel, tunnel),
                sid,
                peer,
                sent,
                received,
            );
            assert!(r.session_wanted(count).is_none());
        }
        r.wanted_tunnels.clear();
        r.wanted_sessions.clear();
        assert!(r.tunnel_wanted(count).is_none());
        assert!(r.session_wanted(count).is_none());
        assert!(r.tunnel_wanted(count + 1).is_none());
        assert!(r.session_wanted(count + 1).is_none());
        assert!(r.k.ops().is_empty());
    }
}

/// spec: C14, M6, G23
#[test]
fn desired_indexes_follow_operator_names_and_release_on_shutdown() {
    let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
    let text = "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\n[sessions.s]\ntunnel_name='a'\nsession_id=100\ninterface_name='l2tp0'\n";
    assert!(r.reconcile(toml::from_str(text).unwrap()));
    let socket = r.tunnels[&10].socket;
    let device = r.k.session_index(10, 100);
    let renamed = text
        .replace("tunnels.a", "tunnels.z")
        .replace("sessions.s", "sessions.q")
        .replace("tunnel_name='a'", "tunnel_name='z'");
    assert!(r.reconcile(toml::from_str(&renamed).unwrap()));
    assert_eq!(r.wanted_tunnels, BTreeMap::from([(10, "z".to_owned())]));
    assert_eq!(r.wanted_sessions, BTreeMap::from([(100, "q".to_owned())]));
    assert_eq!(r.tunnel_wanted(10).unwrap().0, "z");
    assert_eq!(r.session_wanted(100).unwrap().0, "q");
    assert_eq!(r.tunnels[&10].socket, socket);
    assert_eq!(r.k.session_index(10, 100), device);
    assert!(r.shutdown());
    assert!(r.wanted_tunnels.is_empty());
    assert!(r.wanted_sessions.is_empty());
}
