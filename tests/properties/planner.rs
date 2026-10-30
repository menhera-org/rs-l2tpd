//! Seeded reload/event sequences, checking invariants after every step.
use crate::{config, deliver, ops, reconciler, run_for};
use rs_l2tpd::config::Config;
use rs_l2tpd::kernel::{Kernel, L2tpIfName, SessionInfo};

/// spec: M1, M2, M3, M4, M7, M8, M11, M12, M17, G2, G3, G4, G5, G6, G7, G18
#[test]
fn reload_sequences_converge_without_unjustified_identity_changes() {
    let seeds = std::env::var("TEST_SEED")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(1u64);
    for initial in seeds..seeds + 32 {
        let mut seed = initial;
        let (mut r, _) = reconciler();
        let device = r.kernel_mut().add_link("wan", false);
        r.kernel_mut()
            .add_addr(device, "192.0.2.1".parse().unwrap());
        r.kernel_mut()
            .add_addr(device, "2001:db8::1".parse().unwrap());
        let foreign_socket = r.kernel_mut().operator_replace_tunnel(9000, 9001);
        let foreign_info = SessionInfo::new(
            9000,
            9002,
            9003,
            Default::default(),
            Default::default(),
            Some(L2tpIfName::new("foreign-session").unwrap()),
        );
        let foreign_session = r.kernel_mut().foreign_session(foreign_info.clone());
        let foreign_name = r.kernel_mut().add_link("foreign-name", false);
        r.kernel_mut().set_up(foreign_name, true);
        let foreign_link = r.kernel().link(foreign_name).unwrap().clone();
        let mut tid = 10;
        let mut peer_tid = 20;
        let mut sid = 100;
        let mut peer_sid = 200;
        let mut cookie = false;
        let mut v6 = false;
        let mut bind = false;
        let mut name = false;
        let mut mac = false;
        let mut entry = false;
        let mut accepted = Config::new();
        for _ in 0..64 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let old_tunnel = r.kernel().tunnel_socket(tid);
            let old_index = r.kernel().session_index(tid, sid);
            let old_ti = accepted.tunnels().values().next().map(|t| t.identity());
            let old_si = accepted
                .sessions()
                .keys()
                .next()
                .and_then(|s| accepted.session_identity(s));
            match seed % 12 {
                0 => tid = if tid == 10 { 11 } else { 10 },
                1 => peer_tid = if peer_tid == 20 { 21 } else { 20 },
                2 => sid = if sid == 100 { 101 } else { 100 },
                3 => peer_sid = if peer_sid == 200 { 201 } else { 200 },
                4 => cookie = !cookie,
                5 => v6 = !v6,
                6 => bind = !bind,
                7 => name = !name,
                8 => mac = !mac,
                9 => entry = !entry,
                10 => r.kernel_mut().fail_next("rename", nix::errno::Errno::EIO),
                _ => {}
            }
            let tunnel = if entry { "renamed" } else { "a" };
            let session = if entry { "renamed-session" } else { "s" };
            let text = format!(
                "[tunnels.{tunnel}]\ntunnel_id={tid}\npeer_tunnel_id={peer_tid}\nremote_addr='{}'\nip_version='{}'\n{}\n[sessions.{session}]\ntunnel_name='{tunnel}'\nsession_id={sid}\npeer_session_id={peer_sid}\ninterface_name='{}'\n{}\n{}",
                if v6 { "2001:db8::2" } else { "192.0.2.2" },
                if v6 { "V6" } else { "V4" },
                if bind { "bind_interface='wan'" } else { "" },
                if name { "l2tp1" } else { "l2tp0" },
                if mac {
                    "interface_hwaddr='02:00:5e:00:53:01'"
                } else {
                    ""
                },
                if cookie { "cookie='00112233'" } else { "" }
            );
            accepted = config(&text);
            r.reconcile(accepted.clone());
            run_for(&mut r, 3);
            deliver(&mut r);
            let converged = (0..=64).any(|_| {
                let done = r.reconcile(accepted.clone());
                if !done {
                    run_for(&mut r, 1);
                }
                done
            });
            assert!(converged, "seed {initial}");
            assert!(r.ready(), "seed {initial}");
            let ti = accepted.tunnels()[tunnel].identity();
            let si = accepted.session_identity(session).unwrap();
            if old_ti == Some(ti) {
                assert_eq!(r.kernel().tunnel_socket(tid), old_tunnel);
            }
            if old_si == Some(si) {
                assert_eq!(r.kernel().session_index(tid, sid), old_index);
                assert!(
                    r.kernel().link(old_index.unwrap()).unwrap().up(),
                    "G4: a manager-raised device must stay up, seed {initial}"
                );
            }
            assert_eq!(
                r.kernel().tunnel_socket(9000),
                Some(foreign_socket),
                "G2: foreign tunnel ownership, seed {initial}"
            );
            assert_eq!(
                r.kernel_mut().session(9000, 9002).unwrap(),
                Some(foreign_info.clone()),
                "G2: foreign session unchanged, seed {initial}"
            );
            assert_eq!(r.kernel().session_index(9000, 9002), Some(foreign_session));
            assert_eq!(
                r.kernel().link(foreign_name),
                Some(&foreign_link),
                "G2/G4: foreign device and administrative state, seed {initial}"
            );
            let current_index = r.kernel().session_index(tid, sid).unwrap();
            r.kernel_mut().set_up(current_index, true);
            deliver(&mut r);
            let socket = r.kernel().tunnel_socket(tid).unwrap();
            let (peer, _) = r.kernel().connection(socket).unwrap();
            assert_eq!(
                peer.to_string(),
                if v6 { "2001:db8::2" } else { "192.0.2.2" }
            );
            ops(&mut r);
            assert!(r.reconcile(accepted.clone()));
            assert!(ops(&mut r).is_empty(), "fixed point, seed {initial}");
        }
        assert!(r.shutdown());
        r.kernel_mut().tick();
        assert!(r.kernel_mut().tunnel(tid).unwrap().is_none());
        assert_eq!(r.kernel().open_sockets(), 1);
        assert_eq!(r.kernel().tunnel_socket(9000), Some(foreign_socket));
        assert_eq!(
            r.kernel_mut().session(9000, 9002).unwrap(),
            Some(foreign_info)
        );
        assert_eq!(r.kernel().link(foreign_name), Some(&foreign_link));
    }
}
