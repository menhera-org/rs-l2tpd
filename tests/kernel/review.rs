//! Live checks for the kernel assumptions corrected by the Phase 1 review.
//! Run only in an isolated network namespace; see tests/kernel/README.md.

use std::process::Command;
use std::time::{Duration, Instant};

use l2tp::blocking::{L2tpHandle, SessionHandle, TunnelHandle};
use l2tp::{
    IpEndpoint, L2tpIfName, SessionConfig, SessionId, TunnelConfig, TunnelId, TunnelSocket,
};

fn ip(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().expect("iproute2");
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn name(value: &str) -> L2tpIfName {
    L2tpIfName::new(value.as_bytes()).unwrap()
}

fn tunnel(handle: &L2tpHandle, id: u32) -> TunnelHandle {
    let id = TunnelId(id);
    let socket = TunnelSocket::ip_unconnected(
        &IpEndpoint::V4(std::net::Ipv4Addr::UNSPECIFIED),
        None,
        id,
        id,
    )
    .unwrap();
    let config = TunnelConfig::for_socket(id, id, &socket).unwrap();
    let mut tunnel = handle.create_tunnel(config, socket).unwrap();
    tunnel.set_auto_delete(false);
    tunnel
}

fn session(handle: &L2tpHandle, tunnel: u32, id: u32, ifname: &str) -> SessionHandle {
    let mut config = SessionConfig::eth(TunnelId(tunnel), SessionId(id), SessionId(id));
    config.ifname = Some(name(ifname));
    let mut session = handle.create_session(config).unwrap();
    session.set_auto_delete(false);
    session
}

fn wait_absent(handle: &L2tpHandle, tunnel: u32, session: u32) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match handle.get_session(TunnelId(tunnel), SessionId(session)) {
            Err(error) if error.raw_os_error() == Some(19) => break,
            other => {
                assert!(
                    Instant::now() < deadline,
                    "session deletion did not finish: {other:?}"
                );
                std::thread::yield_now();
            }
        }
    }
}

/// kernel: net/l2tp/l2tp_eth.c (l2tp_eth_create), net/l2tp/l2tp_core.c
/// (l2tp_session_get_by_ifname), net/l2tp/l2tp_netlink.c (l2tp_nl_session_get).
/// spec: K16, S4, S22, S28
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN and L2TP modules"]
fn creation_name_is_not_current_or_unique() {
    let handle = L2tpHandle::new().unwrap();
    let _tunnel = tunnel(&handle, 8101);
    let temporary = name("rsl2tp-tabc123");
    let _first = session(&handle, 8101, 81011, "rsl2tp-tabc123");
    ip(&[
        "link",
        "set",
        "dev",
        "rsl2tp-tabc123",
        "name",
        "audit-first",
    ]);
    let _second = session(&handle, 8101, 81012, "rsl2tp-tabc123");
    ip(&[
        "link",
        "set",
        "dev",
        "rsl2tp-tabc123",
        "name",
        "audit-second",
    ]);

    let sessions = handle.list_sessions(TunnelId(8101)).unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|s| s.ifname.as_ref() == Some(&temporary))
    );
    assert!(ip(&["-o", "link", "show", "dev", "audit-first"]).contains("audit-first"));
    assert!(ip(&["-o", "link", "show", "dev", "audit-second"]).contains("audit-second"));

    // A safe deletion must refuse this ambiguous stored name. Demonstrate
    // the raw kernel operation's weaker semantics on disposable objects.
    let selected = handle.get_session_by_ifname(temporary).unwrap().session_id;
    let other = if selected == SessionId(81011) {
        81012
    } else {
        81011
    };
    handle.delete_session_by_ifname(temporary).unwrap();
    wait_absent(&handle, 8101, selected.0);
    assert!(handle.get_session(TunnelId(8101), SessionId(other)).is_ok());
}

/// kernel: net/l2tp/l2tp_core.c (l2tp_tunnel_register, l2tp_tunnel_del_work),
/// net/l2tp/l2tp_ip.c (l2tp_ip_destroy_sock).
/// spec: K5, K17, K37
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN and L2TP modules"]
fn unconnected_tunnel_and_sessions_survive_a_descriptor_duplicate() {
    let handle = L2tpHandle::new().unwrap();
    let tunnel = tunnel(&handle, 8102);
    let _session = session(&handle, 8102, 81021, "audit-socket");
    let fd = tunnel.socket().unwrap().try_clone_fd().unwrap();
    drop(tunnel);
    assert!(handle.get_tunnel(TunnelId(8102)).is_ok());
    assert!(handle.get_session(TunnelId(8102), SessionId(81021)).is_ok());
    drop(fd);
    wait_absent(&handle, 8102, 81021);
}

/// Before 7.3 a kernel sender does not identify the namespace whose object
/// changed (`genlmsg_multicast_allns`); from 7.3 the announcement stays in
/// the tunnel's namespace (`genlmsg_multicast_netns`). Either way the
/// local session survives.
/// kernel: net/l2tp/l2tp_netlink.c (l2tp_session_notify).
/// spec: K41, E27
#[test]
#[ignore = "isolated network namespace with L2TP modules and permission to unshare a child netns"]
fn foreign_namespace_deletion_does_not_delete_local_session() {
    let release = String::from_utf8(
        Command::new("uname")
            .arg("-r")
            .output()
            .expect("uname")
            .stdout,
    )
    .unwrap();
    let mut parts = release.trim().split(|c: char| !c.is_ascii_digit());
    let major: u32 = parts.next().unwrap().parse().unwrap();
    let minor: u32 = parts.next().unwrap().parse().unwrap();
    let crosses_namespaces = (major, minor) < (7, 3);
    let handle = L2tpHandle::new().unwrap();
    let _tunnel = tunnel(&handle, 8103);
    let _session = session(&handle, 8103, 81031, "audit-local");
    let events = handle.events().unwrap();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    // The reader is leaked on purpose: the stream has no close, and the
    // test ends before the process does.
    std::thread::spawn(move || {
        for event in events {
            if let l2tp::L2tpEvent::SessionDeleted(info) = event.unwrap()
                && info.tunnel_id == TunnelId(8103)
                && info.session_id == SessionId(81031)
            {
                let _ = send.send(());
                return;
            }
        }
    });
    let output = Command::new("unshare")
        .args([
            "--net",
            "sh",
            "-ec",
            "ip link set lo up
ip l2tp add tunnel tunnel_id 8103 peer_tunnel_id 8103 encap ip local 127.0.0.1 remote 127.0.0.2
ip l2tp add session tunnel_id 8103 session_id 81031 peer_session_id 81031 name audit-foreign
ip l2tp del session tunnel_id 8103 session_id 81031
ip l2tp del tunnel tunnel_id 8103",
        ])
        .output()
        .expect("unshare");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let announced = receive.recv_timeout(Duration::from_secs(5)).is_ok();
    assert_eq!(
        announced, crosses_namespaces,
        "foreign deletion announced on {release}: {announced}"
    );
    assert!(handle.get_tunnel(TunnelId(8103)).is_ok());
    assert!(handle.get_session(TunnelId(8103), SessionId(81031)).is_ok());
}

/// kernel: net/l2tp/l2tp_core.c (l2tp_xmit_core).
/// spec: K5
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN and L2TP modules"]
fn unconnected_tunnel_drops_outbound_frames() {
    let handle = L2tpHandle::new().unwrap();
    let _tunnel = tunnel(&handle, 8104);
    let _session = session(&handle, 8104, 81041, "audit-drop");
    ip(&["addr", "add", "192.0.2.1/24", "dev", "audit-drop"]);
    ip(&["link", "set", "dev", "audit-drop", "addrgenmode", "none"]);
    ip(&["link", "set", "dev", "audit-drop", "up"]);
    let dropped = || -> u64 {
        let stats = ip(&["-s", "link", "show", "dev", "audit-drop"]);
        stats
            .lines()
            .skip_while(|line| !line.trim_start().starts_with("TX:"))
            .nth(1)
            .unwrap()
            .split_whitespace()
            .nth(3)
            .unwrap()
            .parse()
            .unwrap()
    };
    let before = dropped();
    let socket = std::net::UdpSocket::bind("192.0.2.1:0").unwrap();
    // ARP for this on-link destination sends an Ethernet frame through
    // the session without needing a reachable L2TP peer.
    socket.send_to(b"probe", "192.0.2.2:9").unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while dropped() <= before {
        assert!(
            Instant::now() < deadline,
            "no outbound frame counted as dropped"
        );
        std::thread::yield_now();
    }
}

/// kernel: net/l2tp/l2tp_core.c (l2tp_session_delete, l2tp_session_unhash).
/// spec: K18, K19
#[test]
#[ignore = "isolated network namespace with CAP_NET_ADMIN and L2TP modules"]
fn session_identifier_reuse_waits_for_deletion() {
    let handle = L2tpHandle::new().unwrap();
    let _tunnel = tunnel(&handle, 8105);
    let _session = session(&handle, 8105, 81051, "audit-reuse");
    let mut pending = 0;
    for _ in 0..32 {
        handle
            .delete_session(TunnelId(8105), SessionId(81051))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut config = SessionConfig::eth(TunnelId(8105), SessionId(81051), SessionId(81051));
            config.ifname = Some(name("audit-reuse"));
            match handle.create_session(config) {
                Ok(mut session) => {
                    session.set_auto_delete(false);
                    break;
                }
                Err(error) if error.raw_os_error() == Some(17) => {
                    pending += 1;
                    assert!(Instant::now() < deadline, "session ID not released");
                    std::thread::yield_now();
                }
                Err(error) => panic!("unexpected creation error: {error}"),
            }
        }
    }
    eprintln!("identifier reuse: {pending} EEXIST retries over 32 deletions");
}
