use super::support::{Pair, checked, config, wait};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

fn rx(pair: &Pair, side: usize, device: &str) -> (u64, u64) {
    let text = pair.ip(side, &["-s", "link", "show", "dev", device]);
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with("RX:") {
            let mut values = lines.next().unwrap().split_whitespace();
            return (
                values.next().unwrap().parse().unwrap(),
                values.next().unwrap().parse().unwrap(),
            );
        }
    }
    panic!("no RX counters: {text}");
}
fn fragments(pair: &Pair, side: usize, ipv6: bool) -> u64 {
    let text = checked(pair.command(
        side,
        "cat",
        &[if ipv6 {
            "/proc/net/snmp6"
        } else {
            "/proc/net/snmp"
        }],
    ));
    if ipv6 {
        text.lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                (fields.next()? == "Ip6FragCreates")
                    .then(|| fields.next().unwrap().parse().unwrap())
            })
            .unwrap()
    } else {
        let mut lines = text.lines().filter(|line| line.starts_with("Ip:"));
        let column = lines
            .next()
            .unwrap()
            .split_whitespace()
            .position(|name| name == "FragCreates")
            .unwrap();
        lines
            .next()
            .unwrap()
            .split_whitespace()
            .nth(column)
            .unwrap()
            .parse()
            .unwrap()
    }
}
fn enter(namespace: &str) {
    let file = std::fs::File::open(format!("/run/netns/{namespace}")).unwrap();
    nix::sched::setns(file, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
}
fn bulk(pair: &Pair, side: usize, subnet: usize) {
    let receiver = pair.names[1 - side].clone();
    let sender = pair.names[side].clone();
    let address = format!("198.18.{subnet}.{}", 2 - side);
    let (tx, ready) = std::sync::mpsc::sync_channel(1);
    let receive = std::thread::spawn(move || {
        enter(&receiver);
        let listener = TcpListener::bind((address.as_str(), 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        tx.send(listener.local_addr().unwrap()).unwrap();
        let mut accepted = None;
        wait("bulk TCP connection", || {
            match listener.accept() {
                Ok((socket, _)) => accepted = Some(socket),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("bulk accept: {error}"),
            }
            accepted.is_some()
        });
        let mut socket = accepted.unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = vec![0; 1 << 20];
        socket.read_exact(&mut bytes).unwrap();
        assert!(bytes.iter().enumerate().all(|(n, byte)| *byte == n as u8));
        assert_eq!(socket.read(&mut [0]).unwrap(), 0);
        socket
            .write_all(&(bytes.len() as u64).to_be_bytes())
            .unwrap();
    });
    let peer = ready.recv_timeout(Duration::from_secs(10)).unwrap();
    let send = std::thread::spawn(move || {
        enter(&sender);
        let mut socket = TcpStream::connect_timeout(&peer, Duration::from_secs(5)).unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let bytes: Vec<u8> = (0..1 << 20).map(|n| n as u8).collect();
        socket.write_all(&bytes).unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        let mut count = [0; 8];
        socket.read_exact(&mut count).unwrap();
        assert_eq!(u64::from_be_bytes(count), bytes.len() as u64);
    });
    send.join().unwrap();
    receive.join().unwrap();
}

/// spec: H20, K43, K44, T5, G22
#[test]
#[ignore = "disposable privileged container or QEMU guest"]
fn full_session_mtu_frames_and_bulk_data_fragment_over_both_underlays_and_vrf() {
    for vrf in [false, true] {
        let pair = Pair::new();
        if vrf {
            for side in 0..2 {
                pair.ip(
                    side,
                    &["link", "add", "vrfA", "type", "vrf", "table", "100"],
                );
                pair.ip(side, &["link", "set", "vrfA", "up"]);
                pair.ip(side, &["link", "set", "underlay", "master", "vrfA"]);
            }
        }
        pair.underlay(true, true);
        for side in 0..2 {
            pair.ip(side, &["link", "set", "underlay", "mtu", "1500"]);
        }
        let configured = |side, peers: &[&str]| {
            let text = config(side, peers);
            if vrf {
                text.replace("[sessions.", "bind_interface='vrfA'\n[sessions.")
            } else {
                text
            }
        };
        let mut a = pair.start(0, &configured(0, &["192.0.2.2", "2001:db8:1::2"]));
        let mut b = pair.start(1, &configured(1, &["192.0.2.1", "2001:db8:1::1"]));
        a.event("ready");
        b.event("ready");
        for n in 0..2 {
            let dev = format!("l2tp{n}");
            pair.inner(&dev, n);
            pair.frames(n);
            for mtu in [1500, 9000] {
                let logs = [a.count(""), b.count("")];
                for side in 0..2 {
                    pair.ip(side, &["link", "set", &dev, "mtu", &mtu.to_string()]);
                }
                let before: Vec<_> = (0..2)
                    .map(|side| {
                        (
                            rx(&pair, side, &dev),
                            fragments(&pair, side, n == 1),
                            pair.drops(side, &dev),
                        )
                    })
                    .collect();
                for side in 0..2 {
                    let peer = format!("198.18.{n}.{}", 2 - side);
                    checked(pair.command(
                        side,
                        "ping",
                        &["-c", "1", "-W", "2", "-s", &(mtu - 28).to_string(), &peer],
                    ));
                }
                for (side, (received, created, _)) in before.iter().enumerate() {
                    let after = rx(&pair, side, &dev);
                    assert!(
                        after.0 >= received.0 + mtu as u64 && after.1 > received.1,
                        "whole MTU frame received"
                    );
                    assert!(
                        fragments(&pair, side, n == 1) > *created,
                        "sender fragmented the frame"
                    );
                }
                let before_bulk: Vec<_> = (0..2).map(|side| rx(&pair, side, &dev)).collect();
                for side in 0..2 {
                    bulk(&pair, side, n);
                }
                for (side, (_, _, drops)) in before.iter().enumerate() {
                    assert!(rx(&pair, side, &dev).0 >= before_bulk[side].0 + (1 << 20));
                    assert_eq!(pair.drops(side, &dev), *drops, "no session transmit drops");
                }
                assert_eq!(
                    [a.count(""), b.count("")],
                    logs,
                    "MTU/traffic needs no daemon action"
                );
                println!(
                    "vrf={vrf}, outer_v6={}, session_mtu={mtu}: full-size frames and 1 MiB each way",
                    n == 1
                );
            }
        }
        a.stop();
        b.stop();
        pair.absent(0);
        pair.absent(1);
    }
}

/// spec: T5
#[test]
#[ignore = "disposable privileged container or QEMU guest; setpriv seccomp support"]
fn refused_fragmentation_option_is_reported_once_and_tunnels_still_work() {
    let architecture = match std::env::consts::ARCH {
        "x86_64" => 0xc000003e,
        "aarch64" => 0xc00000b7,
        other => panic!("unsupported seccomp fixture ABI: {other}"),
    };
    // Linux UAPI seccomp_data: architecture at 4, syscall at 0, arguments
    // at 16. Refuse one fragmentation option at a time; allow all other calls.
    for (level, option, label) in [
        (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, "IP_MTU_DISCOVER"),
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            "IPV6_MTU_DISCOVER",
        ),
        (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, "IPV6_DONTFRAG"),
    ] {
        let filter: [(u16, u8, u8, u32); 11] = [
            (0x20, 0, 0, 4),
            (0x15, 1, 0, architecture),
            (0x06, 0, 0, 0x80000000),
            (0x20, 0, 0, 0),
            (0x15, 0, 5, libc::SYS_setsockopt as u32),
            (0x20, 0, 0, 24),
            (0x15, 0, 3, level as u32),
            (0x20, 0, 0, 32),
            (0x15, 0, 1, option as u32),
            (0x06, 0, 0, 0x00050000 | libc::EPERM as u32),
            (0x06, 0, 0, 0x7fff0000),
        ];
        let bytes: Vec<u8> = filter
            .into_iter()
            .flat_map(|(code, jt, jf, value)| {
                let [a, b] = code.to_ne_bytes();
                let [c, d, e, f] = value.to_ne_bytes();
                [a, b, jt, jf, c, d, e, f]
            })
            .collect();
        for native_v4 in [false, true] {
            let pair = Pair::new();
            pair.underlay(true, true);
            if native_v4 {
                for side in 0..2 {
                    pair.tunable(side, "1");
                }
            }
            let path = pair.dir.join("pmtu-filter.bpf");
            std::fs::write(&path, &bytes).unwrap();
            let prefix = [
                "setpriv",
                "--no-new-privs",
                "--seccomp-filter",
                path.to_str().unwrap(),
            ];
            let mut a = pair.start_with(
                0,
                &config(0, &["192.0.2.2", "2001:db8:1::2", "192.0.2.2"]),
                &prefix,
            );
            let mut b = pair.start(1, &config(1, &["192.0.2.1", "2001:db8:1::1", "192.0.2.1"]));
            a.event("ready");
            b.event("ready");
            for n in 0..3 {
                pair.inner(&format!("l2tp{n}"), n);
                pair.frames(n);
            }
            for _ in 0..3 {
                a.reload();
            }
            assert_eq!(
                a.count(&format!(
                    "ERROR rs_l2tpd::kernel::linux::socket: host refuses {label}"
                )),
                1
            );
            assert_eq!(a.count("host refuses"), 1);
            assert_eq!(b.count("host refuses"), 0);
            a.stop();
            b.stop();
            pair.absent(0);
            pair.absent(1);
        }
    }
}
