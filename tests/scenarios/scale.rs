use super::netlink::RouteTrace;
use super::support::{Daemon, Pair, config, wait};
use std::fs;
use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, Instant};

fn configured(side: usize, count: usize) -> String {
    config(
        side,
        &vec![if side == 0 { "192.0.2.2" } else { "192.0.2.1" }; count],
    )
    .replace("[sessions.", "bind_interface='underlay'\n[sessions.")
}
fn objects(pair: &Pair, count: usize) {
    for side in 0..2 {
        assert_eq!(
            pair.ip(side, &["l2tp", "show", "tunnel"])
                .lines()
                .filter(|s| s.starts_with("Tunnel "))
                .count(),
            count
        );
        assert_eq!(
            pair.ip(side, &["l2tp", "show", "session"])
                .lines()
                .filter(|s| s.starts_with("Session "))
                .count(),
            count
        );
    }
}
fn resources(daemon: &Daemon, count: usize) -> (usize, u64) {
    let fds = fs::read_dir(format!("/proc/{}/fd", daemon.pid()))
        .unwrap()
        .count();
    let status = fs::read_to_string(format!("/proc/{}/status", daemon.pid())).unwrap();
    let rss: u64 = status
        .lines()
        .find(|s| s.starts_with("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (count..=count + 20).contains(&fds),
        "{count} tunnels use {fds} descriptors"
    );
    println!("H17_RESOURCES tunnels={count} fds={fds} rss_kib={rss}");
    (fds, rss)
}
fn wire(pair: &Pair, count: usize) {
    for side in 0..2 {
        let mut child = pair
            .command(side, "ip", &["-batch", "-"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || {
            for n in 0..count {
                writeln!(input, "link set l2tp{n} addrgenmode none")?;
                writeln!(input, "link set l2tp{n} up")?;
                writeln!(
                    input,
                    "addr add 198.18.{}.{}/30 dev l2tp{n}",
                    n / 64,
                    (n % 64) * 4 + side + 1
                )?;
            }
            Ok::<_, std::io::Error>(())
        });
        let output = child.wait_with_output().unwrap();
        writer.join().unwrap().unwrap();
        assert!(output.status.success(), "{output:?}");
    }
    for n in 0..count {
        for side in 0..2 {
            let peer = format!("198.18.{}.{}", n / 64, (n % 64) * 4 + 2 - side);
            assert!(
                pair.output(
                    side,
                    "ping",
                    &["-c", "1", "-W", "2", "-I", &format!("l2tp{n}"), &peer]
                )
                .status
                .success(),
                "session {n} side {side}"
            );
        }
    }
    println!("H17_FRAMES sessions={count} directions=both");
}

/// spec: H17, M16, G12, G23
#[test]
#[ignore = "disposable privileged container or QEMU guest with nlmon"]
fn three_hundred_tunnels_release_resources_and_ignore_unrelated_events() {
    let pair = Pair::new();
    pair.underlay(true, true);
    let started = Instant::now();
    let mut initial_a = pair.start(0, &configured(0, 300));
    let mut initial_b = pair.start(1, &configured(1, 300));
    initial_a.event_with_timeout("ready", Duration::from_secs(60));
    initial_b.event_with_timeout("ready", Duration::from_secs(60));
    println!(
        "H17_READY tunnels=300 elapsed_ns={}",
        started.elapsed().as_nanos()
    );
    objects(&pair, 300);
    resources(&initial_a, 300);
    resources(&initial_b, 300);
    initial_a.stop_with_timeout(Duration::from_secs(60));
    initial_b.stop_with_timeout(Duration::from_secs(60));
    pair.absent(0);
    pair.absent(1);
    let started = Instant::now();
    let mut a = pair.start(0, &configured(0, 1));
    let mut b = pair.start(1, &configured(1, 1));
    a.event("ready");
    b.event("ready");
    println!(
        "H17_READY tunnels=1 elapsed_ns={}",
        started.elapsed().as_nanos()
    );
    objects(&pair, 1);
    let baseline = [resources(&a, 1), resources(&b, 1)];
    let mut small = None;
    for cycle in 0..3 {
        for side in 0..2 {
            fs::write(pair.dir.join(format!("{side}.toml")), configured(side, 300)).unwrap();
        }
        let began = Instant::now();
        a.reload_with_timeout(Duration::from_secs(60));
        b.reload_with_timeout(Duration::from_secs(60));
        println!(
            "H17_EXPAND cycle={cycle} elapsed_ns={}",
            began.elapsed().as_nanos()
        );
        objects(&pair, 300);
        for (side, daemon) in [&a, &b].into_iter().enumerate() {
            let large = resources(daemon, 300);
            assert_eq!(
                large.0,
                baseline[side].0 + 299,
                "one descriptor per additional tunnel"
            );
            assert!(
                large.1 <= baseline[side].1 + 300 * 64,
                "linear live RSS envelope"
            );
        }
        if cycle == 0 {
            wire(&pair, 300);
            // A stable reload exercises every entry. Count both netlink protocols.
            let trace = RouteTrace::start(&pair, 0);
            a.reload_with_timeout(Duration::from_secs(60));
            let cost = trace.finish();
            println!("H17_IDENTICAL_RELOAD tunnels=300 {cost:?}");
            assert!(cost.requests > 0 && cost.requests <= 300 * 20 + 20);
            pair.ip(0, &["link", "del", "nltrace"]);
            let connects = a.count("): connected to");
            let logs = a.count("");
            let trace = RouteTrace::start(&pair, 0);
            // Requests stay in B; moving/deleting the peer produces only
            // kernel notifications in A, so any captured request there is a defect.
            for n in 0..100 {
                let name = format!("noise{n}");
                pair.ip(
                    1,
                    &[
                        "link",
                        "add",
                        &name,
                        "type",
                        "veth",
                        "peer",
                        "name",
                        "noise-peer",
                    ],
                );
                pair.ip(1, &["link", "set", "noise-peer", "netns", &pair.names[0]]);
                pair.ip(1, &["link", "del", &name]);
            }
            let until = Instant::now() + Duration::from_millis(2200);
            while Instant::now() < until {
                assert_eq!(
                    trace.snapshot().requests,
                    0,
                    "unrelated events issued requests"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            let counts = trace.finish();
            assert!(
                counts.packets >= 200,
                "actual link notifications must be captured"
            );
            assert_eq!(counts.requests, 0);
            assert_eq!(a.count(""), logs, "unrelated events logged output");
            assert_eq!(a.count("): connected to"), connects);
            println!("H17_UNRELATED events=200 {counts:?}");
            // A relevant address event must still reach the daemon and reconnect
            // every bound tunnel; silence above cannot pass by losing the monitor.
            pair.ip(0, &["addr", "add", "192.0.2.9/24", "dev", "underlay"]);
            wait("all affected tunnels reconnect", || {
                a.count("): connected to") == connects + 300
            });
            println!("H17_RELEVANT reconnects=300");
        }
        for side in 0..2 {
            fs::write(pair.dir.join(format!("{side}.toml")), configured(side, 1)).unwrap();
        }
        a.reload_with_timeout(Duration::from_secs(60));
        b.reload_with_timeout(Duration::from_secs(60));
        objects(&pair, 1);
        let now = [resources(&a, 1), resources(&b, 1)];
        if let Some(prior) = small {
            for side in 0..2 {
                let previous: [(usize, u64); 2] = prior;
                assert_eq!(
                    now[side].0, previous[side].0,
                    "descriptors grew with history"
                );
                assert!(
                    now[side].1 <= previous[side].1 + 2048,
                    "RSS grew with reload history"
                );
            }
        } else {
            small = Some(now);
        }
        for side in 0..2 {
            assert_eq!(now[side].0, baseline[side].0);
        }
        println!("H17_SHRINK cycle={cycle}");
    }
    a.stop_with_timeout(Duration::from_secs(60));
    b.stop_with_timeout(Duration::from_secs(60));
    pair.absent(0);
    pair.absent(1);
}
