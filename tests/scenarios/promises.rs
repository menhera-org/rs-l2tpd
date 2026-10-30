use super::support::{Detached, Pair, config};
use std::fs;

fn legacy_config(side: usize) -> String {
    let peers = if side == 0 {
        ["192.0.2.2", "2001:db8:1::2"]
    } else {
        ["192.0.2.1", "2001:db8:1::1"]
    };
    config(side, &peers)
        .replace("[host]\nfix_bindv6only=false\n", "")
        .replace("[sessions.s0]", "ip_version='V4'\n[sessions.s0]")
        .replace("[sessions.s1]", "ip_version='V6'\n[sessions.s1]")
}
fn baseline(pair: &Pair) -> Detached {
    let binary = std::env::var("RS_L2TPD_BASELINE").expect("the scenario runner builds v0.1.5");
    fs::create_dir_all("/etc/rs-l2tpd.toml.d").unwrap();
    fs::write("/etc/rs-l2tpd.toml", legacy_config(1)).unwrap();
    let pid_file = pair.dir.join("baseline.pid");
    let mut command = pair.command(1, &binary, &["--verbose", "--pidfile"]);
    command.arg(&pid_file);
    Detached::spawn(pair, 1, command, pid_file, pair.dir.join("baseline.log"))
}

/// spec: G11, G22
#[test]
#[ignore = "disposable privileged container; runner supplies the archived v0.1.5 binary"]
fn version_015_configuration_and_peer_exchange_frames() {
    let pair = Pair::new();
    pair.underlay(true, true);
    let mut current = pair.start(0, &legacy_config(0));
    current.event("ready");
    let baseline = baseline(&pair);
    for n in 0..2 {
        pair.inner(&format!("l2tp{n}"), n);
        pair.frames(n);
    }
    current.reload();
    for n in 0..2 {
        pair.frames(n);
    }
    baseline.stop(&pair);
    current.stop();
    pair.absent(0);
}
