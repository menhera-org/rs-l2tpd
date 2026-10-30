use super::support::{Pair, config, wait, wait_with_timeout};

/// spec: H10
#[test]
#[ignore = "disposable privileged container"]
fn a_child_in_another_namespace_survives_reload_and_dies_with_its_parent() {
    let pair = Pair::new();
    pair.underlay(true, false);
    let text = config(0, &["192.0.2.2"]);
    let mut a = pair.start(0, &text);
    let mut b = pair.start(1, &config(1, &["192.0.2.1"]));
    a.event("ready");
    b.event("ready");
    pair.inner("l2tp0", 0);
    pair.frames(0);
    let parent = pair.index(0, "l2tp0");
    pair.ip(
        0,
        &[
            "link",
            "add",
            "link",
            "l2tp0",
            "name",
            "movedchild",
            "type",
            "vlan",
            "id",
            "40",
        ],
    );
    pair.ip(0, &["link", "set", "movedchild", "netns", &pair.names[1]]);
    let child = pair.index(1, "movedchild");
    a.reload();
    assert_eq!(pair.index(0, "l2tp0"), parent);
    assert_eq!(pair.index(1, "movedchild"), child);
    let renamed = text.replace("interface_name='l2tp0'", "interface_name='renamed0'");
    std::fs::write(pair.dir.join("0.toml"), renamed).unwrap();
    a.reload();
    assert_eq!(pair.index(0, "renamed0"), parent);
    assert_eq!(pair.index(1, "movedchild"), child);
    pair.frames(0);
    a.stop();
    pair.absent(0);
    wait("cross-namespace child removed with parent", || {
        !pair
            .output(1, "ip", &["link", "show", "movedchild"])
            .status
            .success()
    });
    assert!(pair.ip(1, &["link", "show", "l2tp0"]).contains("l2tp0"));
    b.stop();
    pair.absent(1);
}

/// spec: H12
#[test]
#[ignore = "disposable privileged container"]
fn foreign_identifiers_and_names_are_left_alone_until_they_are_freed() {
    let pair = Pair::new();
    pair.underlay(true, false);
    for id in ["1", "999"] {
        pair.ip(
            0,
            &[
                "l2tp",
                "add",
                "tunnel",
                "tunnel_id",
                id,
                "peer_tunnel_id",
                id,
                "encap",
                "udp",
                "local",
                "192.0.2.1",
                "remote",
                "192.0.2.2",
                "udp_sport",
                if id == "1" { "1701" } else { "1702" },
                "udp_dport",
                if id == "1" { "1701" } else { "1702" },
            ],
        );
    }
    pair.ip(
        0,
        &[
            "l2tp",
            "add",
            "session",
            "tunnel_id",
            "999",
            "session_id",
            "111",
            "peer_session_id",
            "777",
            "name",
            "foreignsession",
        ],
    );
    pair.ip(0, &["link", "add", "l2tp2", "type", "dummy"]);
    let foreign_session = pair.index(0, "foreignsession");
    let foreign_name = pair.index(0, "l2tp2");
    let foreign_before = tunnel_record(&pair, 999);
    let mut a = pair.start(0, &config(0, &["192.0.2.2"; 3]));
    let mut b = pair.start(1, &config(1, &["192.0.2.1"; 3]));
    b.event("ready");
    a.event_with_timeout("ready", std::time::Duration::from_secs(20));
    assert_eq!(pair.index(0, "foreignsession"), foreign_session);
    assert_eq!(pair.index(0, "l2tp2"), foreign_name);
    assert_eq!(tunnel_record(&pair, 999), foreign_before);
    assert_eq!(a.count("left out"), 2);
    assert!(
        !pair
            .output(0, "ip", &["link", "show", "l2tp0"])
            .status
            .success()
    );
    assert!(
        !pair
            .output(0, "ip", &["link", "show", "l2tp1"])
            .status
            .success()
    );
    let freed = std::time::Instant::now();
    pair.ip(0, &["l2tp", "del", "tunnel", "tunnel_id", "1"]);
    pair.ip(
        0,
        &[
            "l2tp",
            "del",
            "session",
            "tunnel_id",
            "999",
            "session_id",
            "111",
        ],
    );
    pair.ip(0, &["link", "del", "l2tp2"]);
    // No reload: the slow retry must recover held identifiers on its own.
    wait_with_timeout(
        "released identifiers and name",
        std::time::Duration::from_secs(31),
        || {
            (0..3).all(|n| {
                pair.output(0, "ip", &["link", "show", &format!("l2tp{n}")])
                    .status
                    .success()
            })
        },
    );
    assert!(freed.elapsed() <= std::time::Duration::from_secs(31));
    for n in 0..3 {
        pair.inner(&format!("l2tp{n}"), n);
        pair.frames(n);
    }
    a.stop();
    assert_eq!(tunnel_record(&pair, 999), foreign_before);
    assert_eq!(
        pair.ip(0, &["l2tp", "show", "tunnel"])
            .lines()
            .filter(|line| line.starts_with("Tunnel "))
            .count(),
        1
    );
    assert!(pair.ip(0, &["l2tp", "show", "session"]).trim().is_empty());
    b.stop();
    pair.absent(1);
}

fn tunnel_record(pair: &Pair, id: u32) -> String {
    let dump = pair.ip(0, &["l2tp", "show", "tunnel"]);
    let header = format!("Tunnel {id}, ");
    let mut active = false;
    let mut record = String::new();
    for line in dump.lines() {
        if line.starts_with("Tunnel ") {
            active = line.starts_with(&header);
        }
        if active {
            record.push_str(line);
            record.push('\n');
        }
    }
    assert!(!record.is_empty(), "missing tunnel {id}: {dump}");
    record
}
