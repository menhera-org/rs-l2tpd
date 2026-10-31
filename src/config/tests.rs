//! Tests of the configuration rules (C2–C17, L4, K32, O5, O8). The
//! documents are TOML, as the daemon's files are.

#![cfg(feature = "serde")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

fn partial(doc: &str) -> PartialConfig {
    toml::from_str(doc).expect("the document parses")
}

fn lenient(doc: &str) -> (Config, Vec<Problem>) {
    partial(doc).into_config_lenient()
}

fn reload(
    previous: &Config,
    doc: &str,
) -> std::result::Result<(Config, Vec<Problem>), Vec<Problem>> {
    partial(doc).into_config_with_previous(previous)
}

/// (entry name or key path, field, effect) of each problem.
fn summary(problems: &[Problem]) -> Vec<(String, Option<&'static str>, Effect)> {
    problems
        .iter()
        .map(|p| match p.kind() {
            ProblemKind::Entry { name, field, .. } => (name.clone(), *field, p.effect()),
            ProblemKind::Document { path, .. } => (path.join("."), None, p.effect()),
        })
        .collect()
}

fn name(s: &str) -> L2tpIfName {
    L2tpIfName::new(s).unwrap()
}

const RESOLVER: &str = "[resolvers.r]\naddresses = [\"192.0.2.53\"]\n";

/// Tunnel `t` with `fields`, beside resolver `r`: the entry if kept, and
/// the (field, effect) of its problems.
fn tunnel(fields: &str) -> (Option<TunnelConfig>, Vec<(Option<&'static str>, Effect)>) {
    let (config, problems) = lenient(&format!("{RESOLVER}[tunnels.t]\n{fields}"));
    let problems = summary(&problems)
        .into_iter()
        .map(|(_, f, e)| (f, e))
        .collect();
    (config.tunnels().get("t").cloned(), problems)
}

/// Session `s` with `fields`, on tunnel `t`.
fn session(fields: &str) -> (Option<SessionConfig>, Vec<(Option<&'static str>, Effect)>) {
    let doc =
        format!("[tunnels.t]\ntunnel_id = 1\nremote_addr = \"192.0.2.1\"\n[sessions.s]\n{fields}");
    let (config, problems) = lenient(&doc);
    let problems = summary(&problems)
        .into_iter()
        .map(|(_, f, e)| (f, e))
        .collect();
    (config.sessions().get("s").cloned(), problems)
}

/// Resolver `r` with `fields`.
fn resolver(fields: &str) -> (Option<ResolverConfig>, Vec<(Option<&'static str>, Effect)>) {
    let (config, problems) = lenient(&format!("[resolvers.r]\n{fields}"));
    let problems = summary(&problems)
        .into_iter()
        .map(|(_, f, e)| (f, e))
        .collect();
    (config.resolvers().get("r").cloned(), problems)
}

fn left_out(field: &'static str) -> Vec<(Option<&'static str>, Effect)> {
    vec![(Some(field), Effect::LeftOut)]
}

fn corrected(field: &'static str) -> Vec<(Option<&'static str>, Effect)> {
    vec![(Some(field), Effect::Corrected)]
}

const VALID: &str = "tunnel_id = 1\nremote_addr = \"192.0.2.1\"\n";

/// spec: C2, C5
#[test]
fn every_explicit_document_field_replaces_its_previous_value() {
    let document = |n| {
        format!(
            "[host]\nfix_bindv6only={}\n[resolvers.r]\naddresses=['192.0.2.{n}']\nmethod='dhcpv6'\nbind_interface='wan{n}'\ndhcpv6_identity='random'\ndhcpv6_duid='0003000102000000000{n}'\n[tunnels.t]\ntunnel_id={n}\npeer_tunnel_id={}\nremote_addr='host{n}.test'\nip_version='V6'\nbind_interface='wan{n}'\nresolver_name='r'\n[sessions.s]\ntunnel_name='t'\nsession_id={n}\npeer_session_id={}\ninterface_name='l2tp{n}'\ninterface_hwaddr='02:00:00:00:00:0{n}'\ncookie='0102030{n}'\npeer_cookie='0405060{n}'\n",
            n == 1,
            n + 10,
            n + 20
        )
    };
    let mut merged = partial(&document(1));
    let replacement = partial(&document(2));
    let expected = toml::to_string(&replacement).unwrap();
    merged.merge(replacement);
    assert_eq!(toml::to_string(&merged).unwrap(), expected);
}

/// spec: C14, C16, L4, O8
#[test]
fn identities_and_all_discovery_choices_survive_document_round_trips() {
    let (base, problems) = lenient(
        "[tunnels.t]\ntunnel_id=7\npeer_tunnel_id=8\nremote_addr='192.0.2.1'\n[sessions.s]\ntunnel_name='t'\nsession_id=9\npeer_session_id=10\ninterface_name='l2tp0'\n",
    );
    assert!(problems.is_empty());
    let identity = base.session_identity("s").unwrap();
    assert_eq!(identity.tunnel(), base.tunnels()["t"].identity());
    assert_eq!(identity.tunnel().tunnel_id(), 7);
    assert_eq!(identity.session_id(), 9);
    for (method, text) in [
        (Method::Ra, "ra"),
        (Method::Dhcpv6, "dhcpv6"),
        (Method::Ipv6, "ipv6"),
    ] {
        assert_eq!(method.to_string(), text);
        for identity in [
            Dhcpv6Identity::LinkLayer,
            Dhcpv6Identity::Anonymous,
            Dhcpv6Identity::Random,
            Dhcpv6Identity::Duid(vec![0, 3, 0, 1, 2, 0]),
        ] {
            if method == Method::Ra && identity != Dhcpv6Identity::LinkLayer {
                continue;
            }
            let mut config = base.clone();
            config
                .insert_resolver(
                    "r",
                    ResolverConfig::with_method(
                        method,
                        name("wan0"),
                        (method != Method::Ra).then_some(identity),
                    )
                    .unwrap(),
                )
                .unwrap();
            let rendered = toml::to_string(&config).unwrap();
            let (round_trip, problems) = partial(&rendered).into_config_lenient();
            assert!(problems.is_empty(), "{problems:?}");
            assert_eq!(round_trip, config);
            assert!(rendered.contains(&format!("method = \"{text}\"")));
        }
    }
}

/// spec: C6, C12, C15, O4, O6
#[test]
fn retained_resolver_and_document_diagnostics_keep_their_context() {
    let (previous, problems) = lenient(RESOLVER);
    assert!(problems.is_empty());
    let (kept, problems) = reload(&previous, "[resolvers.r]\nmethod='unknown'\n").unwrap();
    assert_eq!(kept, previous);
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].effect(), Effect::KeptPrevious);
    let description = problems[0].to_string();
    assert!(
        description.contains("resolver \"r\", method:"),
        "{description}"
    );
    assert!(description.ends_with("the values in force are kept"));
    let (_, problems) = lenient("[tunnels.'']\ntunnel_id=7\n");
    assert_eq!(problems.len(), 1);
    assert!(problems[0].to_string().starts_with("tunnel \"\": "));
    for source in [None, Some("settings.toml")] {
        let mut document = partial("'odd key'=1\n");
        if let Some(source) = source {
            document.set_source(source);
        }
        let (_, problems) = document.into_config_lenient();
        let text = problems[0].to_string();
        assert!(text.contains("odd key"));
        assert!(text.ends_with("; ignored"));
        assert_eq!(text.starts_with("settings.toml:"), source.is_some());
    }
    let (previous, _) = lenient("[tunnels.a]\ntunnel_id=1\n[tunnels.b]\ntunnel_id=2\n");
    let problems = reload(
        &previous,
        "[tunnels.a]\ntunnel_id=0\n[tunnels.b]\ntunnel_id=1\n",
    )
    .unwrap_err();
    assert!(
        problems
            .iter()
            .any(|problem| problem.to_string().ends_with("the reload is refused"))
    );
}

/// spec: C5
#[test]
fn configuration_names() {
    let long = "n".repeat(64);
    let (config, problems) = lenient(&format!("[tunnels.{long}]\n{VALID}"));
    assert!(problems.is_empty() && config.tunnels().contains_key(&long));
    for key in [format!("{long}n"), "\"a\\u0007\"".into(), "\"\"".into()] {
        let (config, problems) = lenient(&format!("[tunnels.{key}]\n{VALID}"));
        assert!(config.tunnels().is_empty(), "{key}");
        assert_eq!(summary(&problems)[0].1, None);
        assert_eq!(summary(&problems)[0].2, Effect::LeftOut);
    }
}

/// Every field is optional in a document, and values with a textual form
/// stay text until the merged result is validated.
/// spec: C5, C2
#[test]
fn documents_are_merged_before_validation() {
    let mut main = partial("[tunnels.t]\ntunnel_id = 1\nremote_addr = \"not an address!\"\n");
    main.merge(partial("[tunnels.t]\nremote_addr = \"192.0.2.1\"\n"));
    let (config, problems) = main.into_config_lenient();
    assert!(problems.is_empty());
    assert!(config.tunnels()["t"].remote_addr().is_some());
}

/// spec: C6
#[test]
fn a_value_of_the_wrong_type_fails_the_document() {
    for doc in [
        "[tunnels.t]\ntunnel_id = \"1\"\n",
        "[tunnels.t]\nremote_addr = 5\n",
        "[tunnels.t]\nremote_addr = { a = 1 }\n",
        "tunnels = 5\n",
        "[host]\nfix_bindv6only = \"yes\"\n",
        "[resolvers.r]\naddresses = \"192.0.2.53\"\n",
    ] {
        assert!(toml::from_str::<PartialConfig>(doc).is_err(), "{doc}");
    }
}

/// spec: C6, C15
#[test]
fn unknown_keys_at_every_depth() {
    let mut main = partial(&format!(
        "bogus = 1\n[host]\nx = 1\n{RESOLVER}w = []\n[tunnels.t]\n{VALID}extra = 1\n\
         [tunnels.t.deeper]\ny = 1\n[sessions.s]\ntunnel_name = \"t\"\nsession_id = 1\n\
         interface_name = \"l2tp0\"\nz = true\n"
    ));
    main.set_source("main.toml");
    let mut dropin = partial("[tunnels.t]\n\"odd key\" = 1\n");
    dropin.set_source("10-dropin.toml");
    main.merge(dropin);
    let (config, problems) = main.clone().into_config_lenient();
    assert_eq!(config.sessions().len(), 1, "unknown keys are ignored");
    let paths: Vec<_> = problems
        .iter()
        .map(|p| match p.kind() {
            ProblemKind::Document { source, path } => {
                assert_eq!(p.effect(), Effect::Ignored);
                (
                    source.clone().unwrap().display().to_string(),
                    path.join("."),
                )
            }
            _ => panic!("{p}"),
        })
        .collect();
    let expected = [
        ("main.toml", "bogus"),
        ("main.toml", "host.x"),
        ("main.toml", "resolvers.r.w"),
        ("main.toml", "tunnels.t.deeper"),
        ("main.toml", "tunnels.t.extra"),
        ("main.toml", "sessions.s.z"),
        ("10-dropin.toml", "tunnels.t.odd key"),
    ];
    assert_eq!(paths, expected.map(|(s, p)| (s.to_string(), p.to_string())));
    assert_eq!(
        problems[6].to_string(),
        "10-dropin.toml: tunnels.t.\"odd key\": unknown key tunnel_id=1; ignored"
    );
    let strict = Config::try_from(main).unwrap_err().to_string();
    assert!(strict.contains("main.toml: bogus"), "{strict}");
}

/// spec: C7
#[test]
fn tunnel_identifiers() {
    assert_eq!(
        tunnel("remote_addr = \"192.0.2.1\"").1,
        left_out("tunnel_id")
    );
    for id in ["0", "-1", "4294967296"] {
        let (t, p) = tunnel(&format!("tunnel_id = {id}\nremote_addr = \"192.0.2.1\""));
        assert!(t.is_none());
        assert_eq!(p, left_out("tunnel_id"), "{id}");
    }
    let (t, p) = tunnel("tunnel_id = 4294967295\nremote_addr = \"192.0.2.1\"");
    assert!(p.is_empty());
    let t = t.unwrap();
    assert_eq!((t.tunnel_id(), t.peer_tunnel_id()), (u32::MAX, u32::MAX));
    let (t, _) = tunnel(&format!("{VALID}peer_tunnel_id = 7"));
    assert_eq!(t.unwrap().peer_tunnel_id(), 7);
    assert_eq!(
        tunnel(&format!("{VALID}peer_tunnel_id = 0")).1,
        left_out("peer_tunnel_id")
    );
}

/// Literals: dotted quads, RFC 4291 text, IPv4-mapped as IPv4, zones on
/// link-local addresses, loopback allowed.
/// spec: C7, T27, R47
#[test]
fn tunnel_literals() {
    let peer = |text: &str, extra: &str| {
        let (t, p) = tunnel(&format!("tunnel_id = 1\nremote_addr = \"{text}\"\n{extra}"));
        (
            t.and_then(|t| t.remote_addr().cloned().map(|r| (r, t.family()))),
            p,
        )
    };
    let ip = |addr: IpAddr, zone: Option<&str>| RemoteAddr::Ip {
        addr,
        zone: zone.map(name),
    };
    let v4 = |s: &str| IpAddr::V4(s.parse::<Ipv4Addr>().unwrap());
    let v6 = |s: &str| IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());
    for (text, addr, family) in [
        ("192.0.2.1", ip(v4("192.0.2.1"), None), Family::V4),
        ("2001:db8::1", ip(v6("2001:db8::1"), None), Family::V6),
        ("::ffff:192.0.2.1", ip(v4("192.0.2.1"), None), Family::V4),
        ("127.0.0.1", ip(v4("127.0.0.1"), None), Family::V4),
        ("::1", ip(v6("::1"), None), Family::V6),
        ("fe80::1%eth0", ip(v6("fe80::1"), Some("eth0")), Family::V6),
    ] {
        assert_eq!(peer(text, ""), (Some((addr, family)), vec![]), "{text}");
    }
    for text in [
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "255.255.255.255",
        "2001:db8::1%eth0",
        "fe80::1%a/b",
        "192.0.2.1/24",
    ] {
        let (peer, problems) = peer(text, "");
        assert_eq!(peer, None, "{text}: applied without a peer");
        assert_eq!(problems, corrected("remote_addr"), "{text}");
    }
    assert_eq!(peer("fe80::1", "").1, left_out("remote_addr"));
    assert_eq!(peer("fe80::1", "bind_interface = \"eth0\"").1, vec![]);
}

/// spec: C7
#[test]
fn tunnel_host_names() {
    let host = |text: &str| {
        let (t, p) = tunnel(&format!(
            "tunnel_id = 1\nremote_addr = \"{text}\"\nip_version = \"V6\""
        ));
        (t.and_then(|t| t.remote_addr().cloned()), p)
    };
    let label = "a".repeat(63);
    let long = [label.as_str(); 4].join(".");
    let at_most = &long[..253];
    for (text, expected) in [
        ("Peer.Example.org.", "Peer.Example.org"),
        ("peer-1.example", "peer-1.example"),
        ("localhost", "localhost"),
        (label.as_str(), label.as_str()),
        (at_most, at_most),
    ] {
        assert_eq!(
            host(text),
            (Some(RemoteAddr::Host(expected.into())), vec![]),
            "{text}"
        );
    }
    let too_long_label = format!("{label}a.example");
    for text in [
        &long[..254],
        &too_long_label,
        "-a.example",
        "a-.example",
        "a_b.example",
        "a..b",
        "",
        ".",
    ] {
        assert_eq!(host(text), (None, corrected("remote_addr")), "{text:?}");
    }
}

/// spec: C7, C10
#[test]
fn tunnel_ip_version() {
    let family = |fields: &str| {
        let (t, p) = tunnel(&format!("tunnel_id = 1\n{fields}"));
        let t = t.unwrap();
        (t.remote_addr().is_some(), t.family(), p)
    };
    assert_eq!(
        family("remote_addr = \"192.0.2.1\"\nip_version = \"v4\""),
        (true, Family::V4, vec![])
    );
    assert_eq!(
        family("remote_addr = \"peer.example\"\nip_version = \"v4\""),
        (true, Family::V4, vec![])
    );
    // Required for a host name; IPv6 when nothing else names a family.
    assert_eq!(
        family("remote_addr = \"peer.example\""),
        (false, Family::V6, corrected("ip_version"))
    );
    // A literal of the other family: the family is the one ip_version names.
    assert_eq!(
        family("remote_addr = \"2001:db8::1\"\nip_version = \"V4\""),
        (false, Family::V4, corrected("ip_version"))
    );
    // Invalid: the literal's family.
    assert_eq!(
        family("remote_addr = \"192.0.2.1\"\nip_version = \"V5\""),
        (false, Family::V4, corrected("ip_version"))
    );
    assert_eq!(
        family("remote_addr = \"224.0.0.1\""),
        (false, Family::V4, corrected("remote_addr"))
    );
    assert_eq!(
        family("remote_addr = \"garbage!\"\nip_version = \"V4\""),
        (false, Family::V4, corrected("remote_addr"))
    );
    assert_eq!(
        family("ip_version = \"V4\""),
        (false, Family::V4, corrected("remote_addr"))
    );
    assert_eq!(
        family("remote_addr = \"garbage!\""),
        (false, Family::V6, corrected("remote_addr"))
    );
}

/// spec: C7, K32
#[test]
fn interface_names() {
    for good in ["eth0", "0123456789abcde", "vrf-wan", "a.b"] {
        let (t, p) = tunnel(&format!("{VALID}bind_interface = \"{good}\""));
        assert_eq!(t.unwrap().bind_interface(), Some(&name(good)));
        assert!(p.is_empty(), "{good}");
    }
    for bad in [
        "",
        "0123456789abcdef",
        ".",
        "..",
        "a/b",
        "a:b",
        "a%d",
        "a b",
        "a\\tb",
        "a\\u00a0b",
    ] {
        assert_eq!(
            tunnel(&format!("{VALID}bind_interface = \"{bad}\"")).1,
            left_out("bind_interface"),
            "{bad}"
        );
    }
}

/// spec: C7, V1
#[test]
fn tunnel_resolver_name() {
    let host = "tunnel_id = 1\nremote_addr = \"peer.example\"\nip_version = \"V6\"\n";
    let (t, p) = tunnel(&format!("{host}resolver_name = \"r\""));
    assert_eq!((t.unwrap().resolver_name(), p), (Some("r"), vec![]));
    assert_eq!(
        tunnel(&format!("{host}resolver_name = \"nope\"")).1,
        left_out("resolver_name")
    );
    let (t, p) = tunnel(&format!("{VALID}resolver_name = \"nope\""));
    assert_eq!(
        (t.unwrap().resolver_name(), p),
        (None, corrected("resolver_name"))
    );
}

/// spec: C8
#[test]
fn session_fields() {
    let base = "tunnel_name = \"t\"\nsession_id = 5\ninterface_name = \"l2tp0\"\n";
    let (s, p) = session(base);
    let s = s.unwrap();
    assert!(p.is_empty());
    assert_eq!(
        (s.tunnel_name(), s.session_id(), s.peer_session_id()),
        ("t", 5, 5)
    );
    assert_eq!(s.interface_name(), &name("l2tp0"));
    assert_eq!(
        (s.interface_hwaddr(), s.cookie(), s.peer_cookie()),
        (None, None, None)
    );
    assert_eq!(
        session(&format!("{base}peer_session_id = 6"))
            .0
            .unwrap()
            .peer_session_id(),
        6
    );
    assert_eq!(
        session("session_id = 5\ninterface_name = \"l2tp0\"").1,
        left_out("tunnel_name")
    );
    assert_eq!(
        session("tunnel_name = \"u\"\nsession_id = 5\ninterface_name = \"l2tp0\"").1,
        left_out("tunnel_name")
    );
    assert_eq!(
        session("tunnel_name = \"t\"\ninterface_name = \"l2tp0\"").1,
        left_out("session_id")
    );
    for id in ["0", "-5", "4294967296"] {
        assert_eq!(
            session(&format!(
                "tunnel_name = \"t\"\nsession_id = {id}\ninterface_name = \"l2tp0\""
            ))
            .1,
            left_out("session_id")
        );
        assert_eq!(
            session(&format!("{base}peer_session_id = {id}")).1,
            left_out("peer_session_id")
        );
    }
    assert_eq!(
        session("tunnel_name = \"t\"\nsession_id = 5").1,
        left_out("interface_name")
    );
    assert_eq!(
        session("tunnel_name = \"t\"\nsession_id = 5\ninterface_name = \"l2tp%d\"").1,
        left_out("interface_name")
    );
}

/// spec: C8, C10
#[test]
fn session_hardware_addresses() {
    let base = "tunnel_name = \"t\"\nsession_id = 5\ninterface_name = \"l2tp0\"\n";
    for good in ["02:00:5E:00:53:01", "02-00-5e-00-53-01"] {
        let (s, p) = session(&format!("{base}interface_hwaddr = \"{good}\""));
        assert_eq!(
            s.unwrap().interface_hwaddr().unwrap().octets(),
            [2, 0, 0x5e, 0, 0x53, 1]
        );
        assert!(p.is_empty());
    }
    for bad in [
        "01:00:5e:00:00:01",
        "00:00:00:00:00:00",
        "02:00:5e:00:53",
        "02:00:5e:00:53:01:02",
        "2:0:5e:0:53:1",
        "02:00-5e:00:53:01",
        "02:00:5e:00:53:zz",
    ] {
        let (s, p) = session(&format!("{base}interface_hwaddr = \"{bad}\""));
        assert_eq!(
            s.unwrap().interface_hwaddr(),
            None,
            "{bad}: the kernel's address"
        );
        assert_eq!(p, corrected("interface_hwaddr"), "{bad}");
    }
}

/// spec: C8, O5
#[test]
fn session_cookies() {
    let base = "tunnel_name = \"t\"\nsession_id = 5\ninterface_name = \"l2tp0\"\n";
    let (s, _) = session(&format!("{base}cookie = \"0011AAbb\""));
    let s = s.unwrap();
    assert_eq!(s.cookie().unwrap().as_bytes(), [0, 0x11, 0xaa, 0xbb]);
    assert_eq!(
        s.peer_cookie(),
        s.cookie(),
        "peer_cookie defaults to cookie"
    );
    let (s, _) = session(&format!(
        "{base}cookie = \"0011223344556677\"\npeer_cookie = \"8899aabb\""
    ));
    let s = s.unwrap();
    assert_eq!(s.cookie().unwrap().as_bytes().len(), 8);
    assert_eq!(
        s.peer_cookie().unwrap().as_bytes(),
        [0x88, 0x99, 0xaa, 0xbb]
    );
    for bad in ["001122", "00112233445566778899", "zz112233", "0011223", ""] {
        for field in ["cookie", "peer_cookie"] {
            let (s, problems) = lenient(&format!(
                "[tunnels.t]\n{VALID}[sessions.s]\n{base}{field} = \"{bad}\""
            ));
            assert!(s.sessions().is_empty());
            assert_eq!(summary(&problems)[0].1, Some(field));
            if !bad.is_empty() {
                assert!(
                    !problems[0].to_string().contains(bad),
                    "O5: {}",
                    problems[0]
                );
            }
        }
    }
}

/// spec: C16, V2
#[test]
fn resolver_addresses() {
    let (r, p) = resolver(
        "addresses = [\"192.0.2.53\", \"192.0.2.53:5353\", \"[2001:db8::53]:5353\", \"2001:db8::53\", \
         \"[fe80::53%eth0]:53\", \"fe80::53%eth0\", \"::ffff:192.0.2.54\", \"[2001:db8::54]\"]",
    );
    assert!(p.is_empty());
    let r = r.unwrap();
    let servers: Vec<String> = r.addresses().iter().map(ToString::to_string).collect();
    assert_eq!(
        servers,
        [
            "192.0.2.53",
            "192.0.2.53:5353",
            "[2001:db8::53]:5353",
            "2001:db8::53",
            "fe80::53%eth0",
            "fe80::53%eth0",
            "192.0.2.54",
            "2001:db8::54"
        ]
    );
    assert_eq!(
        (r.addresses()[1].port(), r.addresses()[0].port()),
        (5353, 53)
    );
    assert_eq!(r.method(), None);
    for bad in [
        "[]",
        "[\"224.0.0.1\"]",
        "[\"192.0.2.53:0\"]",
        "[\"192.0.2.53:+53\"]",
        "[\"192.0.2.53:x\"]",
        "[\"[2001:db8::53]x\"]",
        "[\"[2001:db8::53\"]",
        "[\"name.example\"]",
        "[\"2001:db8::53%eth0\"]",
        "[\"fe80::53%a/b\"]",
        "[\"fe80::53\"]",
    ] {
        assert_eq!(
            resolver(&format!("addresses = {bad}")).1,
            left_out("addresses"),
            "{bad}"
        );
    }
    // A link-local server without a zone needs the bind interface.
    let (r, p) = resolver("addresses = [\"fe80::53\"]\nbind_interface = \"eth0\"");
    assert_eq!(
        (r.unwrap().bind_interface(), p),
        (Some(&name("eth0")), vec![])
    );
    assert_eq!(
        resolver("addresses = [\"192.0.2.53\"]\nbind_interface = \"a/b\"").1,
        left_out("bind_interface")
    );
}

/// spec: C16, V2
#[test]
fn resolver_methods() {
    for (text, method) in [
        ("RA", Method::Ra),
        ("dhcpv6", Method::Dhcpv6),
        ("IPv6", Method::Ipv6),
    ] {
        let (r, p) = resolver(&format!("method = \"{text}\"\nbind_interface = \"wan0\""));
        let r = r.unwrap();
        assert_eq!(
            (r.method(), r.addresses().is_empty(), p),
            (Some(method), true, vec![])
        );
        assert_eq!(r.dhcpv6_identity(), &Dhcpv6Identity::LinkLayer);
    }
    assert_eq!(resolver("method = \"ra\"").1, left_out("bind_interface"));
    assert_eq!(
        resolver("method = \"slaac\"\nbind_interface = \"wan0\"").1,
        left_out("method")
    );
    assert_eq!(
        resolver("method = \"ra\"\nbind_interface = \"wan0\"\naddresses = [\"192.0.2.53\"]").1,
        left_out("method")
    );
    assert_eq!(
        resolver("bind_interface = \"wan0\"").1,
        left_out("addresses")
    );
}

/// spec: C16, V12
#[test]
fn resolver_dhcpv6_identities() {
    let dhcpv6 = "method = \"dhcpv6\"\nbind_interface = \"wan0\"\n";
    for (text, identity) in [
        ("Link-Layer", Dhcpv6Identity::LinkLayer),
        ("anonymous", Dhcpv6Identity::Anonymous),
        ("RANDOM", Dhcpv6Identity::Random),
    ] {
        let (r, p) = resolver(&format!("{dhcpv6}dhcpv6_identity = \"{text}\""));
        assert_eq!((r.unwrap().dhcpv6_identity(), p), (&identity, vec![]));
    }
    assert_eq!(
        resolver(&format!("{dhcpv6}dhcpv6_identity = \"mac\"")).1,
        left_out("dhcpv6_identity")
    );
    let duid = |digits: usize| "a".repeat(digits);
    for good in [6, 260] {
        let (r, p) = resolver(&format!("{dhcpv6}dhcpv6_duid = \"{}\"", duid(good)));
        assert_eq!(
            (r.unwrap().dhcpv6_identity(), p),
            (&Dhcpv6Identity::Duid(vec![0xaa; good / 2]), vec![])
        );
    }
    for bad in [4, 7, 262] {
        assert_eq!(
            resolver(&format!("{dhcpv6}dhcpv6_duid = \"{}\"", duid(bad))).1,
            left_out("dhcpv6_duid"),
            "{bad}"
        );
    }
    assert_eq!(
        resolver(&format!(
            "{dhcpv6}dhcpv6_identity = \"random\"\ndhcpv6_duid = \"000300010200\""
        ))
        .1,
        left_out("dhcpv6_duid")
    );
    // Meaningful with dhcpv6 and ipv6 only; ignored with a warning otherwise.
    for other in [
        "method = \"ra\"\nbind_interface = \"wan0\"",
        "addresses = [\"192.0.2.53\"]",
    ] {
        let (r, p) = resolver(&format!("{other}\ndhcpv6_identity = \"anonymous\""));
        assert_eq!(
            (r.unwrap().dhcpv6_identity(), p),
            (&Dhcpv6Identity::LinkLayer, corrected("dhcpv6_identity"))
        );
        let (r, p) = resolver(&format!("{other}\ndhcpv6_duid = \"000300010200\""));
        assert_eq!(
            (r.unwrap().dhcpv6_identity(), p),
            (&Dhcpv6Identity::LinkLayer, corrected("dhcpv6_duid"))
        );
    }
}

/// spec: C17
#[test]
fn host_settings() {
    assert!(lenient("").0.host().fix_bindv6only());
    assert!(
        !lenient("[host]\nfix_bindv6only = false")
            .0
            .host()
            .fix_bindv6only()
    );
    assert!(
        lenient("[host]\nfix_bindv6only = true")
            .0
            .host()
            .fix_bindv6only()
    );
}

/// spec: C9, R14
#[test]
fn uniqueness_in_byte_order_of_names() {
    let tunnels = |a: &str, b: &str| {
        let (config, problems) = lenient(&format!(
            "[tunnels.{a}]\n{VALID}[tunnels.{b}]\ntunnel_id = 1\nremote_addr = \"192.0.2.2\"\n"
        ));
        (
            config.tunnels().keys().cloned().collect::<Vec<_>>(),
            summary(&problems),
        )
    };
    let at_fault = |name: &str| vec![(name.to_string(), Some("tunnel_id"), Effect::LeftOut)];
    assert_eq!(tunnels("a", "b"), (vec!["a".to_string()], at_fault("b")));
    assert_eq!(tunnels("b", "a"), (vec!["a".to_string()], at_fault("b")));
    assert_eq!(tunnels("a", "B"), (vec!["B".to_string()], at_fault("a")));
    // Sessions: identifiers across tunnels, interface names.
    let (config, problems) = lenient(&format!(
        "[tunnels.t]\n{VALID}[tunnels.u]\ntunnel_id = 2\nremote_addr = \"192.0.2.2\"\n\
         [sessions.a]\ntunnel_name = \"t\"\nsession_id = 5\ninterface_name = \"l2tp0\"\n\
         [sessions.b]\ntunnel_name = \"u\"\nsession_id = 5\ninterface_name = \"l2tp1\"\n\
         [sessions.c]\ntunnel_name = \"u\"\nsession_id = 6\ninterface_name = \"l2tp0\"\n"
    ));
    assert_eq!(config.sessions().keys().collect::<Vec<_>>(), ["a"]);
    assert_eq!(
        summary(&problems),
        [
            ("b".into(), Some("session_id"), Effect::LeftOut),
            ("c".into(), Some("interface_name"), Effect::LeftOut)
        ]
    );
    // Resolver names are a space of their own.
    let (config, problems) = lenient(&format!(
        "[resolvers.x]\naddresses = [\"192.0.2.53\"]\n[tunnels.x]\n{VALID}[sessions.x]\n\
         tunnel_name = \"x\"\nsession_id = 1\ninterface_name = \"l2tp0\"\n"
    ));
    assert!(problems.is_empty());
    assert_eq!(
        (
            config.resolvers().len(),
            config.tunnels().len(),
            config.sessions().len()
        ),
        (1, 1, 1)
    );
}

/// spec: C10
#[test]
fn start_up_leaves_out_and_takes_dependents() {
    let (config, problems) = lenient(
        "[resolvers.bad]\nmethod = \"ra\"\n\
         [tunnels.named]\ntunnel_id = 1\nremote_addr = \"peer.example\"\nip_version = \"V6\"\nresolver_name = \"bad\"\n\
         [tunnels.broken]\ntunnel_id = 0\nremote_addr = \"192.0.2.1\"\n\
         [tunnels.peerless]\ntunnel_id = 3\nremote_addr = \"ff02::1\"\n\
         [sessions.a]\ntunnel_name = \"named\"\nsession_id = 1\ninterface_name = \"l2tp1\"\n\
         [sessions.b]\ntunnel_name = \"broken\"\nsession_id = 2\ninterface_name = \"l2tp2\"\n\
         [sessions.c]\ntunnel_name = \"peerless\"\nsession_id = 3\ninterface_name = \"l2tp3\"\n",
    );
    assert_eq!(
        summary(&problems),
        [
            ("bad".into(), Some("bind_interface"), Effect::LeftOut),
            ("broken".into(), Some("tunnel_id"), Effect::LeftOut),
            ("named".into(), Some("resolver_name"), Effect::LeftOut),
            ("peerless".into(), Some("remote_addr"), Effect::Corrected),
            ("a".into(), Some("tunnel_name"), Effect::LeftOut),
            ("b".into(), Some("tunnel_name"), Effect::LeftOut),
        ]
    );
    // The tunnel without a peer exists, and so do its sessions.
    assert_eq!(config.tunnels().keys().collect::<Vec<_>>(), ["peerless"]);
    assert_eq!(config.sessions().keys().collect::<Vec<_>>(), ["c"]);
    assert_eq!(
        problems[3].to_string(),
        "tunnel \"peerless\", remote_addr: ff02::1 is not a unicast address tunnel_id=3; applied without a peer"
    );
    assert_eq!(
        problems[0].to_string(),
        "resolver \"bad\", bind_interface: required with method ra; left out"
    );
}

/// spec: C10
#[test]
fn an_empty_result_is_valid() {
    let (config, problems) = lenient("");
    assert_eq!((config, problems), (Config::new(), vec![]));
    let (config, problems) = lenient("[tunnels.t]\n[sessions.s]\n");
    assert_eq!(config, Config::new());
    assert_eq!(problems.len(), 2);
}

/// spec: C12
#[test]
fn reload_keeps_values_in_force() {
    let doc = |a: &str| {
        format!(
            "[tunnels.a]\ntunnel_id = {a}\nremote_addr = \"192.0.2.1\"\n\
             [sessions.s]\ntunnel_name = \"a\"\nsession_id = 1\ninterface_name = \"l2tp0\"\n"
        )
    };
    let (previous, _) = lenient(&doc("10"));
    // A hard mistake of an entry in force keeps its values.
    let (config, problems) = reload(&previous, &doc("0")).unwrap();
    assert_eq!(config, previous);
    assert_eq!(
        summary(&problems),
        [("a".into(), Some("tunnel_id"), Effect::KeptPrevious)]
    );
    // A new entry with a hard mistake is left out.
    let (config, problems) = reload(
        &previous,
        &format!("{}[tunnels.b]\ntunnel_id = 0\n", doc("10")),
    )
    .unwrap();
    assert_eq!(config, previous);
    assert_eq!(
        summary(&problems),
        [("b".into(), Some("tunnel_id"), Effect::LeftOut)]
    );
    // A tolerated mistake as at start-up.
    let (config, problems) = reload(&previous, &doc("10").replace("192.0.2.1", "ff02::1")).unwrap();
    assert!(config.tunnels()["a"].remote_addr().is_none());
    assert_eq!(
        summary(&problems),
        [("a".into(), Some("remote_addr"), Effect::Corrected)]
    );
    // Removal is no problem.
    assert_eq!(reload(&previous, "").unwrap(), (Config::new(), vec![]));
}

/// A reload that fixes a tolerated mistake gives the entry the corrected
/// value under the same kernel identity, so that it is applied in place.
/// spec: C11, C14
#[test]
fn a_reload_corrects_tolerated_mistakes_in_place() {
    let doc = |peer: &str, hwaddr: &str| {
        format!(
            "[tunnels.a]\ntunnel_id = 1\nremote_addr = \"{peer}\"\n[sessions.s]\ntunnel_name = \"a\"\n\
             session_id = 1\ninterface_name = \"l2tp0\"\ninterface_hwaddr = \"{hwaddr}\"\n"
        )
    };
    let (previous, problems) = lenient(&doc("ff02::1", "01:00:00:00:00:01"));
    assert_eq!(problems.len(), 2);
    let (config, problems) = reload(&previous, &doc("2001:db8::1", "02:00:00:00:00:01")).unwrap();
    assert!(problems.is_empty());
    assert!(config.tunnels()["a"].remote_addr().is_some());
    assert!(config.sessions()["s"].interface_hwaddr().is_some());
    assert_eq!(
        config.tunnels()["a"].identity(),
        previous.tunnels()["a"].identity()
    );
    assert_eq!(config.session_identity("s"), previous.session_identity("s"));
}

/// The example of C12: `a` had 10 and `b` 20; the reload gives `a` a hard
/// mistake and `b` 10, and is refused naming `a`, whatever the names.
/// spec: C12, C9
#[test]
fn reload_refused_when_values_in_force_no_longer_fit() {
    for (a, b) in [("a", "b"), ("z", "b")] {
        let (previous, _) = lenient(&format!(
            "[tunnels.{a}]\ntunnel_id = 10\nremote_addr = \"192.0.2.1\"\n\
             [tunnels.{b}]\ntunnel_id = 20\nremote_addr = \"192.0.2.2\"\n"
        ));
        let problems = reload(
            &previous,
            &format!(
                "[tunnels.{a}]\ntunnel_id = 10\nremote_addr = \"192.0.2.1\"\nbind_interface = \"a/b\"\n\
                 [tunnels.{b}]\ntunnel_id = 10\nremote_addr = \"192.0.2.2\"\n"
            ),
        )
        .unwrap_err();
        assert_eq!(
            summary(&problems),
            [
                (a.into(), Some("bind_interface"), Effect::KeptPrevious),
                (a.into(), Some("tunnel_id"), Effect::Refused),
            ]
        );
    }
    // Two valid entries of the accepted configuration that now collide:
    // the later one has a hard mistake, and its values in force collide.
    let (previous, _) = lenient(
        "[tunnels.a]\ntunnel_id = 10\nremote_addr = \"192.0.2.1\"\n\
         [tunnels.b]\ntunnel_id = 20\nremote_addr = \"192.0.2.2\"\n",
    );
    let problems = reload(
        &previous,
        "[tunnels.a]\ntunnel_id = 20\nremote_addr = \"192.0.2.1\"\n\
         [tunnels.b]\ntunnel_id = 20\nremote_addr = \"192.0.2.2\"\n",
    )
    .unwrap_err();
    assert_eq!(
        summary(&problems).last().unwrap(),
        &("b".into(), Some("tunnel_id"), Effect::Refused)
    );
}

/// spec: C12, V13
#[test]
fn reload_refused_when_a_dependency_is_removed() {
    let (previous, _) = lenient(&format!(
        "{RESOLVER}[tunnels.t]\ntunnel_id = 1\nremote_addr = \"peer.example\"\nip_version = \"V6\"\n\
         resolver_name = \"r\"\n[sessions.s]\ntunnel_name = \"t\"\nsession_id = 1\ninterface_name = \"l2tp0\"\n"
    ));
    assert_eq!(previous.tunnels().len(), 1);
    // The resolver is removed while the tunnel still names it.
    let problems = reload(
        &previous,
        "[tunnels.t]\ntunnel_id = 1\nremote_addr = \"peer.example\"\nip_version = \"V6\"\n\
         resolver_name = \"r\"\n[sessions.s]\ntunnel_name = \"t\"\nsession_id = 1\ninterface_name = \"l2tp0\"\n",
    )
    .unwrap_err();
    assert_eq!(
        summary(&problems).last().unwrap(),
        &("t".into(), Some("resolver_name"), Effect::Refused)
    );
    // The tunnel is removed while the session still names it.
    let problems = reload(
        &previous,
        &format!("{RESOLVER}[sessions.s]\ntunnel_name = \"t\"\nsession_id = 1\ninterface_name = \"l2tp0\"\n"),
    )
    .unwrap_err();
    assert_eq!(
        problems.last().unwrap().to_string(),
        "session \"s\", tunnel_name: no tunnel \"t\" in the configuration session_id=1; the reload is refused"
    );
}

/// spec: C12
#[test]
fn new_valid_entries_collide_among_themselves_first() {
    let (previous, _) = lenient(&format!("[tunnels.a]\n{VALID}"));
    let (config, problems) = reload(
        &previous,
        &format!("[tunnels.a]\n{VALID}[tunnels.b]\ntunnel_id = 1\nremote_addr = \"192.0.2.2\"\n"),
    )
    .unwrap();
    assert_eq!(config, previous);
    assert_eq!(
        summary(&problems),
        [("b".into(), Some("tunnel_id"), Effect::LeftOut)]
    );
}

/// The example of C2, and tables merged rather than replaced.
/// spec: C2
#[test]
fn merging() {
    let mut main = partial(
        "[host]\nfix_bindv6only = false\n[tunnels.a]\ntunnel_id = 1\nremote_addr = \"192.0.2.1\"\n",
    );
    main.merge(partial(
        "[tunnels.a]\nremote_addr = \"192.0.2.2\"\n[sessions.s]\ntunnel_name = \"a\"\nsession_id = 1\n",
    ));
    main.merge(partial(
        "[sessions.s]\ninterface_name = \"l2tp0\"\n[host]\n",
    ));
    let (config, problems) = main.into_config_lenient();
    assert!(problems.is_empty());
    let a = &config.tunnels()["a"];
    assert_eq!(a.tunnel_id(), 1);
    assert_eq!(a.remote_addr().unwrap().to_string(), "192.0.2.2");
    assert_eq!(config.sessions()["s"].interface_name(), &name("l2tp0"));
    assert!(!config.host().fix_bindv6only());
}

/// The accepted configuration has its tolerated mistakes corrected, and
/// the rendering reads back as the same configuration; a tunnel without a
/// peer is rendered without `remote_addr`, which is still a problem.
/// spec: C13, O8
#[test]
fn accepted_configuration_reads_back() {
    let (config, problems) = lenient(&format!(
        "{RESOLVER}[resolvers.d]\nmethod = \"IPV6\"\nbind_interface = \"wan0\"\ndhcpv6_duid = \"000300010200\"\n\
         [tunnels.a]\ntunnel_id = 1\nremote_addr = \"fe80::1%eth0\"\n\
         [tunnels.b]\ntunnel_id = 2\nremote_addr = \"224.0.0.1\"\n\
         [tunnels.c]\ntunnel_id = 3\npeer_tunnel_id = 4\nremote_addr = \"peer.example.\"\nip_version = \"v6\"\n\
         resolver_name = \"r\"\nbind_interface = \"vrf-wan\"\n\
         [sessions.s]\ntunnel_name = \"b\"\nsession_id = 1\ninterface_name = \"l2tp0\"\n\
         interface_hwaddr = \"01:00:00:00:00:01\"\ncookie = \"00112233\"\n\
         [sessions.t]\ntunnel_name = \"c\"\nsession_id = 2\npeer_session_id = 3\ninterface_name = \"l2tp1\"\n\
         interface_hwaddr = \"02-00-5E-00-53-01\"\ncookie = \"0011223344556677\"\npeer_cookie = \"8899aabb\"\n"
    ));
    assert_eq!(problems.len(), 2);
    let rendered = toml::to_string(&config).unwrap();
    let (again, problems) = lenient(&rendered);
    assert_eq!(again, config, "{rendered}");
    assert_eq!(
        summary(&problems),
        [("b".into(), Some("remote_addr"), Effect::Corrected)]
    );
}

/// spec: O8
#[test]
fn check_mode_rendering_order() {
    let (config, _) = lenient(
        "[sessions.s]\ncookie = \"00112233\"\ninterface_name = \"l2tp0\"\nsession_id = 10\ntunnel_name = \"b\"\n\
         [tunnels.b]\nremote_addr = \"peer.example\"\nresolver_name = \"r\"\nip_version = \"v6\"\ntunnel_id = 2\n\
         [tunnels.a]\nremote_addr = \"::ffff:192.0.2.1\"\npeer_tunnel_id = 3\ntunnel_id = 1\n\
         [resolvers.r]\naddresses = [\"192.0.2.53\", \"[2001:db8::53]:5353\"]\n\
         [host]\nfix_bindv6only = false\n",
    );
    assert_eq!(
        toml::to_string(&config).unwrap(),
        "[host]\nfix_bindv6only = false\n\n\
         [resolvers.r]\naddresses = [\"192.0.2.53\", \"[2001:db8::53]:5353\"]\n\n\
         [tunnels.a]\ntunnel_id = 1\npeer_tunnel_id = 3\nremote_addr = \"192.0.2.1\"\n\n\
         [tunnels.b]\ntunnel_id = 2\nremote_addr = \"peer.example\"\nip_version = \"V6\"\nresolver_name = \"r\"\n\n\
         [sessions.s]\ntunnel_name = \"b\"\nsession_id = 10\ninterface_name = \"l2tp0\"\ncookie = \"00112233\"\n"
    );
    assert_eq!(toml::to_string(&Config::new()).unwrap(), "");
}

/// Entries are matched by kernel identity, not by name.
/// spec: C14, T23, S17
#[test]
fn kernel_identities() {
    let doc = |tunnel: &str, peer: &str, session: &str, cookies: &str| {
        lenient(&format!(
            "[tunnels.{tunnel}]\ntunnel_id = 1\n{peer}remote_addr = \"192.0.2.1\"\n\
             [sessions.{session}]\ntunnel_name = \"{tunnel}\"\nsession_id = 5\ninterface_name = \"l2tp0\"\n{cookies}"
        ))
        .0
    };
    let base = doc("a", "", "s", "cookie = \"00112233\"\n");
    let renamed = doc(
        "b",
        "",
        "u",
        "cookie = \"00112233\"\npeer_cookie = \"00112233\"\n",
    );
    assert_eq!(
        base.tunnels()["a"].identity(),
        renamed.tunnels()["b"].identity()
    );
    assert_eq!(base.session_identity("s"), renamed.session_identity("u"));
    assert_eq!(base.session_identity("nope"), None);
    let peer = doc("a", "peer_tunnel_id = 2\n", "s", "cookie = \"00112233\"\n");
    assert_ne!(
        base.tunnels()["a"].identity(),
        peer.tunnels()["a"].identity()
    );
    assert_ne!(base.session_identity("s"), peer.session_identity("s"));
    let cookie = doc(
        "a",
        "",
        "s",
        "cookie = \"00112233\"\npeer_cookie = \"00112234\"\n",
    );
    assert_ne!(base.session_identity("s"), cookie.session_identity("s"));
}

/// spec: C15
#[test]
fn strict_conversion() {
    let doc =
        format!("[tunnels.t]\n{VALID}[tunnels.u]\ntunnel_id = 2\nremote_addr = \"ff02::1\"\n");
    let err = Config::try_from(partial(&doc)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid configuration: tunnel \"u\", remote_addr: ff02::1 is not a unicast address tunnel_id=2"
    );
    let err = toml::from_str::<Config>(&doc).unwrap_err().to_string();
    assert!(err.contains("tunnel \"u\", remote_addr"), "{err}");
    let config = toml::from_str::<Config>(&format!("[tunnels.t]\n{VALID}")).unwrap();
    assert_eq!(config.tunnels().len(), 1);
    // Every problem carries its kind, name, field, effect and error.
    let (_, problems) = lenient(&doc);
    assert_eq!(
        problems[0].kind(),
        &ProblemKind::Entry {
            kind: EntryKind::Tunnel,
            name: "u".into(),
            field: Some("remote_addr")
        }
    );
    assert_eq!(
        (problems[0].effect(), problems[0].message()),
        (Effect::Corrected, "ff02::1 is not a unicast address")
    );
}

/// The configuration format of 0.1.5 keeps working.
/// spec: G22
#[test]
fn format_of_0_1_5() {
    let config = toml::from_str::<Config>(
        "[tunnels.t]\ntunnel_id = 1\npeer_tunnel_id = 1\nip_version = \"V6\"\nremote_addr = \"peer.example\"\n\
         bind_interface = \"eth0\"\n[sessions.s]\ntunnel_name = \"t\"\nsession_id = 1\npeer_session_id = 1\n\
         interface_name = \"l2tp0\"\n",
    )
    .unwrap();
    assert_eq!(config.sessions().len(), 1);
}

/// Every constructor and insertion validates, so that a `Config` cannot
/// hold an invalid entry.
/// spec: L4, C7, C8, C9, C16
#[test]
fn builders_and_insertions_validate() {
    let v4 = |s: &str| RemoteAddr::Ip {
        addr: s.parse().unwrap(),
        zone: None,
    };
    let built = |b: TunnelConfigBuilder| b.build().map_err(|e| e.to_string());
    assert!(built(TunnelConfig::builder(0).remote_addr(v4("192.0.2.1"))).is_err());
    assert!(
        built(
            TunnelConfig::builder(1)
                .peer_tunnel_id(0)
                .remote_addr(v4("192.0.2.1"))
        )
        .is_err()
    );
    assert!(built(TunnelConfig::builder(1).remote_addr(v4("224.0.0.1"))).is_err());
    assert!(
        built(
            TunnelConfig::builder(1)
                .remote_addr(v4("192.0.2.1"))
                .ip_version(Family::V6)
        )
        .is_err()
    );
    assert!(
        built(
            TunnelConfig::builder(1)
                .remote_addr(v4("192.0.2.1"))
                .resolver_name("r")
        )
        .is_err()
    );
    assert!(
        built(
            TunnelConfig::builder(1)
                .remote_addr(v4("192.0.2.1"))
                .bind_interface(name("a%b"))
        )
        .is_err()
    );
    assert!(
        built(
            TunnelConfig::builder(1)
                .remote_addr(RemoteAddr::Host("a..b".into()))
                .ip_version(Family::V4)
        )
        .is_err()
    );
    assert!(
        built(TunnelConfig::builder(1).remote_addr(RemoteAddr::Host("peer.example".into())))
            .is_err()
    );
    assert_eq!(
        built(TunnelConfig::builder(1).remote_addr(v4("fe80::1"))).unwrap_err(),
        "invalid configuration: remote_addr: fe80::1 is link-local: it needs a zone or bind_interface"
    );
    let zoned = RemoteAddr::Ip {
        addr: "2001:db8::1".parse().unwrap(),
        zone: Some(name("eth0")),
    };
    assert!(built(TunnelConfig::builder(1).remote_addr(zoned)).is_err());
    assert!(
        built(TunnelConfig::builder(1)).is_err(),
        "no peer and no family"
    );
    let peerless = built(TunnelConfig::builder(1).ip_version(Family::V4)).unwrap();
    assert_eq!(
        (peerless.remote_addr(), peerless.family()),
        (None, Family::V4)
    );
    let t = built(TunnelConfig::builder(1).remote_addr(v4("::ffff:192.0.2.1"))).unwrap();
    assert_eq!(t.remote_addr(), Some(&v4("192.0.2.1")));
    let host = built(
        TunnelConfig::builder(2)
            .remote_addr(RemoteAddr::Host("peer.example.".into()))
            .ip_version(Family::V6)
            .resolver_name("r")
            .bind_interface(name("vrf0")),
    )
    .unwrap();
    assert_eq!(
        host.remote_addr(),
        Some(&RemoteAddr::Host("peer.example".into()))
    );

    let mut config = Config::new();
    assert!(
        config.insert_tunnel("h", host.clone()).is_err(),
        "no resolver r"
    );
    let r = ResolverConfig::with_addresses(
        vec![NameServer::new("192.0.2.53".parse().unwrap(), None, 53).unwrap()],
        None,
    )
    .unwrap();
    config.insert_resolver("r", r).unwrap();
    config.insert_tunnel("h", host).unwrap();
    config.insert_tunnel("t", t.clone()).unwrap();
    config.insert_tunnel("t", t.clone()).unwrap();
    assert!(config.insert_tunnel("u", t).is_err(), "tunnel_id taken");
    assert!(config.insert_tunnel("n".repeat(65), peerless).is_err());
    let s = SessionConfig::builder("t", 5, name("l2tp0"))
        .build()
        .unwrap();
    assert!(
        config
            .insert_session(
                "s",
                SessionConfig::builder("x", 5, name("l2tp0"))
                    .build()
                    .unwrap()
            )
            .is_err()
    );
    config.insert_session("s", s.clone()).unwrap();
    config.insert_session("s", s).unwrap();
    assert!(
        config
            .insert_session(
                "u",
                SessionConfig::builder("t", 5, name("l2tp1"))
                    .build()
                    .unwrap()
            )
            .is_err()
    );
    assert!(
        config
            .insert_session(
                "u",
                SessionConfig::builder("t", 6, name("l2tp0"))
                    .build()
                    .unwrap()
            )
            .is_err()
    );
    assert!(
        SessionConfig::builder("t", 0, name("l2tp0"))
            .build()
            .is_err()
    );
    assert!(
        SessionConfig::builder("t", 1, name("l2tp0"))
            .peer_session_id(0)
            .build()
            .is_err()
    );
    assert!(
        SessionConfig::builder("t", 1, name("l2tp%d"))
            .build()
            .is_err()
    );
    let full = SessionConfig::builder("t", 7, name("l2tp2"))
        .peer_session_id(8)
        .interface_hwaddr(HwAddr::new([2, 0, 0, 0, 0, 1]).unwrap())
        .cookie(Cookie::new(&[1, 2, 3, 4]).unwrap())
        .peer_cookie(Cookie::new(&[1; 8]).unwrap())
        .build()
        .unwrap();
    config.insert_session("full", full).unwrap();
    assert!(
        config
            .insert_session(
                "bad\n",
                SessionConfig::builder("t", 9, name("l2tp9"))
                    .build()
                    .unwrap()
            )
            .is_err()
    );
    config.set_host(HostConfig::new().with_fix_bindv6only(false));
    assert!(!config.host().fix_bindv6only());

    assert!(Cookie::new(&[1, 2, 3]).is_err());
    assert!(HwAddr::new([1, 0, 0, 0, 0, 0]).is_err());
    assert!(HwAddr::new([0; 6]).is_err());
    let ll = "fe80::53".parse().unwrap();
    assert!(NameServer::new("192.0.2.53".parse().unwrap(), Some(name("eth0")), 53).is_err());
    assert!(NameServer::new("192.0.2.53".parse().unwrap(), None, 0).is_err());
    assert!(NameServer::new("ff02::1".parse().unwrap(), None, 53).is_err());
    let server = NameServer::new(ll, Some(name("eth0")), 5353).unwrap();
    assert_eq!(
        (server.addr(), server.zone(), server.to_string()),
        (ll, Some(&name("eth0")), "[fe80::53%eth0]:5353".into())
    );
    assert!(ResolverConfig::with_addresses(vec![], None).is_err());
    assert!(
        ResolverConfig::with_addresses(vec![NameServer::new(ll, None, 53).unwrap()], None).is_err()
    );
    assert!(
        ResolverConfig::with_method(Method::Ra, name("wan0"), Some(Dhcpv6Identity::Anonymous))
            .is_err()
    );
    assert!(
        ResolverConfig::with_method(
            Method::Dhcpv6,
            name("wan0"),
            Some(Dhcpv6Identity::Duid(vec![1, 2]))
        )
        .is_err()
    );
    assert!(ResolverConfig::with_method(Method::Ipv6, name("wan%d"), None).is_err());
    let d = ResolverConfig::with_method(Method::Dhcpv6, name("wan0"), Some(Dhcpv6Identity::Random))
        .unwrap();
    assert_eq!(d.dhcpv6_identity(), &Dhcpv6Identity::Random);
}

/// spec: O5
#[test]
fn cookies_are_never_formatted() {
    let cookie = Cookie::new(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
    assert_eq!(format!("{cookie:?}"), "Cookie(4 bytes)");
    let session = SessionConfig::builder("t", 1, name("l2tp0"))
        .cookie(cookie)
        .build()
        .unwrap();
    let debug = format!("{session:?}");
    assert!(
        !debug.contains("dead") && !debug.contains("beef"),
        "{debug}"
    );
    assert_eq!(
        format!("{:?}", HwAddr::new([2, 0, 0x5e, 0, 0x53, 1]).unwrap()),
        "HwAddr(02:00:5e:00:53:01)"
    );
}

/// Static validation must not infer a device kind, MAC or membership from a name.
/// spec: C16, T27, L4
#[test]
fn host_dependent_conditions_are_not_parse_errors() {
    for fields in [
        "method = \"ra\"",
        "method = \"dhcpv6\"",
        "method = \"ipv6\"",
        "addresses = [\"192.0.2.53\"]",
    ] {
        let (config, problems) = resolver(&format!("{fields}\nbind_interface = \"vrf-missing\""));
        assert!(config.is_some());
        assert!(problems.is_empty());
    }
    let (config, problems) = tunnel(
        "tunnel_id = 1\nremote_addr = \"fe80::1%absent-zone\"\nbind_interface = \"absent-vrf\"",
    );
    assert!(config.is_some());
    assert!(problems.is_empty());
}

/// Irrelevant valid fields are tolerated; malformed values remain errors.
/// spec: C10, C11, C16
#[test]
fn irrelevant_dhcpv6_fields_still_validate_their_values() {
    for fields in [
        "method = \"ra\"\nbind_interface = \"wan0\"",
        "addresses = [\"192.0.2.53\"]",
    ] {
        for (key, value) in [("dhcpv6_identity", "unknown"), ("dhcpv6_duid", "xyz")] {
            let (config, problems) = resolver(&format!("{fields}\n{key} = \"{value}\""));
            assert!(config.is_none());
            assert_eq!(problems, left_out(key));
        }
    }
}

/// spec: C7 C10
#[test]
fn completion_host_names_and_mapped_family() {
    for host in [
        "300.1.1.1",
        "1.2.3",
        "01.2.3.4",
        "a.123",
        "123",
        "é.example",
    ] {
        let (entry, problems) = tunnel(&format!(
            "tunnel_id=1\nremote_addr='{host}'\nip_version='V6'"
        ));
        assert!(entry.unwrap().remote_addr().is_none(), "{host}");
        assert_eq!(problems, corrected("remote_addr"), "{host}");
    }
    let host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(host.len(), 253);
    let (entry, problems) = tunnel(&format!(
        "tunnel_id=1\nremote_addr='{host}.'\nip_version='V6'"
    ));
    assert!(problems.is_empty());
    assert_eq!(entry.unwrap().remote_addr(), Some(&RemoteAddr::Host(host)));
    let (entry, problems) = tunnel("tunnel_id=1\nremote_addr='::ffff:192.0.2.1'\nip_version='V6'");
    assert!(entry.unwrap().remote_addr().is_none());
    assert_eq!(problems, corrected("ip_version"));
}

/// spec: C7 C10 C13 O8
#[test]
fn completion_corrected_host_retains_resolver() {
    for endpoint in ["peer.example", "bad host"] {
        let (entry, problems) = tunnel(&format!(
            "tunnel_id=1\nremote_addr='{endpoint}'\nresolver_name='r'"
        ));
        let entry = entry.unwrap();
        assert!(entry.remote_addr().is_none());
        assert_eq!(entry.resolver_name(), Some("r"));
        assert_eq!(problems.len(), 1);
    }
    let (entry, problems) =
        tunnel("tunnel_id=1\nremote_addr='192.0.2.1'\nip_version='V6'\nresolver_name='r'");
    assert!(entry.unwrap().resolver_name().is_none());
    assert_eq!(problems.len(), 2);
}

/// spec: C7 C10 T27 R47
#[test]
fn completion_hard_endpoint_mistake_precedes_tolerated_family() {
    for family in ["V4", "bad"] {
        let (entry, problems) = tunnel(&format!(
            "tunnel_id=1\nremote_addr='fe80::1'\nip_version='{family}'"
        ));
        assert!(entry.is_none());
        assert_eq!(problems, left_out("remote_addr"));
    }
}

/// spec: C12
#[test]
fn completion_new_collision_keeps_an_accepted_name() {
    let previous = lenient("[tunnels.b]\ntunnel_id=2\nremote_addr='192.0.2.2'").0;
    let (config, problems) = reload(&previous, "[tunnels.a]\ntunnel_id=1\nremote_addr='192.0.2.1'\n[tunnels.b]\ntunnel_id=1\nremote_addr='192.0.2.3'").unwrap();
    assert_eq!(config.tunnels()["b"], previous.tunnels()["b"]);
    assert_eq!(config.tunnels()["a"].tunnel_id(), 1);
    assert_eq!(
        summary(&problems),
        [("b".into(), Some("tunnel_id"), Effect::KeptPrevious)]
    );
}

/// spec: C2
#[test]
fn completion_empty_tables_do_not_remove_merged_values() {
    let mut before = partial(&format!("[tunnels.t]\n{VALID}"));
    before.merge(partial("[tunnels.t]\n"));
    let (config, problems) = before.into_config_lenient();
    assert!(problems.is_empty());
    assert_eq!(
        config.tunnels()["t"].remote_addr().unwrap().to_string(),
        "192.0.2.1"
    );
}
