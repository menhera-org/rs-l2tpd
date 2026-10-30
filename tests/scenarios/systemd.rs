//! P6: actual root PID 1 and the supplied unit, without sandbox overrides.
#[allow(dead_code)]
#[path = "support.rs"]
mod support;
#[allow(dead_code)]
#[path = "system_manager.rs"]
mod system_manager;

use std::{fs, process::Command};
use support::{BINARY, checked, wait};

fn systemctl(args: &[&str]) -> String {
    let mut command = Command::new("systemctl");
    command.arg("--no-pager").args(args);
    checked(command)
}
fn property(unit: &str, name: &str) -> String {
    systemctl(&["show", unit, "--value", "-p", name])
        .trim()
        .to_owned()
}
fn journal() -> String {
    let mut command = Command::new("journalctl");
    command.args(["--no-pager", "-n", "300", "-u", "rs-l2tpd.service"]);
    checked(command)
}
fn mount_option(mounts: &str, path: &str, flag: &str) -> bool {
    mounts.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields[4] == path && fields[5].split(',').any(|value| value == flag)
    })
}

/// spec: P21, P25, P14, P26, G8, R1, K1, K21
#[test]
#[ignore = "root systemd QEMU guest, tests/kernel/systemd-guest.sh"]
fn supplied_unit_enforces_mounts_capabilities_ordering_store_and_cleanup() {
    assert_eq!(std::env::var("RS_L2TPD_ROOT_SYSTEMD").as_deref(), Ok("1"));
    assert_eq!(
        fs::read_to_string("/proc/1/comm").unwrap().trim(),
        "systemd"
    );
    let map = fs::read_to_string("/proc/self/uid_map").unwrap();
    let fields: Vec<u64> = map.split_whitespace().map(|v| v.parse().unwrap()).collect();
    assert_eq!(
        fields[0..2],
        [0, 0],
        "initial user namespace, not a system container"
    );
    assert!(!std::path::Path::new("/sys/module/l2tp_eth").exists());
    assert!(!std::path::Path::new("/sys/module/l2tp_netlink").exists());
    // The production family request triggers the kernel's module autoload.
    drop(rs_l2tpd::kernel::linux::LinuxKernel::new().unwrap());
    assert!(std::path::Path::new("/sys/module/l2tp_netlink").exists());
    fs::write("/etc/rs-l2tpd.toml", system_manager::CONFIG).unwrap();
    let mut install = Command::new(BINARY);
    install.args(["--setup-systemd", "--prefix", "/"]);
    checked(install);
    systemctl(&["daemon-reload"]);
    systemctl(&["enable", "rs-l2tpd.service"]);
    let modprobe = fs::read_to_string("/proc/sys/kernel/modprobe").unwrap();
    fs::write("/proc/sys/kernel/modprobe", "/bin/false").unwrap();
    systemctl(&["stop", "network-online.target"]);
    systemctl(&["start", "--no-block", "network-online.target"]);
    wait("missing Ethernet module is reported", || {
        journal().contains("cannot be created")
    });
    assert_eq!(property("rs-l2tpd.service", "ActiveState"), "activating");
    assert_eq!(property("network-online.target", "ActiveState"), "inactive");
    assert!(!std::path::Path::new("/run/rs-l2tpd/rs-l2tpd.pid").exists());
    assert!(!std::path::Path::new("/sys/module/l2tp_eth").exists());
    let jobs = systemctl(&["list-jobs"]);
    assert!(
        jobs.lines()
            .any(|line| line.contains("network-online.target") && line.contains("waiting"))
    );
    fs::write("/proc/sys/kernel/modprobe", modprobe).unwrap();
    wait(
        "kernel autoload permits readiness and then network-online",
        || property("network-online.target", "ActiveState") == "active",
    );
    assert!(std::path::Path::new("/sys/module/l2tp_eth").exists());
    assert!(std::path::Path::new("/sys/class/net/incusl2tp").exists());
    assert!(std::path::Path::new("/run/rs-l2tpd/rs-l2tpd.pid").exists());
    systemctl(&["stop", "rs-l2tpd.service"]);
    systemctl(&["disable", "rs-l2tpd.service"]);
    fs::write("/tmp/phase6-outside", "outside the service's private tmp").unwrap();
    system_manager::exercise(|pid| {
        assert_eq!(property("rs-l2tpd.service", "ProtectSystem"), "strict");
        assert_eq!(property("rs-l2tpd.service", "ProtectKernelTunables"), "yes");
        assert_eq!(property("rs-l2tpd.service", "PrivateTmp"), "yes");
        assert!(property("rs-l2tpd.service", "DropInPaths").is_empty());
        assert_eq!(
            property("rs-l2tpd.service", "FragmentPath"),
            "/usr/local/lib/systemd/system/rs-l2tpd.service"
        );
        let expected = include_str!("../../contrib/rs-l2tpd.service.in")
            .replace("@BINARY@", "/usr/local/sbin/rs-l2tpd");
        assert_eq!(
            fs::read_to_string("/usr/local/lib/systemd/system/rs-l2tpd.service").unwrap(),
            expected
        );
        assert_ne!(
            fs::read_link(format!("/proc/{pid}/ns/mnt")).unwrap(),
            fs::read_link("/proc/1/ns/mnt").unwrap()
        );
        let mounts = fs::read_to_string(format!("/proc/{pid}/mountinfo")).unwrap();
        assert!(
            mount_option(&mounts, "/", "ro"),
            "ProtectSystem=strict really mounted read-only"
        );
        assert!(
            mount_option(&mounts, "/proc/sys", "ro"),
            "kernel tunables really protected"
        );
        assert!(
            mount_option(&mounts, "/proc/sys/net/ipv6/bindv6only", "rw"),
            "the one writable tunable"
        );
        assert!(mount_option(&mounts, "/run/rs-l2tpd", "rw"));
        assert!(!std::path::Path::new(&format!("/proc/{pid}/root/tmp/phase6-outside")).exists());
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
        for key in ["CapEff:\t", "CapPrm:\t", "CapBnd:\t", "CapAmb:\t"] {
            let value = status
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap();
            assert_eq!(
                u64::from_str_radix(value, 16).unwrap(),
                (1 << 10) | (1 << 12) | (1 << 13),
                "{key}"
            );
        }
        println!(
            "ROOT_SANDBOX=active; private mounts, protected root/tunables, writable exception, exact capabilities"
        );
    });
}
