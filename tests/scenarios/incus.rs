//! Executed only by the Incus driver, inside its disposable system container.
use super::support::{BINARY, checked, wait};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::fs;
use std::process::Command;

fn systemctl(args: &[&str]) -> String {
    let mut command = Command::new("systemctl");
    command.arg("--no-pager").args(args);
    checked(command)
}
fn property(name: &str) -> String {
    systemctl(&["show", "rs-l2tpd.service", "--value", "-p", name])
        .trim()
        .to_owned()
}
fn pid() -> i32 {
    property("MainPID").parse().unwrap()
}
fn index() -> u32 {
    fs::read_to_string("/sys/class/net/incusl2tp/ifindex")
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}
fn mac() -> String {
    fs::read_to_string("/sys/class/net/incusl2tp/address")
        .unwrap()
        .trim()
        .to_owned()
}
fn networkd_address() -> bool {
    let output = Command::new("ip")
        .args(["-o", "-4", "addr", "show", "incusl2tp"])
        .output()
        .unwrap();
    output.status.success() && String::from_utf8_lossy(&output.stdout).contains("198.18.0.1/24")
}
fn assert_active(expected_index: u32, expected_mac: &str) {
    assert_eq!(index(), expected_index);
    assert_eq!(mac(), expected_mac);
    assert!(networkd_address());
    let mut show = Command::new("ip");
    show.args(["-o", "link", "show", "incusl2tp"]);
    let link = checked(show);
    let flags = link.split_once('<').unwrap().1.split_once('>').unwrap().0;
    assert!(flags.split(',').any(|flag| flag == "UP"), "{link}");
}
fn stop() {
    systemctl(&["stop", "rs-l2tpd.service"]);
    for object in ["tunnel", "session"] {
        let mut command = Command::new("ip");
        command.args(["l2tp", "show", object]);
        assert!(checked(command).trim().is_empty());
    }
    assert!(!std::path::Path::new("/run/rs-l2tpd/rs-l2tpd.pid").exists());
}

/// spec: H9, H11, G4, P14, P25, R10
#[test]
#[ignore = "unprivileged Incus system container; tests/docker/run.sh incus"]
fn system_container_store_tunable_networkd_and_udev() {
    assert_eq!(std::env::var("RS_L2TPD_INCUS").as_deref(), Ok("1"));
    wait("system manager's private bus", || {
        std::path::Path::new("/run/systemd/private").exists()
    });
    let boot = Command::new("systemctl")
        .args(["--no-pager", "is-system-running", "--wait"])
        .output()
        .unwrap();
    let state = String::from_utf8(boot.stdout).unwrap();
    assert!(
        matches!(state.trim(), "running" | "degraded"),
        "boot: {state}"
    );
    let map = fs::read_to_string("/proc/self/uid_map").unwrap();
    let fields: Vec<u64> = map.split_whitespace().map(|v| v.parse().unwrap()).collect();
    assert_eq!(fields[0], 0);
    assert_ne!(fields[1], 0, "the container must be unprivileged");
    let text = "[tunnels.incus]\ntunnel_id=10\npeer_tunnel_id=20\nremote_addr='192.0.2.2'\n\
        [sessions.incus]\ntunnel_name='incus'\nsession_id=100\npeer_session_id=200\ninterface_name='incusl2tp'\n";
    fs::create_dir_all("/etc/rs-l2tpd.toml.d").unwrap();
    fs::create_dir_all("/etc/systemd/network").unwrap();
    fs::write("/etc/rs-l2tpd.toml", text).unwrap();
    fs::write(
        "/etc/systemd/network/10-phase6.network",
        "[Match]\nName=incusl2tp\n[Network]\nAddress=198.18.0.1/24\nIPv6AcceptRA=no\n",
    )
    .unwrap();
    assert_eq!(
        systemctl(&["is-active", "systemd-networkd.service"]).trim(),
        "active"
    );
    assert_eq!(
        systemctl(&["is-active", "systemd-udevd.service"]).trim(),
        "active"
    );
    // Read fixture files before any session is created.
    systemctl(&["restart", "systemd-networkd.service"]);
    fs::write("/proc/sys/net/ipv6/bindv6only", "1").unwrap();
    let mut command = Command::new(BINARY);
    command.arg("--setup-systemd");
    checked(command);
    assert_eq!(property("ActiveState"), "active");
    assert_eq!(
        fs::read_to_string("/proc/sys/net/ipv6/bindv6only")
            .unwrap()
            .trim(),
        "0"
    );
    wait("configured-name .network applied", networkd_address);
    let mut settle = Command::new("udevadm");
    settle.args(["settle", "--timeout=10"]);
    checked(settle);
    let assignment = fs::read_to_string("/sys/class/net/incusl2tp/addr_assign_type").unwrap();
    match assignment.trim() {
        "3" => println!("CONCURRENT_MAC=persistent; address={}", mac()),
        "1" => {
            let mut journal = Command::new("journalctl");
            journal.args(["--no-pager", "-n", "200", "-u", "systemd-udevd.service"]);
            let logs = checked(journal);
            assert!(
                logs.lines().any(|line| line.contains("incusl2tp:")
                    && line.contains("MACAddress=/MACAddressPolicy=")
                    && line.contains("Device or resource busy")),
                "{logs}"
            );
            println!(
                "CONCURRENT_MAC=kernel-random; udev MAC write refused with EBUSY; address={}",
                mac()
            );
        }
        other => panic!("unexpected concurrent MAC assignment type: {other}"),
    }
    let mut info = Command::new("udevadm");
    info.args(["info", "/sys/class/net/incusl2tp"]);
    assert!(checked(info).contains("ID_NET_LINK_FILE=/usr/lib/systemd/network/99-default.link"));
    let original_index = index();
    let concurrent_mac = mac();
    let original_pid = pid();
    let file_pid: i32 = fs::read_to_string("/run/rs-l2tpd/rs-l2tpd.pid")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(file_pid, original_pid);
    let status = fs::read_to_string(format!("/proc/{original_pid}/status")).unwrap();
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .unwrap();
    assert_eq!(
        u64::from_str_radix(effective, 16).unwrap(),
        (1 << 10) | (1 << 12) | (1 << 13)
    );
    systemctl(&["reload", "rs-l2tpd.service"]);
    wait("reload complete", || {
        let mut journal = Command::new("journalctl");
        journal.args(["--no-pager", "-n", "100", "-u", "rs-l2tpd.service"]);
        checked(journal).contains("reload completed")
    });
    assert_active(original_index, &concurrent_mac);
    assert_eq!(property("NFileDescriptorStore"), "1");
    kill(Pid::from_raw(original_pid), Signal::SIGKILL).unwrap();
    wait("killed daemon reaped", || {
        !std::path::Path::new(&format!("/proc/{original_pid}")).exists()
    });
    assert_eq!(
        property("MainPID"),
        "0",
        "observe manager ownership before automatic restart"
    );
    assert_eq!(index(), original_index);
    assert_eq!(property("NFileDescriptorStore"), "1");
    wait("manager restart and adoption", || {
        let current = pid();
        current > 0 && current != original_pid && property("ActiveState") == "active"
    });
    assert_active(original_index, &concurrent_mac);
    let mut command = Command::new("/usr/local/sbin/rs-l2tpd");
    command.args(["--restart", "--pid-file", "/run/rs-l2tpd/rs-l2tpd.pid"]);
    checked(command);
    wait("re-exec resumed", || {
        let mut command = Command::new("journalctl");
        command.args(["--no-pager", "-n", "100", "-u", "rs-l2tpd.service"]);
        checked(command).contains("re-exec resumed")
    });
    assert_active(original_index, &concurrent_mac);
    stop();
    // Ordered case: udev completes while the new session is down, then
    // networkd may activate it. Concurrent activation has no such guarantee.
    let mut persistent = None;
    let mut previous_index = original_index;
    for _ in 0..2 {
        systemctl(&["stop", "systemd-networkd.service"]);
        systemctl(&["start", "rs-l2tpd.service"]);
        let mut settle = Command::new("udevadm");
        settle.args(["settle", "--timeout=10"]);
        checked(settle);
        wait("ordered persistent MAC applied", || {
            fs::read_to_string("/sys/class/net/incusl2tp/addr_assign_type")
                .is_ok_and(|v| v.trim() == "3")
        });
        let mut show = Command::new("ip");
        show.args(["-o", "link", "show", "incusl2tp"]);
        let link = checked(show);
        let flags = link.split_once('<').unwrap().1.split_once('>').unwrap().0;
        assert!(!flags.split(',').any(|flag| flag == "UP"), "{link}");
        let current_mac = mac();
        if let Some(expected) = &persistent {
            assert_eq!(
                &current_mac, expected,
                "same name and machine ID yield the same persistent MAC"
            );
        } else {
            persistent = Some(current_mac.clone());
        }
        let current_index = index();
        assert_ne!(current_index, previous_index);
        println!("ORDERED_MAC=persistent; address={current_mac}; ifindex={current_index}");
        systemctl(&["start", "systemd-networkd.service"]);
        wait(
            "networkd activation after ordered udev completion",
            networkd_address,
        );
        assert_eq!(mac(), current_mac);
        assert_eq!(index(), current_index);
        previous_index = current_index;
        stop();
    }
    fs::write(
        "/etc/rs-l2tpd.toml",
        format!("{text}interface_hwaddr='02:00:5e:00:53:01'\n"),
    )
    .unwrap();
    systemctl(&["start", "rs-l2tpd.service"]);
    wait("staged configured MAC and networkd address", || {
        networkd_address() && mac() == "02:00:5e:00:53:01"
    });
    stop();
}
