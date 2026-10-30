//! Unprivileged system-container assertions around the shared manager contract.
use super::support::wait;
use std::{fs, process::Command};

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
    let original_index = super::system_manager::exercise(|_| {});
    super::system_manager::mac_policy(original_index);
}
