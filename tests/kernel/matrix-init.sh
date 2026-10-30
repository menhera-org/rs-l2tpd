#!/bin/sh
# PID 1 only in the disposable QEMU guest.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
finish() { result=$?; echo "MATRIX_GUEST_RESULT=$result"; poweroff -f; }
trap finish 0
set -eu
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /dev/pts /run
mount -t devpts devpts /dev/pts
chmod 1777 /tmp
uname -a
printf 'GUEST_KERNEL_RELEASE=%s\n' "$(uname -r)"
run_suite() {
    rm -f /tmp/suite.status
    { result=0; "$@" || result=$?; printf '%s\n' "$result" > /tmp/suite.status; } 2>&1 | tee /tmp/suite.log
    [ "$(cat /tmp/suite.status)" = 0 ] || return 1
    grep -Eq 'test result: ok\. [1-9][0-9]* passed;' /tmp/suite.log
}
mode=$(cat /matrix-mode)
export RS_L2TPD_SCENARIO_CONTAINER=1
if ! grep -q 'l2tp_builtin=1' /proc/cmdline; then
    depmod -a
    for module in l2tp_core l2tp_netlink l2tp_ip l2tp_eth dummy veth; do modprobe "$module"; done
    if [ "$mode" = normal ]; then
        for module in l2tp_ip6 vrf bridge 8021q nlmon; do modprobe "$module"; done
    fi
fi
if [ "$mode" != normal ]; then
    export RS_L2TPD_IPV6_ABSENT=1
    echo 'scope: IPv6-absent boot scenario only'
    run_suite /boot-scenarios --ignored --exact absent_ipv6_stack_uses_native_ipv4_and_keeps_ipv6_peers_disconnected --nocapture
    echo CONFORMANCE_RESULT=0
    echo SCENARIO_RESULT=0
    exit 0
fi
run_suite /kernel-unit --ignored --test-threads=1 --nocapture
run_suite /kernel-linux --ignored --test-threads=1 --nocapture
run_suite /review-kernel --ignored --test-threads=1 --nocapture
run_suite /binary-unit --test-threads=1 --nocapture
run_suite /binary-unit --ignored --exact pidfile::permission_tests::precreated_permissions_links_and_owner --nocapture
run_suite /binary-unit --ignored --exact pidfile::removal_tests::removal_uses_inode_after_directory_owner_changes --nocapture
run_suite /binary-unit --ignored --exact files::filesystem_tests::permission_errors_name_unreadable_unlistable_and_uninspectable_paths --nocapture
run_suite /process-test --include-ignored --test-threads=1 --nocapture
echo CONFORMANCE_RESULT=0
export RS_L2TPD_BASELINE=/baseline
run_suite /scenarios --ignored --test-threads=1 --nocapture --skip incus::system_container_store_tunable_networkd_and_udev
echo SCENARIO_RESULT=0
