#!/bin/sh
# PID 1 in the disposable QEMU guest, never run on the host.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
finish() {
    result=$?
    echo "REVIEW_RESULT=$result"
    poweroff -f
}
trap finish EXIT
set -eu
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /dev/pts /run
mount -t devpts devpts /dev/pts
if ! grep -q 'l2tp_builtin=1' /proc/cmdline; then
    modprobe l2tp_netlink
    modprobe l2tp_ip
    modprobe l2tp_ip6
    modprobe l2tp_eth
fi
uname -a
for suite in /kernel-unit /kernel-linux /review-kernel; do
    if [ -x "$suite" ]; then
        "$suite" --ignored --test-threads=1 --nocapture
    fi
done
