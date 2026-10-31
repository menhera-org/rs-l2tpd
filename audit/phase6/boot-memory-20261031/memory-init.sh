#!/bin/sh
# PID 1 in a disposable guest; this probe does not run the conformance suites.
set -eu
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t debugfs debugfs /sys/kernel/debug
printf 'MEMORY_PROBE_KERNEL=%s\n' "$(uname -r)"
printf 'MEMORY_PROBE_CMDLINE=%s\n' "$(cat /proc/cmdline)"
grep -E 'MemTotal:|MemAvailable:|CmaTotal:|CmaFree:' /proc/meminfo
if [ -d /sys/kernel/debug/kho/out ]; then
    echo KHO_DEBUGFS_PRESENT=1
    find /sys/kernel/debug/kho/out -maxdepth 1 -type f
else
    echo KHO_DEBUGFS_PRESENT=0
fi
echo MEMORY_PROBE_RESULT=0
poweroff -f
