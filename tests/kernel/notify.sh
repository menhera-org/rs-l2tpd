#!/bin/sh
# Exercise the real systemd family filter and descriptor-store protocol.
set -eu
if [ "${1-}" = child ]; then
    notify_dir=$(mktemp -d /tmp/rs-l2tpd-fdstore.XXXXXX)
    trap 'rm -r "$notify_dir"' EXIT HUP INT TERM
    mkfifo "$notify_dir/pipe"
    exec 3<>"$notify_dir/pipe"
    systemd-notify --ready --fd=3 --fdname=audit FDSTORE=1
    systemctl --user --no-pager --property=NFileDescriptorStore --value show "$2" | grep -x 1
    systemd-notify FDSTOREREMOVE=1 FDNAME=audit
    systemctl --user --no-pager --property=NFileDescriptorStore --value show "$2" | grep -x 0
    exit 0
fi
case $0 in
    /*) script=$0 ;;
    *) script=$(pwd)/$0 ;;
esac
notify_unit=rs-l2tpd-audit-notify-$$
notify_log=$(mktemp /tmp/rs-l2tpd-notify.XXXXXX)
trap 'rm -f "$notify_log"' EXIT HUP INT TERM
systemd-run --user --no-pager --pipe --wait --collect \
    --unit="$notify_unit-ok" --property=Type=notify --property=NotifyAccess=all \
    --property=FileDescriptorStoreMax=1 --property=NoNewPrivileges=yes \
    --property=TimeoutStartSec=15s --property=TimeoutStopSec=5s --property=RuntimeMaxSec=15s \
    '--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6' \
    sh "$script" child "$notify_unit-ok.service"
if systemd-run --user --no-pager --pipe --wait --collect \
    --unit="$notify_unit-denied" --property=Type=notify --property=NotifyAccess=all \
    --property=FileDescriptorStoreMax=1 --property=NoNewPrivileges=yes \
    --property=TimeoutStartSec=15s --property=TimeoutStopSec=5s --property=RuntimeMaxSec=15s \
    '--property=RestrictAddressFamilies=AF_NETLINK AF_INET AF_INET6' \
    sh "$script" child "$notify_unit-denied.service" > "$notify_log" 2>&1; then
    cat "$notify_log"
    echo "AF_UNIX exclusion unexpectedly allowed notification" >&2
    exit 1
fi
cat "$notify_log"
grep -q 'Address family not supported by protocol' "$notify_log"
