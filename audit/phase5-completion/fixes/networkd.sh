#!/bin/sh
# Disposable privileged container only; checks the actual daemon against stock networkd/udev.
set -eu
mode=$1
systemctl --no-pager --version
[ -s /etc/machine-id ] || systemd-machine-id-setup
mkdir -p /etc/systemd/network /run/systemd /run/udev /run/dbus
dbus-daemon --system --fork
if [ "$mode" = native ]; then
    /lib/systemd/systemd-udevd > /tmp/udev.log 2>&1 &
    n=0
    until [ -S /run/udev/control ]; do
        n=$((n+1)); [ "$n" -lt 50 ]; sleep 0.1
    done
else
    if ! grep -q ' /sys sysfs ro' /proc/mounts; then
        mount -o remount,ro,nosuid,nodev,noexec /sys
    fi
    grep ' /sys sysfs ro' /proc/mounts
fi
cat > /etc/systemd/network/10-l2tp.network <<'EOF'
[Match]
Name=l2tp0
[Network]
Address=192.0.2.1/24
EOF
/lib/systemd/systemd-networkd > /tmp/networkd.log 2>&1 &
cat > /tmp/daemon.toml <<'EOF'
[host]
fix_bindv6only=false
[tunnels.a]
tunnel_id=10
remote_addr="127.0.0.1"
[sessions.s]
tunnel_name="a"
session_id=100
interface_name="l2tp0"
EOF
first=
for run in 1 2 3; do
    /bin-new --foreground --config /tmp/daemon.toml --config-dir /absent --pid-file /tmp/daemon.pid > /tmp/daemon.log 2>&1 &
    pid=$!
    n=0
    until grep -q 'ready pid=' /tmp/daemon.log; do
        kill -0 "$pid"
        n=$((n+1)); [ "$n" -lt 100 ]; sleep 0.1
    done
    if [ "$mode" = native ]; then udevadm settle --timeout=10; fi
    n=0
    until ip -o addr show dev l2tp0 | grep -q 192.0.2.1; do
        n=$((n+1)); [ "$n" -lt 100 ] || { cat /tmp/networkd.log; exit 1; }; sleep 0.1
    done
    if [ "$mode" = native ]; then
        n=0
        until [ "$(cat /sys/class/net/l2tp0/addr_assign_type)" = 3 ]; do
            n=$((n+1))
            [ "$n" -lt 100 ] || { cat /tmp/udev.log; udevadm info /sys/class/net/l2tp0; exit 1; }
            sleep 0.1
        done
    fi
    mac=$(cat /sys/class/net/l2tp0/address)
    grep -q 'created as l2tp0' /tmp/daemon.log
    ! grep -q 'renamed to.*by another manager' /tmp/daemon.log
    printf 'run=%s mode=%s mac=%s address=192.0.2.1/24 creation=l2tp0\n' "$run" "$mode" "$mac"
    if [ "$mode" = native ]; then
        if [ -z "$first" ]; then first=$mac; else [ "$first" = "$mac" ]; fi
    fi
    kill -TERM "$pid"
    wait "$pid"
    if [ "$mode" = native ]; then udevadm settle --timeout=10; fi
done
printf '%s\n' 'NETWORKD_RESULT=0'
