#!/bin/sh
set -eu
repo=$(pwd)
record=${PHASE6_MAC_RECORD:-$repo/audit/phase6/staged-mac-override-20261031/authority-control}
binary=${BASELINE_BINARY:?set BASELINE_BINARY to the archived baseline musl binary}
name=rs-l2tpd-mac-authority-$$
mkdir -p "$record"
cleanup() {
    result=$?
    incus exec "$name" -- journalctl --no-pager -n 3000 -o short-monotonic -u systemd-udevd.service -u systemd-networkd.service -u rs-l2tpd.service > "$record/baseline-journal.log" 2>&1 || :
    incus exec "$name" -- sh -ec 'ip -details addr show; udevadm info /sys/class/net/incusl2tp' > "$record/baseline-final-link.log" 2>&1 || :
    incus delete -f "$name" > "$record/baseline-cleanup.log" 2>&1 || result=1
    printf 'BASELINE_WITNESS_RESULT=%s\n' "$result"
    exit "$result"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
pool=$(incus profile device get default root pool)
[ -n "$pool" ]
printf '%s\n' 'source: de8ac73; all features; x86_64-unknown-linux-musl' 'command: incus launch images:ubuntu/24.04 NAME --no-profiles --storage ROOT_POOL -c security.privileged=false'
incus --quiet launch images:ubuntu/24.04 "$name" --no-profiles --storage "$pool" -c security.privileged=false
incus --quiet file push "$binary" "$name/usr/local/sbin/rs-l2tpd"
# Variables in this program belong to the disposable container.
# shellcheck disable=SC2016
incus exec "$name" -- sh -ec '
    n=0
    while [ ! -S /run/systemd/private ]; do
        n=$((n + 1)); [ "$n" -lt 30 ]; sleep 1
    done
    systemctl --no-pager is-system-running --wait || test "$?" -eq 1
    uname -r
    systemd --version
    mkdir -p /etc/rs-l2tpd.toml.d /etc/systemd/network /etc/systemd/system/rs-l2tpd.service.d
    cat > /etc/systemd/system/rs-l2tpd.service.d/probe.conf <<"UNIT"
[Unit]
StartLimitIntervalSec=0
UNIT
    cat > /etc/rs-l2tpd.toml <<"CONFIG"
[host]
fix_bindv6only=false
[tunnels.incus]
tunnel_id=10
peer_tunnel_id=20
remote_addr="192.0.2.2"
[sessions.incus]
tunnel_name="incus"
session_id=100
peer_session_id=200
interface_name="incusl2tp"
interface_hwaddr="02:00:5e:00:53:01"
CONFIG
    cat > /etc/systemd/network/10-phase6.network <<"NETWORK"
[Match]
Name=incusl2tp
[Network]
Address=198.18.0.1/24
IPv6AcceptRA=no
NETWORK
    cat > /etc/systemd/network/05-phase6-custom.link <<"LINK"
[Match]
OriginalName=incusl2tp rsl2tp-t*
[Link]
MACAddressPolicy=none
LINK
    udevadm control --reload
    udevadm control --log-level=debug
    systemctl --no-pager restart systemd-networkd.service
    /usr/local/sbin/rs-l2tpd --setup-systemd
    n=0
    while [ "$n" -lt 3 ]; do
        n=$((n + 1))
        udevadm settle --timeout=10
        udevadm info /sys/class/net/incusl2tp | grep -q ID_NET_LINK_FILE=/etc/systemd/network/05-phase6-custom.link
        tries=0
        until ip -o -4 addr show incusl2tp | grep -q 198.18.0.1/24; do
            tries=$((tries + 1)); [ "$tries" -lt 10 ]; sleep 1
        done
        address=$(cat /sys/class/net/incusl2tp/address)
        index=$(cat /sys/class/net/incusl2tp/ifindex)
        printf "AUTHORITY_STAGED attempt=%s index=%s mac=%s\n" "$n" "$index" "$address"
        if [ "$address" != 02:00:5e:00:53:01 ]; then
            printf "%s\n" AUTHORITY_FAILED=1
            exit 1
        fi
        systemctl --no-pager stop rs-l2tpd.service
        if [ "$n" -lt 3 ]; then systemctl --no-pager start rs-l2tpd.service; fi
    done
    printf "%s\n" AUTHORITY_PRESERVED=3
    exit 0
'
