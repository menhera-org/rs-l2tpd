#!/bin/sh
# Initial P5 system-unit probe; container has no host network attachment.
set -eu
repo=$(CDPATH='' cd -P "$(dirname "$0")/../.." && pwd)
name=rs-l2tpd-phase6-$$
record=$repo/audit/phase6/incus-$name
mkdir -p "$record"
cleanup() {
    incus delete -f "$name" > "$record/cleanup.log" 2>&1 || true
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
set -x
incus launch images:ubuntu/24.04 "$name" -c security.privileged=false
incus config show "$name" --expanded
incus exec "$name" -- uname -r
incus exec "$name" -- ip -brief link
incus file push "$repo/target/x86_64-unknown-linux-musl/debug/rs-l2tpd" "$name/tmp/rs-l2tpd"
incus exec "$name" -- sh -ec '
    mkdir -p /etc/rs-l2tpd.toml.d
    cat > /etc/rs-l2tpd.toml <<EOF
[tunnels.incus]
tunnel_id=10
peer_tunnel_id=20
remote_addr="192.0.2.2"
[sessions.incus]
tunnel_name="incus"
session_id=100
peer_session_id=200
interface_name="incusl2tp"
EOF
    echo 1 > /proc/sys/net/ipv6/bindv6only
    /tmp/rs-l2tpd --setup-systemd
'
incus exec "$name" -- systemctl --no-pager status rs-l2tpd.service
incus exec "$name" -- journalctl --no-pager -n 100 -u rs-l2tpd.service
incus exec "$name" -- cat /proc/sys/net/ipv6/bindv6only
incus exec "$name" -- ip l2tp show tunnel
incus exec "$name" -- systemctl --no-pager stop rs-l2tpd.service
incus exec "$name" -- ip l2tp show tunnel
