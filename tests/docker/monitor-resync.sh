#!/bin/sh
# Run in an isolated Docker network namespace with NET_ADMIN and NET_RAW.
# /artifacts/current is the static daemon under test, mounted read-only.
set -eu

cp /artifacts/current /opt/current
chmod 755 /opt/current
NOISE_ADDRESSES=${NOISE_ADDRESSES:-50000}
case "$NOISE_ADDRESSES" in
    ''|*[!0-9]*) echo 'NOISE_ADDRESSES must be a positive integer' >&2; exit 1 ;;
esac
[ "$NOISE_ADDRESSES" -gt 0 ] && [ "$NOISE_ADDRESSES" -le 200000 ] || {
    echo 'NOISE_ADDRESSES must be between 1 and 200000' >&2
    exit 1
}
: > /tmp/resync-daemon.log

fail() {
    echo "$*" >&2
    cat /tmp/resync-daemon.log >&2
    ip l2tp show tunnel >&2
    exit 1
}

stop_daemon() {
    if [ -f /run/resync-daemon.pid ]; then
        pid=$(cat /run/resync-daemon.pid)
        # A failed overflow setup may have left the daemon stopped.
        kill -CONT "$pid" 2>/dev/null || :
        kill -TERM "$pid" 2>/dev/null || :
        attempts=0
        while [ -e /run/resync-daemon.pid ]; do
            attempts=$((attempts + 1))
            [ "$attempts" -lt 50 ] || return 1
            sleep 0.1
        done
    fi
}

cleanup() {
    stop_daemon || :
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

wait_endpoint() {
    attempts=0
    until ip l2tp show tunnel tunnel_id 1001 |
        grep -Fq "From $1 to 2001:db8:1::2"; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 100 ] || fail "source did not change to $1"
        sleep 0.1
    done
}

session_index() {
    ip -o link show dev pseudowire0 | cut -d : -f 1
}

socket_identities() {
    # The monitor must reopen after overflow. Exclude its netlink sockets,
    # resolver sockets and runtime socketpairs, retaining the native IP L2TP
    # socket, which is absent from these standard socket tables.
    awk '
        FNR == 1 { next }
        FILENAME ~ /\/unix$/ { print "socket:[" $7 "]"; next }
        { print "socket:[" $10 "]" }
    ' /proc/"$daemon_pid"/net/netlink /proc/"$daemon_pid"/net/unix \
        /proc/"$daemon_pid"/net/udp /proc/"$daemon_pid"/net/udp6 \
        /proc/"$daemon_pid"/net/tcp /proc/"$daemon_pid"/net/tcp6 \
        > /tmp/resync-control-sockets
    for fd in /proc/"$daemon_pid"/fd/*; do
        target=$(readlink "$fd" 2>/dev/null || :)
        case "$target" in
            socket:*) printf '%s\n' "$target" ;;
        esac
    done | sort -u | grep -Fvx -f /tmp/resync-control-sockets || :
}

printf 'CASE monitor overflow source recovery\n'
ip link set lo up
for device in underlay0 noise0; do
    ip link add "$device" type dummy
    ip link set "$device" addrgenmode none
    ip link set "$device" up
done
ip address add 2001:db8:1::1/64 dev underlay0 nodad
ip address add fd00:ffff::1/128 dev noise0 nodad
mkdir -p /etc/rs-l2tpd.toml.d
cat > /etc/rs-l2tpd.toml <<'CONFIG'
[tunnels.uplink]
tunnel_id = 1001
peer_tunnel_id = 2001
ip_version = "V6"
remote_addr = "2001:db8:1::2"
bind_interface = "underlay0"
[sessions.lan]
tunnel_name = "uplink"
session_id = 1001
peer_session_id = 2001
interface_name = "pseudowire0"
CONFIG
timeout 15 /opt/current --pidfile /run/resync-daemon.pid \
    > /tmp/resync-daemon.log 2>&1 < /dev/null ||
    fail 'daemon did not become ready'
daemon_pid=$(cat /run/resync-daemon.pid)
wait_endpoint 2001:db8:1::1
ip link set pseudowire0 addrgenmode none
ip link set pseudowire0 up
ip address add 198.18.0.1/30 dev pseudowire0
ip address add fd00:2::1/64 dev pseudowire0 nodad
original_index=$(session_index)
original_addresses=$(ip -o address show dev pseudowire0 scope global)
# Drain setup notifications before deliberately blocking the receiver.
sleep 0.5
kill -STOP "$daemon_pid"
attempts=0
until awk '$1 == "State:" { exit $2 != "T" }' /proc/"$daemon_pid"/status; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 50 ] || fail 'daemon did not stop for overflow setup'
    sleep 0.1
done
socket_identities > /tmp/resync-sockets-original
[ -s /tmp/resync-sockets-original ] || fail 'native L2TP socket identity is unavailable'

# Fill the paused monitor before changing the bound source. The interesting
# DELADDR/NEWADDR must be recovered from current kernel state after reopening,
# rather than relying on their individual notifications being delivered.
awk -v count="$NOISE_ADDRESSES" 'BEGIN {
    for (i = 1; i <= count; i++) {
        print "address add fd00:ffff::2/128 dev noise0 nodad"
        print "address delete fd00:ffff::2/128 dev noise0"
    }
}' > /tmp/resync-addresses
ip -6 -batch /tmp/resync-addresses
ip address delete 2001:db8:1::1/64 dev underlay0
ip address add 2001:db8:1::3/64 dev underlay0 nodad
ip -6 route get 2001:db8:1::2 oif underlay0 |
    grep -Fq 'src 2001:db8:1::3' || fail 'replacement source is unavailable'
kill -CONT "$daemon_pid"

attempts=0
until grep -Fq 'netlink socket buffer full' /tmp/resync-daemon.log; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 100 ] ||
        fail 'netlink did not overflow; increase NOISE_ADDRESSES for this host'
    sleep 0.1
done
wait_endpoint 2001:db8:1::3
[ "$(cat /run/resync-daemon.pid)" = "$daemon_pid" ] || fail 'daemon restarted'
[ "$(session_index)" = "$original_index" ] || fail 'session interface was recreated'
[ "$(ip -o address show dev pseudowire0 scope global)" = "$original_addresses" ] ||
    fail 'session addresses changed'
socket_identities > /tmp/resync-sockets-current
while IFS= read -r socket; do
    grep -Fxq "$socket" /tmp/resync-sockets-current ||
        fail 'native L2TP socket was recreated'
done < /tmp/resync-sockets-original
ip l2tp show tunnel tunnel_id 1001 | grep -Fq 'Peer tunnel 2001' ||
    fail 'peer tunnel ID changed'
ip l2tp show session tunnel_id 1001 session_id 1001 |
    grep -Fq 'Peer session 2001, tunnel 2001' || fail 'session IDs changed'

stop_daemon || fail 'daemon shutdown did not complete'
[ -z "$(ip l2tp show tunnel)" ] || fail 'tunnel survived shutdown'
if ip link show pseudowire0 >/dev/null 2>&1; then
    fail 'session interface survived shutdown'
fi
printf 'PASS monitor overflow: source refreshed, socket/session preserved, shutdown clean\n'
