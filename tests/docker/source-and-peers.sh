#!/bin/sh
# Unbound tunnels whose source address is replaced, literal peers without a
# route, and identifiers held by another tunnel or session on the host.
# Run in a disposable container with NET_ADMIN and NET_RAW; /artifacts/current
# is the static daemon under test, mounted read-only.
set -eu

cp /artifacts/current /opt/current
chmod 755 /opt/current
CASES=${CASES:-"unbound literal conflict"}

fail() {
    echo "$*" >&2
    cat /tmp/daemon.log >&2
    ip l2tp show tunnel >&2
    ip l2tp show session >&2
    exit 1
}

stop_daemon() {
    if [ -e /run/test.pid ]; then
        kill -TERM "$(cat /run/test.pid)" 2>/dev/null || :
        attempts=0
        while [ -e /run/test.pid ]; do
            attempts=$((attempts + 1))
            [ "$attempts" -lt 100 ] || return 1
            sleep 0.1
        done
    fi
    [ -z "$(ip l2tp show tunnel | grep -v '^Tunnel 9[0-9]*,' || :)" ]
}

cleanup() {
    stop_daemon || :
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

reset_case() {
    stop_daemon || fail 'daemon shutdown did not complete'
    for device in $(ip -o link show type dummy | awk -F ': ' '{ sub(/@.*/, "", $2); print $2 }'); do
        ip link delete "$device"
    done
    : > /tmp/daemon.log
    ip link set lo up
    ip link add dummy0 type dummy
    ip link set dummy0 addrgenmode none
    ip link set dummy0 up
}

socket_identities() {
    for fd in /proc/"$daemon_pid"/fd/*; do
        target=$(readlink "$fd" 2>/dev/null || :)
        case "$target" in socket:*) printf '%s\n' "$target" ;; esac
    done | sort -u
}

start_daemon() {
    timeout 40 /opt/current --pidfile /run/test.pid > /tmp/daemon.log 2>&1 ||
        fail 'daemon did not become ready'
    daemon_pid=$(cat /run/test.pid)
    sleep 0.2
    socket_identities > /tmp/sockets-first
    sleep 0.2
    socket_identities > /tmp/sockets-second
    comm -12 /tmp/sockets-first /tmp/sockets-second > /tmp/sockets-original
    [ -s /tmp/sockets-original ] || fail 'daemon socket identities are unavailable'
}

check_identity() {
    [ "$(cat /run/test.pid)" = "$daemon_pid" ] || fail 'daemon restarted'
    socket_identities > /tmp/sockets-current
    while IFS= read -r socket; do
        grep -Fxq "$socket" /tmp/sockets-current || fail 'a persistent socket was replaced'
    done < /tmp/sockets-original
}

wait_endpoint() {
    attempts=0
    until ip l2tp show tunnel tunnel_id "$1" | grep -Fq "From $2 to $3"; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt "$4" ] || fail "tunnel $1: expected source $2 and peer $3"
        sleep 0.1
    done
}

for test_case in $CASES; do
    printf 'CASE %s\n' "$test_case"
    reset_case
    case "$test_case" in
        unbound)
            ip address add 2001:db8:1::1/64 dev dummy0 nodad
            ip address add 192.0.2.1/24 dev dummy0
            cat > /etc/rs-l2tpd.toml <<'CONFIG'
[tunnels.v6]
tunnel_id = 10
remote_addr = "2001:db8:1::2"
[tunnels.v4]
tunnel_id = 11
remote_addr = "192.0.2.2"
[sessions.v6]
tunnel_name = "v6"
session_id = 100
interface_name = "v6s0"
[sessions.v4]
tunnel_name = "v4"
session_id = 101
interface_name = "v4s0"
CONFIG
            start_daemon
            wait_endpoint 10 2001:db8:1::1 2001:db8:1::2 50
            wait_endpoint 11 ::ffff:192.0.2.1 ::ffff:192.0.2.2 50
            v6_index=$(cat /sys/class/net/v6s0/ifindex)
            v4_index=$(cat /sys/class/net/v4s0/ifindex)
            # Another address of each family: no reconnect, the source stays.
            ip address add 2001:db8:1::9/64 dev dummy0 nodad
            ip address add 192.0.2.9/24 dev dummy0
            ip address delete 2001:db8:1::9/64 dev dummy0
            ip address delete 192.0.2.9/24 dev dummy0
            sleep 1
            wait_endpoint 10 2001:db8:1::1 2001:db8:1::2 1
            wait_endpoint 11 ::ffff:192.0.2.1 ::ffff:192.0.2.2 1
            [ "$(grep -c 'reconnected unbound tunnel' /tmp/daemon.log)" -eq 0 ] ||
                fail 'unrelated addresses triggered reconnects'
            # The selected sources themselves are replaced: the kernel would
            # keep sending from the removed addresses; the daemon reconnects.
            ip address delete 2001:db8:1::1/64 dev dummy0
            ip address add 2001:db8:1::3/64 dev dummy0 nodad
            ip address delete 192.0.2.1/24 dev dummy0
            ip address add 192.0.2.3/24 dev dummy0
            wait_endpoint 10 2001:db8:1::3 2001:db8:1::2 50
            wait_endpoint 11 ::ffff:192.0.2.3 ::ffff:192.0.2.2 50
            check_identity
            [ "$(cat /sys/class/net/v6s0/ifindex)" = "$v6_index" ] || fail 'v6 session recreated'
            [ "$(cat /sys/class/net/v4s0/ifindex)" = "$v4_index" ] || fail 'v4 session recreated'
            # A source removed with no replacement yet: retried until one exists.
            ip address delete 2001:db8:1::3/64 dev dummy0
            attempts=0
            until grep -q 'failed to reconnect unbound tunnel_id=10' /tmp/daemon.log; do
                attempts=$((attempts + 1))
                [ "$attempts" -lt 50 ] || fail 'a reconnect without a source did not fail'
                sleep 0.1
            done
            sleep 1.5
            ip address add 2001:db8:1::5/64 dev dummy0 nodad
            wait_endpoint 10 2001:db8:1::5 2001:db8:1::2 50
            wait_endpoint 11 ::ffff:192.0.2.3 ::ffff:192.0.2.2 1
            check_identity
            ;;
        literal)
            ip address add 2001:db8:1::1/64 dev dummy0 nodad
            # The discard address is routable, the peer is not.
            ip -6 route add 100::/64 dev dummy0
            cat > /etc/rs-l2tpd.toml <<'CONFIG'
[tunnels.far]
tunnel_id = 10
remote_addr = "2001:db8:2::2"
[sessions.far]
tunnel_name = "far"
session_id = 100
interface_name = "far0"
CONFIG
            # Readiness does not wait for the route: the tunnel is created
            # on the discard address and the peer is retried.
            start_daemon
            ip link show far0 > /dev/null || fail 'session missing'
            ip l2tp show tunnel tunnel_id 10 | grep -Fq 'to 100::' || fail 'discard peer expected'
            grep -q 'cannot reach its peer 2001:db8:2::2 yet' /tmp/daemon.log ||
                fail 'the pending peer was not reported'
            far_index=$(cat /sys/class/net/far0/ifindex)
            sleep 2
            [ "$(grep -c 'cannot reach its peer' /tmp/daemon.log)" -eq 1 ] ||
                fail 'the pending peer was reported more than once'
            ip -6 route add 2001:db8:2::/64 dev dummy0
            wait_endpoint 10 2001:db8:1::1 2001:db8:2::2 50
            grep -q 'tunnel_id=10 reached its peer 2001:db8:2::2' /tmp/daemon.log ||
                fail 'reaching the peer was not logged'
            [ "$(cat /sys/class/net/far0/ifindex)" = "$far_index" ] || fail 'session recreated'
            check_identity
            # The route goes away again: the kernel keeps the connection and
            # the daemon changes nothing; a reload to a new unroutable peer
            # moves the tunnel to the discard address, not to the old peer.
            ip -6 route delete 2001:db8:2::/64 dev dummy0
            sed -i 's/2001:db8:2::2/2001:db8:3::2/' /etc/rs-l2tpd.toml
            kill -HUP "$daemon_pid"
            wait_endpoint 10 2001:db8:1::1 100:: 50
            grep -q 'cannot reach its peer 2001:db8:3::2 yet' /tmp/daemon.log ||
                fail 'the new pending peer was not reported'
            ip -6 route add 2001:db8:3::/64 dev dummy0
            wait_endpoint 10 2001:db8:1::1 2001:db8:3::2 50
            [ "$(cat /sys/class/net/far0/ifindex)" = "$far_index" ] || fail 'session recreated on reload'
            check_identity
            ;;
        conflict)
            ip address add 2001:db8:1::1/64 dev dummy0 nodad
            # A foreign tunnel and session hold session identifier 100.
            ip l2tp add tunnel tunnel_id 900 peer_tunnel_id 901 encap udp \
                local 127.0.0.1 remote 127.0.0.1 udp_sport 9000 udp_dport 9001
            ip l2tp add session tunnel_id 900 session_id 100 peer_session_id 100 name foreign0
            cat > /etc/rs-l2tpd.toml <<'CONFIG'
[tunnels.up]
tunnel_id = 10
remote_addr = "2001:db8:1::2"
[sessions.taken]
tunnel_name = "up"
session_id = 100
interface_name = "taken0"
[sessions.free]
tunnel_name = "up"
session_id = 101
interface_name = "free0"
CONFIG
            # The refused session is retried ten times, then left out: the
            # daemon becomes ready with everything else.
            start_daemon
            ip link show free0 > /dev/null || fail 'the free session must exist'
            if ip link show taken0 > /dev/null 2>&1; then fail 'the taken identifiers cannot be in use twice'; fi
            grep -q 'session_id=100 in tunnel_id=10: the kernel refused its identifiers 10 times' /tmp/daemon.log ||
                fail 'the conflict was not reported'
            [ "$(cat /sys/class/net/foreign0/ifindex)" ] || fail 'foreign session must survive'
            # Once the identifiers are free, the periodic retry creates it.
            ip l2tp del session tunnel_id 900 session_id 100
            attempts=0
            until ip link show taken0 > /dev/null 2>&1; do
                attempts=$((attempts + 1))
                [ "$attempts" -lt 450 ] || fail 'the freed identifiers were not retried'
                sleep 0.1
            done
            ip l2tp show session tunnel_id 10 session_id 100 | grep -Fq 'interface name: taken0' ||
                fail 'session 100 must belong to the daemon now'
            check_identity
            ip l2tp del tunnel tunnel_id 900
            ;;
        *) fail "unknown CASES entry: $test_case" ;;
    esac
    stop_daemon || fail 'daemon shutdown did not complete'
    printf 'PASS %s\n' "$test_case"
done
echo 'PASS all requested source and peer cases'
