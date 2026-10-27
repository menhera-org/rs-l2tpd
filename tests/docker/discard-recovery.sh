#!/bin/sh
# Run in an isolated Docker network namespace with NET_ADMIN and NET_RAW.
# /artifacts/current is the static daemon under test, mounted read-only.
set -eu

cp /artifacts/current /opt/current
chmod 755 /opt/current
CASES=${CASES:-"dns fallback existing replacement"}

fail() {
    echo "$*" >&2
    cat /tmp/discard-daemon.log >&2
    ip l2tp show tunnel >&2
    exit 1
}

stop_daemon() {
    if [ -f /run/discard-daemon.pid ]; then
        kill -TERM "$(cat /run/discard-daemon.pid)" 2>/dev/null || :
        attempts=0
        while [ -e /run/discard-daemon.pid ]; do
            attempts=$((attempts + 1))
            [ "$attempts" -lt 50 ] || fail 'daemon shutdown did not complete'
            sleep 0.1
        done
    fi
}

cleanup() {
    if [ -f /run/discard-daemon.pid ]; then
        kill -CONT "$(cat /run/discard-daemon.pid)" 2>/dev/null || :
        kill -TERM "$(cat /run/discard-daemon.pid)" 2>/dev/null || :
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

reset_case() {
    stop_daemon
    for device in $(ip -o link show type dummy | awk -F ': ' '{ sub(/@.*/, "", $2); print $2 }'); do
        ip link delete "$device"
    done
    : > /tmp/discard-daemon.log
    printf '127.0.0.1 localhost\n::1 localhost\n' > /etc/hosts
    # Failed lookups stay local and return promptly; the positive answer is
    # added to /etc/hosts and observed by the normal resolver refresh.
    printf 'nameserver 127.0.0.1\noptions attempts:1 timeout:1\n' > /etc/resolv.conf
    ip link set lo up
}

write_config() {
    cat > /etc/rs-l2tpd.toml <<CONFIG
[tunnels.uplink]
tunnel_id = 1001
peer_tunnel_id = 2001
ip_version = "V6"
remote_addr = "$1"
CONFIG
    if [ -n "$2" ]; then
        printf 'bind_interface = "%s"\n' "$2" >> /etc/rs-l2tpd.toml
    fi
    cat >> /etc/rs-l2tpd.toml <<'CONFIG'
[sessions.lan]
tunnel_name = "uplink"
session_id = 1001
peer_session_id = 2001
interface_name = "pseudowire0"
CONFIG
}

socket_identities() {
    # Native IP L2TP sockets are absent from these standard socket tables.
    # Exclude resolver, netlink and runtime socketpair descriptors: a DNS
    # request can outlive both initial snapshots, then close on resolution.
    awk '
        FNR == 1 { next }
        FILENAME ~ /\/unix$/ { print "socket:[" $7 "]"; next }
        { print "socket:[" $10 "]" }
    ' /proc/"$daemon_pid"/net/netlink /proc/"$daemon_pid"/net/unix \
        /proc/"$daemon_pid"/net/udp /proc/"$daemon_pid"/net/udp6 \
        /proc/"$daemon_pid"/net/tcp /proc/"$daemon_pid"/net/tcp6 \
        > /tmp/discard-control-sockets
    for fd in /proc/"$daemon_pid"/fd/*; do
        target=$(readlink "$fd" 2>/dev/null || :)
        case "$target" in
            socket:*) printf '%s\n' "$target" ;;
        esac
    done | sort -u | grep -Fvx -f /tmp/discard-control-sockets || :
}

ifindex() {
    ip -o link show dev "$1" | cut -d : -f 1
}

start_daemon() {
    timeout 25 /opt/current --pidfile /run/discard-daemon.pid > /tmp/discard-daemon.log 2>&1 ||
        fail 'daemon did not become ready'
    daemon_pid=$(cat /run/discard-daemon.pid)
    ip link set pseudowire0 addrgenmode none
    ip link set pseudowire0 up
    ip address add 198.18.0.1/30 dev pseudowire0
    ip address add fd00:2::1/64 dev pseudowire0 nodad
    original_index=$(ifindex pseudowire0)
    original_addresses=$(ip -o address show dev pseudowire0 scope global)
    sleep 0.2
    socket_identities > /tmp/discard-sockets-first
    sleep 0.2
    socket_identities > /tmp/discard-sockets-second
    comm -12 /tmp/discard-sockets-first /tmp/discard-sockets-second > /tmp/discard-sockets-original
    [ -s /tmp/discard-sockets-original ] || fail 'daemon socket identities are unavailable'
}

check_identity() {
    [ "$(cat /run/discard-daemon.pid)" = "$daemon_pid" ] || fail 'daemon restarted'
    [ "$(ifindex pseudowire0)" = "$original_index" ] || fail 'session interface was recreated'
    [ "$(ip -o address show dev pseudowire0 scope global)" = "$original_addresses" ] ||
        fail 'session addresses changed'
    socket_identities > /tmp/discard-sockets-current
    while IFS= read -r socket; do
        grep -Fxq "$socket" /tmp/discard-sockets-current || fail 'persistent socket was replaced'
    done < /tmp/discard-sockets-original
    ip l2tp show session tunnel_id 1001 session_id 1001 |
        grep -Fq 'Peer session 2001, tunnel 2001' || fail 'session IDs changed'
}

wait_endpoints() {
    attempts=0
    until ip l2tp show tunnel tunnel_id 1001 | grep -Fq "From $1 to $2"; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt "$3" ] || fail "expected source $1 and peer $2"
        sleep 0.1
    done
    check_identity
}

check_shutdown() {
    stop_daemon
    [ -z "$(ip l2tp show tunnel)" ] || fail 'tunnel survived shutdown'
    if ip link show pseudowire0 >/dev/null 2>&1; then
        fail 'session interface survived shutdown'
    fi
}

add_admin_device() {
    ip link add "$1" type dummy
    ip link set "$1" addrgenmode none
    ip link set "$1" up
    ip address add 2001:db8:99::1/64 dev "$1" nodad
    ip -6 route add 2001:db8:88::/64 dev "$1"
    protected_index=$(ifindex "$1")
}

check_admin_device() {
    [ "$(ifindex "$1")" = "$protected_index" ] || fail 'unowned dummy device was removed or replaced'
    ip -o address show dev "$1" | grep -Fq '2001:db8:99::1/64' ||
        fail 'unowned dummy address was removed'
    ip -6 route show 2001:db8:88::/64 | grep -Fq "dev $1" ||
        fail 'unowned dummy route was removed'
}

for test_case in $CASES; do
    printf 'CASE discard recovery %s\n' "$test_case"
    reset_case
    case "$test_case" in
        dns)
            ip link add underlay0 type dummy
            ip link set underlay0 addrgenmode none
            ip link set underlay0 up
            ip address add 2001:db8:10::1/64 dev underlay0 nodad
            ip -6 route add 100::/128 dev underlay0
            write_config late-peer.test underlay0
            start_daemon
            wait_endpoints 2001:db8:10::1 100:: 50
            ip address delete 2001:db8:10::1/64 dev underlay0
            ip address add 2001:db8:10::3/64 dev underlay0 nodad
            printf '2001:db8:10::2 late-peer.test\n' >> /etc/hosts
            # Wait through the daemon's normal 30-second DNS refresh. No
            # SIGHUP or tunnel recreation is used to provoke recovery.
            wait_endpoints 2001:db8:10::3 2001:db8:10::2 450
            check_shutdown
            ;;
        fallback)
            write_config 100:: ''
            start_daemon
            ip l2tp show tunnel tunnel_id 1001 | grep -Fq 'to 100::' || fail 'discard peer is missing'
            ip link add real0 type dummy
            ip link set real0 addrgenmode none
            ip link set real0 up
            ip address add 2001:db8:20::1/64 dev real0 nodad
            write_config 2001:db8:20::2 ''
            kill -HUP "$daemon_pid"
            wait_endpoints 2001:db8:20::1 2001:db8:20::2 100
            check_shutdown
            ;;
        existing)
            add_admin_device rsl2tpnull0
            write_config 100:: ''
            start_daemon
            check_admin_device rsl2tpnull0
            check_shutdown
            check_admin_device rsl2tpnull0
            ;;
        replacement)
            write_config 100:: ''
            start_daemon
            null_name=$(ip -6 route get 100:: | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
            [ -n "$null_name" ] || fail 'discard route has no output device'
            old_index=$(ifindex "$null_name")
            # Queue the removal and replacement together. Otherwise automatic
            # repair can legitimately reclaim the free name before this fixture.
            kill -STOP "$daemon_pid"
            attempts=0
            until grep -q '^State:.*T' "/proc/$daemon_pid/status"; do
                attempts=$((attempts + 1))
                [ "$attempts" -lt 50 ] || fail 'daemon did not stop for replacement'
                sleep 0.1
            done
            ip link delete "$null_name"
            add_admin_device "$null_name"
            [ "$protected_index" != "$old_index" ] || fail 'replacement device reused the old interface index'
            kill -CONT "$daemon_pid"
            attempts=0
            while :; do
                repaired_name=$(ip -6 route show exact 100::/128 |
                    awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
                if [ -n "$repaired_name" ] && [ "$repaired_name" != "$null_name" ]; then break; fi
                attempts=$((attempts + 1))
                [ "$attempts" -lt 100 ] || fail 'discard route was not repaired through a fresh owned device'
                sleep 0.1
            done
            check_admin_device "$null_name"
            check_shutdown
            check_admin_device "$null_name"
            ;;
        *) fail "unknown CASES entry: $test_case" ;;
    esac
    printf 'PASS discard recovery %s\n' "$test_case"
done
echo 'PASS all requested discard-recovery cases'
