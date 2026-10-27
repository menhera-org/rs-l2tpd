#!/bin/sh
# Run in an isolated container with a real systemd-networkd installation.
set -eu

NETWORKD=${NETWORKD:-/usr/lib/systemd/systemd-networkd}
NETWORKCTL=${NETWORKCTL:-networkctl}
CASES=${CASES:-"main vrf"}
cp /artifacts/current /opt/current
chmod 755 /opt/current
mkdir -p /run/systemd /run/dbus /etc/systemd/network
networkd_pid=
dbus_pid=$(dbus-daemon --system --fork --nopidfile --print-pid=1)

fail() {
    echo "$*" >&2
    cat /tmp/daemon.log /tmp/networkd.log >&2
    ip -6 route show table all >&2
    ip l2tp show tunnel >&2
    exit 1
}

cleanup() {
    if [ -f /run/test.pid ]; then
        kill -TERM "$(cat /run/test.pid)" 2>/dev/null || :
    fi
    if [ -n "$networkd_pid" ]; then
        kill -TERM "$networkd_pid" 2>/dev/null || :
    fi
    kill -TERM "$dbus_pid" 2>/dev/null || :
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

stop_networkd() {
    if [ -n "$networkd_pid" ]; then
        kill -TERM "$networkd_pid"
        wait "$networkd_pid"
        networkd_pid=
    fi
}

start_networkd() {
    SYSTEMD_LOG_LEVEL=debug "$NETWORKD" >> /tmp/networkd.log 2>&1 &
    networkd_pid=$!
}

ifindex() {
    ip -o link show dev "$1" | cut -d : -f 1
}

socket_identities() {
    # Native IP L2TP sockets are not in these standard socket tables.
    awk '
        FNR == 1 { next }
        FILENAME ~ /\/unix$/ { print "socket:[" $7 "]"; next }
        { print "socket:[" $10 "]" }
    ' /proc/"$daemon_pid"/net/netlink /proc/"$daemon_pid"/net/unix \
        /proc/"$daemon_pid"/net/udp /proc/"$daemon_pid"/net/udp6 \
        /proc/"$daemon_pid"/net/tcp /proc/"$daemon_pid"/net/tcp6 \
        > /tmp/control-sockets
    for fd in /proc/"$daemon_pid"/fd/*; do
        target=$(readlink "$fd" 2>/dev/null || :)
        case "$target" in socket:*) printf '%s\n' "$target" ;; esac
    done | sort -u | grep -Fvx -f /tmp/control-sockets || :
}

check_identity() {
    [ "$(cat /run/test.pid)" = "$daemon_pid" ] || fail 'daemon restarted'
    [ "$(ifindex pseudowire0)" = "$session_index" ] || fail 'session interface was recreated'
    [ "$(ip -o address show dev pseudowire0 scope global)" = "$session_addresses" ] ||
        fail 'session addresses changed'
    [ "$(socket_identities)" = "$tunnel_sockets" ] || fail 'tunnel socket was replaced'
    ip l2tp show session tunnel_id 1001 session_id 1001 |
        grep -Fq 'Peer session 2001, tunnel 2001' || fail 'session IDs changed'
    ip l2tp show tunnel tunnel_id 1001 | grep -Fq 'to 100::' || fail 'discard peer changed'
    [ "$(ip -6 route show table 103)" = "$unrelated_routes" ] || fail 'unrelated table changed'
    if [ "$test_case" = vrf ]; then
        [ -z "$(ip -6 route show table main exact 100::/128)" ] || fail 'VRF repair escaped into the main table'
    fi
}

wait_route() {
    attempts=0
    until ip -6 route show table "$route_table" exact 100::/128 | grep -Fq "dev $null_name"; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 100 ] || fail "discard route was not restored in table $route_table"
        sleep 0.1
    done
    check_identity
}

removal_count() {
    grep -c 'Removing foreign route .*dst: 100::/128' /tmp/networkd.log || :
}

wait_networkd_removal() {
    attempts=0
    until [ "$(removal_count)" -gt "$1" ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 100 ] || fail 'networkd did not exercise foreign-route removal'
        kill -0 "$networkd_pid" 2>/dev/null || fail 'networkd exited'
        sleep 0.1
    done
    wait_route
}

for test_case in $CASES; do
    printf 'CASE networkd routes %s\n' "$test_case"
    : > /tmp/daemon.log
    : > /tmp/networkd.log
    ip link set lo up
    ip -6 route replace 2001:db8:103::/64 dev lo table 103
    # Networkd itself preserves kernel-protocol routes. This sentinel can
    # therefore detect daemon changes without networkd deleting it first.
    ip -6 route replace unreachable 100::/128 table 103 metric 1024 proto kernel
    unrelated_routes=$(ip -6 route show table 103)
    foreign_discard_routes=$(ip -6 route show table all exact 100::/128)
    route_table=254
    case "$test_case" in
        main) bind_name= ;;
        vrf)
            route_table=101
            bind_name=vrf0
            ip link add vrf0 type vrf table "$route_table"
            ip link set vrf0 up
            ip link add source0 type dummy
            ip link set source0 addrgenmode none
            ip link set source0 master vrf0
            ip link set source0 up
            ip address add 2001:db8:101::1/64 dev source0 nodad
            ip -6 route add unreachable default table "$route_table" metric 4278198272
            ;;
        *) fail "unknown CASES entry: $test_case" ;;
    esac
    cat > /etc/rs-l2tpd.toml <<'CONFIG'
[tunnels.test]
tunnel_id = 1001
peer_tunnel_id = 2001
ip_version = "V6"
remote_addr = "100::"
CONFIG
    if [ -n "$bind_name" ]; then
        printf 'bind_interface = "%s"\n' "$bind_name" >> /etc/rs-l2tpd.toml
    fi
    cat >> /etc/rs-l2tpd.toml <<'CONFIG'
[sessions.test]
tunnel_name = "test"
session_id = 1001
peer_session_id = 2001
interface_name = "pseudowire0"
CONFIG
    timeout 25 /opt/current --pidfile /run/test.pid > /tmp/daemon.log 2>&1 ||
        fail 'daemon did not become ready'
    daemon_pid=$(cat /run/test.pid)
    null_name=$(ip -6 route show table "$route_table" exact 100::/128 |
        awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
    [ -n "$null_name" ] || fail 'initial discard route is missing'
    ip link set pseudowire0 addrgenmode none
    ip link set pseudowire0 up
    ip address add 198.18.0.1/30 dev pseudowire0
    ip address add fd00:2::1/64 dev pseudowire0 nodad
    session_index=$(ifindex pseudowire0)
    session_addresses=$(ip -o address show dev pseudowire0 scope global)
    tunnel_sockets=$(socket_identities)
    [ -n "$tunnel_sockets" ] || fail 'tunnel socket identity is unavailable'
    cat > /etc/systemd/network/10-test.network <<'NETWORK'
[Match]
Name=rsl2tpnull*
[Network]
NETWORK
    previous_removals=$(removal_count)
    start_networkd
    wait_networkd_removal "$previous_removals"
    echo 'PASS initial networkd configuration repaired'

    previous_removals=$(removal_count)
    "$NETWORKCTL" --no-pager reload
    "$NETWORKCTL" --no-pager reconfigure "$null_name"
    wait_networkd_removal "$previous_removals"
    echo 'PASS networkd reload and reconfiguration repaired'

    previous_removals=$(removal_count)
    stop_networkd
    start_networkd
    wait_networkd_removal "$previous_removals"
    echo 'PASS networkd restart repaired'

    for iteration in 1 2 3; do
        ip -6 route delete 100::/128 table "$route_table" dev "$null_name"
        wait_route
        printf 'PASS route deletion %s repaired\n' "$iteration"
    done

    if [ "$test_case" = vrf ]; then
        old_index=$(ifindex vrf0)
        ip link delete vrf0
        route_table=102
        ip link add vrf0 type vrf table "$route_table"
        ip link set vrf0 up
        ip link set source0 master vrf0
        ip address replace 2001:db8:101::1/64 dev source0 nodad
        ip -6 route add unreachable default table "$route_table" metric 4278198272
        [ "$(ifindex vrf0)" != "$old_index" ] || fail 'VRF replacement reused the old index'
        wait_route
        if [ -n "$(ip -6 route show table 101 exact 100::/128)" ]; then
            ip -6 route delete 100::/128 table 101 dev "$null_name"
        fi
        ip -6 route delete 100::/128 table "$route_table" dev "$null_name"
        wait_route
        sleep 1.5
        [ -z "$(ip -6 route show table 101 exact 100::/128)" ] || fail 'obsolete VRF table was repaired'
        echo 'PASS replacement VRF table repaired'
    fi

    # Leave a repair pending while shutdown begins. Neither its timer nor a
    # later networkd reconfiguration may recreate daemon resources.
    ip -6 route delete 100::/128 table "$route_table" dev "$null_name"
    kill -TERM "$daemon_pid"
    attempts=0
    while [ -e /run/test.pid ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 50 ] || fail 'daemon shutdown did not complete'
        sleep 0.1
    done
    stop_networkd
    start_networkd
    sleep 2
    [ -z "$(ip l2tp show tunnel)" ] || fail 'tunnel survived shutdown'
    if ip link show pseudowire0 >/dev/null 2>&1; then fail 'session survived shutdown'; fi
    if ip link show "$null_name" >/dev/null 2>&1; then fail 'null device was resurrected'; fi
    [ "$(ip -6 route show table all exact 100::/128)" = "$foreign_discard_routes" ] ||
        fail 'shutdown changed a foreign route or retained an owned discard route'
    stop_networkd
    if [ "$test_case" = vrf ]; then
        ip link delete source0
        ip link delete vrf0
    fi
    printf 'PASS networkd routes %s\n' "$test_case"
done
echo 'PASS all requested networkd route cases'
