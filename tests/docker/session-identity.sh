#!/bin/sh
# Reused interface indices must never transfer session ownership.
set -eu
CASES=${CASES:-"rename moved deleted"}
cp /artifacts/current /opt/current
chmod 755 /opt/current
ip link set lo up
daemon_pid=
guest_pid=
cleanup() {
    if [ -n "$daemon_pid" ]; then kill -TERM "$daemon_pid" 2>/dev/null || :; fi
    if [ -n "$guest_pid" ]; then kill "$guest_pid" 2>/dev/null || :; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
fail() {
    echo "$*" >&2
    cat /tmp/daemon.log >&2
    ip -o link show >&2
    if [ -n "$guest_pid" ]; then nsenter -t "$guest_pid" -n ip -o link show >&2; fi
    exit 1
}
write_config() {
    cat > /etc/rs-l2tpd.toml <<'CONFIG'
[tunnels.uplink]
tunnel_id=1001
peer_tunnel_id=2001
ip_version="V6"
remote_addr="::1"
CONFIG
    if [ "$1" = none ]; then return; fi
    cat >> /etc/rs-l2tpd.toml <<CONFIG
[sessions.lan]
tunnel_name="uplink"
session_id=1001
peer_session_id=2001
interface_name="$1"
CONFIG
    if [ -n "${2:-}" ]; then printf 'interface_hwaddr="%s"\n' "$2" >> /etc/rs-l2tpd.toml; fi
}
reload_config() {
    before=$(grep -Ec 'configuration reload completed|failed to apply reloaded configuration' /tmp/daemon.log || :)
    kill -HUP "$daemon_pid"
    n=0
    while [ "$(grep -Ec 'configuration reload completed|failed to apply reloaded configuration' /tmp/daemon.log || :)" -le "$before" ]; do
        n=$((n+1)); [ "$n" -lt 100 ] || fail 'reload was not processed'; sleep 0.1
    done
}
check_foreign() {
    [ "$(cat /sys/class/net/foreign0/ifindex)" = "$original_index" ] || fail 'foreign dummy was renamed or replaced'
    [ "$(cat /sys/class/net/foreign0/address)" = 02:aa:bb:cc:dd:ee ] || fail 'foreign MAC was changed'
    ip -o address show dev foreign0 > /tmp/foreign-current
    diff -u /tmp/foreign-original /tmp/foreign-current || fail 'foreign addresses were changed'
}
for test_case in $CASES; do
    echo "CASE session identity $test_case"
    write_config pseudowire0
    timeout 15 /opt/current --pidfile /run/test.pid > /tmp/daemon.log 2>&1 || fail 'startup failed'
    daemon_pid=$(cat /run/test.pid)
    original_index=$(cat /sys/class/net/pseudowire0/ifindex)
    case "$test_case" in
        rename)
            ip link set pseudowire0 name external0
            write_config pseudowire1 02:00:5e:00:53:01
            reload_config
            [ "$(cat /sys/class/net/pseudowire1/ifindex)" = "$original_index" ] || fail 'external rename lost session identity'
            [ "$(cat /sys/class/net/pseudowire1/address)" = 02:00:5e:00:53:01 ] || fail 'MAC update missed the original renamed session'
            ;;
        moved|deleted)
            if [ "$test_case" = moved ]; then
                unshare -n sleep 90 &
                guest_pid=$!
                sleep 0.2
                ip link set pseudowire0 netns "$guest_pid"
                # /sys may still describe the outer namespace; query netlink.
                guest_original=$(nsenter -t "$guest_pid" -n ip -o link show dev pseudowire0)
            else
                ip l2tp del session tunnel_id 1001 session_id 1001
            fi
            n=0
            while ip link show pseudowire0 >/dev/null 2>&1; do
                n=$((n+1)); [ "$n" -lt 50 ] || fail 'original interface did not leave'; sleep 0.1
            done
            ip link add name foreign0 index "$original_index" type dummy
            ip link set foreign0 address 02:aa:bb:cc:dd:ee
            ip address add 198.51.100.1/24 dev foreign0
            ip address add 2001:db8:50::1/64 dev foreign0 nodad
            ip -o address show dev foreign0 > /tmp/foreign-original
            write_config pseudowire1 02:00:5e:00:53:01
            reload_config
            check_foreign
            if [ "$test_case" = moved ]; then
                [ "$(nsenter -t "$guest_pid" -n ip -o link show dev pseudowire0)" = "$guest_original" ] || fail 'moved session was modified'
            else
                ip l2tp add session tunnel_id 1001 session_id 1001 peer_session_id 2001 name foreignpw
                foreign_session_index=$(cat /sys/class/net/foreignpw/ifindex)
                write_config none
                reload_config
                [ "$(cat /sys/class/net/foreignpw/ifindex)" = "$foreign_session_index" ] || fail 'foreign session reusing the IDs was deleted'
                check_foreign
            fi
            ;;
        *) fail "unknown CASES entry: $test_case" ;;
    esac
    kill -TERM "$daemon_pid"
    n=0
    while [ -e /run/test.pid ]; do
        n=$((n+1)); [ "$n" -lt 100 ] || fail 'shutdown did not finish'; sleep 0.1
    done
    n=0
    while [ -n "$(ip l2tp show tunnel)" ]; do
        n=$((n+1)); [ "$n" -lt 100 ] || fail 'owned tunnel survived shutdown'; sleep 0.1
    done
    daemon_pid=
    if [ "$test_case" != rename ]; then check_foreign; ip link delete foreign0; fi
    if [ -n "$guest_pid" ]; then
        if nsenter -t "$guest_pid" -n ip link show pseudowire0 >/dev/null 2>&1; then fail 'moved session survived owned tunnel teardown'; fi
        kill "$guest_pid"
        wait "$guest_pid" 2>/dev/null || :
        guest_pid=
    fi
    if ip link show foreignpw >/dev/null 2>&1; then fail 'session survived owned tunnel teardown'; fi
    echo "PASS session identity $test_case"
done
echo 'PASS all requested session identity cases'
