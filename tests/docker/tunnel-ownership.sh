#!/bin/sh
# An externally deleted managed tunnel's numeric ID may belong to someone
# else by shutdown. Closing our original socket must not delete its successor.
set -eu

fail() {
    cat /tmp/daemon.log >&2
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

cp /artifacts/current /tmp/daemon
chmod 755 /tmp/daemon
ip link set lo up
mkdir -p /etc/rs-l2tpd.toml.d
cat > /etc/rs-l2tpd.toml <<'CONFIG'
[tunnels.test]
tunnel_id = 810001
peer_tunnel_id = 810002
ip_version = "V6"
remote_addr = "::1"
[sessions.test]
tunnel_name = "test"
session_id = 810001
peer_session_id = 810002
interface_name = "pwire0"
CONFIG

timeout 15 /tmp/daemon --pidfile /run/test.pid > /tmp/daemon.log 2>&1 < /dev/null
daemon_pid=$(cat /run/test.pid)
trap 'kill -TERM "$daemon_pid" 2>/dev/null || :' 0

ip l2tp del tunnel tunnel_id 810001
attempts=0
while ip link show dev pwire0 >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 100 ] || fail 'old session did not disappear'
    sleep 0.1
done
attempts=0
until ip l2tp add tunnel tunnel_id 810001 peer_tunnel_id 810003 encap udp \
    local 127.0.0.1 remote 127.0.0.1 udp_sport 8101 udp_dport 8102 \
    > /tmp/foreign-create.log 2>&1; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 100 ] || {
        cat /tmp/foreign-create.log >&2
        fail 'could not reuse the old tunnel ID after asynchronous deletion'
    }
    sleep 0.1
done
ip l2tp add session tunnel_id 810001 session_id 810001 \
    peer_session_id 810004 name foreign0
ip address add 192.0.2.1/24 dev foreign0
ip link set dev foreign0 up
foreign_link=$(ip -o link show dev foreign0)
foreign_addresses=$(ip -4 -o address show dev foreign0)
foreign_tunnel=$(ip l2tp show tunnel)
foreign_session=$(ip l2tp show session)

kill -TERM "$daemon_pid"
attempts=0
while [ -f /run/test.pid ]; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 100 ] || fail 'daemon did not finish shutdown'
    sleep 0.1
done
# Allow queued kernel teardown to run before asserting preservation.
sleep 1
[ "$(ip l2tp show tunnel)" = "$foreign_tunnel" ] || fail 'replacement tunnel changed'
[ "$(ip l2tp show session)" = "$foreign_session" ] || fail 'replacement session changed'
[ "$(ip -o link show dev foreign0)" = "$foreign_link" ] || fail 'replacement link changed'
[ "$(ip -4 -o address show dev foreign0)" = "$foreign_addresses" ] || fail 'replacement addresses changed'
printf 'PASS: shutdown preserves a foreign tunnel and session reusing our IDs\n'
