#!/bin/sh
# A host whose IPv6 is disabled with sysctls: every configured tunnel and
# session must still exist, IPv4 peers must work, and the rest must use the
# IPv4 discard address until it can be reached. Run with
#   --sysctl net.ipv6.conf.all.disable_ipv6=1
#   --sysctl net.ipv6.conf.default.disable_ipv6=1
# /artifacts/current is the static daemon under test, mounted read-only.
set -eu

cp /artifacts/current /opt/current
chmod 755 /opt/current

fail() {
    echo "$*" >&2
    cat /tmp/daemon.log >&2
    ip l2tp show tunnel >&2
    ip route show >&2
    exit 1
}

cleanup() {
    if [ -e /run/test.pid ]; then
        kill -TERM "$(cat /run/test.pid)" 2>/dev/null || :
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" = 1 ] ||
    fail 'run with --sysctl net.ipv6.conf.all.disable_ipv6=1'
[ "$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6)" = 1 ] ||
    fail 'run with --sysctl net.ipv6.conf.default.disable_ipv6=1'

ip link set lo up
ip link add dummy0 type dummy
ip link set dummy0 up
ip address add 192.0.2.1/24 dev dummy0
printf 'nameserver 127.0.0.1\noptions attempts:1 timeout:1\n' > /etc/resolv.conf
printf '127.0.0.1 localhost\n' > /etc/hosts
cat > /etc/rs-l2tpd.toml <<'EOF'
[tunnels.lit4]
tunnel_id = 10
remote_addr = "192.0.2.2"

[tunnels.name4]
tunnel_id = 11
ip_version = "V4"
remote_addr = "late-peer.test"

[tunnels.name6]
tunnel_id = 12
ip_version = "V6"
remote_addr = "peer6.test"

[tunnels.lit6]
tunnel_id = 13
remote_addr = "2001:db8::2"

[tunnels.far4]
tunnel_id = 14
remote_addr = "198.51.100.2"

[sessions.lit4]
tunnel_name = "lit4"
session_id = 100
interface_name = "lit4s0"

[sessions.name4]
tunnel_name = "name4"
session_id = 101
interface_name = "name4s0"

[sessions.name6]
tunnel_name = "name6"
session_id = 102
interface_name = "name6s0"

[sessions.lit6]
tunnel_name = "lit6"
session_id = 103
interface_name = "lit6s0"

[sessions.far4]
tunnel_name = "far4"
session_id = 104
interface_name = "far4s0"
EOF

echo 'CASE IPv6-disabled host becomes ready with every interface'
# Nothing routes 192.0.0.8 or 100:: here: the daemon waits its grace
# period, creates its null device, routes the IPv4 discard address to it
# (the IPv6 one cannot be routed on this host) and becomes ready.
timeout 90 /opt/current --pidfile /run/test.pid > /tmp/daemon.log 2>&1 ||
    fail 'daemon did not become ready'
for session in lit4s0 name4s0 name6s0 lit6s0 far4s0; do
    ip link show "$session" > /dev/null || fail "$session is missing"
done
[ "$(ip l2tp show tunnel | grep -c '^Tunnel')" -eq 5 ] || fail 'five tunnels expected'
ip l2tp show tunnel tunnel_id 10 | grep -Fq 'to ::ffff:192.0.2.2' ||
    fail 'the IPv4 literal peer must be connected'
ip l2tp show tunnel tunnel_id 11 | grep -Fq 'to ::ffff:192.0.0.8' ||
    fail 'an IPv4 host name must use the IPv4 discard address'
ip l2tp show tunnel tunnel_id 12 | grep -Fq 'to ::ffff:192.0.0.8' ||
    fail 'an IPv6 host name must fall back to the IPv4 discard address'
ip l2tp show tunnel tunnel_id 13 | grep -Fq 'to ::ffff:192.0.0.8' ||
    fail 'an unreachable IPv6 literal must fall back to the IPv4 discard address'
ip l2tp show tunnel tunnel_id 14 | grep -Fq 'to ::ffff:192.0.0.8' ||
    fail 'an unroutable IPv4 literal must use the IPv4 discard address'
ip link show rsl2tpnull0 > /dev/null || fail 'the null device is expected'
ip route get 192.0.0.8 | grep -Fq 'dev rsl2tpnull0' ||
    fail 'the IPv4 discard route must go through the null device'
grep -q 'cannot reach its peer 198.51.100.2 yet' /tmp/daemon.log ||
    fail 'the pending IPv4 peer was not reported'
grep -q 'cannot reach its peer 2001:db8::2 yet' /tmp/daemon.log ||
    fail 'the pending IPv6 peer was not reported'
echo 'PASS IPv6-disabled host becomes ready with every interface'

echo 'CASE a route to the pending IPv4 peer connects it in place'
far_index=$(cat /sys/class/net/far4s0/ifindex)
ip route add 198.51.100.0/24 dev dummy0
attempts=0
until ip l2tp show tunnel tunnel_id 14 | grep -Fq 'to ::ffff:198.51.100.2'; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 100 ] || fail 'the pending IPv4 peer was not connected'
    sleep 0.1
done
grep -q 'tunnel_id=14 reached its peer 198.51.100.2' /tmp/daemon.log ||
    fail 'reaching the peer was not logged'
[ "$(cat /sys/class/net/far4s0/ifindex)" = "$far_index" ] || fail 'session interface was recreated'
echo 'PASS a route to the pending IPv4 peer connects it in place'

echo 'CASE a resolving IPv4 host name connects in place'
name4_index=$(cat /sys/class/net/name4s0/ifindex)
printf '192.0.2.3 late-peer.test\n' >> /etc/hosts
# The normal 30-second resolver refresh, no reload.
attempts=0
until ip l2tp show tunnel tunnel_id 11 | grep -Fq 'to ::ffff:192.0.2.3'; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 450 ] || fail 'the resolved IPv4 peer was not connected'
    sleep 0.1
done
[ "$(cat /sys/class/net/name4s0/ifindex)" = "$name4_index" ] || fail 'session interface was recreated'
echo 'PASS a resolving IPv4 host name connects in place'

echo 'CASE no retry storm and clean shutdown'
# The IPv6 discard route can never be installed here; that is reported,
# not retried every second.
[ "$(grep -c 'failed to restore discard routes' /tmp/daemon.log)" -le 1 ] ||
    fail 'route restoration was retried loudly'
kill -TERM "$(cat /run/test.pid)"
attempts=0
while [ -e /run/test.pid ]; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 100 ] || fail 'shutdown did not finish'
    sleep 0.1
done
[ -z "$(ip l2tp show tunnel)" ] || fail 'tunnels survived shutdown'
if ip link show rsl2tpnull0 > /dev/null 2>&1; then fail 'the null device survived shutdown'; fi
echo 'PASS no retry storm and clean shutdown'
echo 'PASS all IPv6-disabled host cases'
