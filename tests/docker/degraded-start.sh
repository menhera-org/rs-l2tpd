#!/bin/sh
# Runs inside a disposable container with its own network namespace.
# /artifacts/current is the daemon under test, mounted read-only.
#
# Configuration mistakes must never stop the daemon. An unusable endpoint
# only affects connectivity: the tunnel and its session interfaces are
# created, connected to the discard address, and a corrected reload
# reconnects the tunnel in place. An unusable hardware address only affects
# the interface's address: the session is created with the kernel's, and a
# corrected reload applies the address in place. Any other mistake leaves
# its entry out at start-up; on a reload the entry keeps its previous
# values, or is left out if it is new, and only an unparsable file keeps
# the whole previous configuration. --check prints what would be applied
# and exits 1 on any problem. Nothing usable, or nothing at all, is a valid
# configuration. A host that does not route the discard address gets the
# daemon's null device, which discards the frames; readiness waits for
# every configurable interface.
set -eu

cp /artifacts/current /opt/current
chmod 755 /opt/current

cleanup() {
    if [ -e /run/test.pid ]; then
        kill "$(cat /run/test.pid)" 2>/dev/null || :
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

wait_for_log() {
    attempts=0
    until grep -q "$1" /tmp/daemon.log; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 100 ]; then
            echo "timed out waiting for: $1" >&2
            echo '--- daemon log' >&2
            cat /tmp/daemon.log >&2
            echo '--- configuration' >&2
            cat /etc/rs-l2tpd.toml >&2
            return 1
        fi
        sleep 0.1
    done
}

# Reloads and waits for the reload to be applied or refused.
reload() {
    before=$(grep -c -E 'configuration (reload|convergence) completed|failed to load configuration' /tmp/daemon.log || true)
    kill -HUP "$(cat /run/test.pid)"
    attempts=0
    until [ "$(grep -c -E 'configuration (reload|convergence) completed|failed to load configuration' /tmp/daemon.log || true)" -gt "$before" ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 100 ] || { echo 'timed out waiting for the reload' >&2; cat /tmp/daemon.log >&2; return 1; }
        sleep 0.1
    done
}

stop_daemon() {
    kill -TERM "$(cat /run/test.pid)"
    attempts=0
    while [ -e /run/test.pid ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 50 ] || return 1
        sleep 0.1
    done
    [ -z "$(ip l2tp show tunnel)" ]
}

tunnel_count() {
    ip l2tp show tunnel | grep -c '^Tunnel' || true
}

ifindex() {
    ip -o link show "$1" | cut -d: -f1
}

hwaddr() {
    ip -o link show "$1" | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p'
}

tx_packets() {
    ip -s link show "$1" | awk '/TX:/ { getline; print $2 }'
}

ip link set lo up
ip link add dummy0 type dummy
ip link set dummy0 up
ip address add 2001:db8:1::1/64 dev dummy0 nodad
ip address add 192.0.2.1/24 dev dummy0

mkdir -p /etc/rs-l2tpd.toml.d
cat > /etc/rs-l2tpd.toml <<EOF
[tunnels.good]
tunnel_id = 10
remote_addr = "2001:db8:1::2"

[tunnels.soft]
tunnel_id = 11
ip_version = "V6"
remote_addr = "192.0.2.2"

[tunnels.hard]
tunnel_id = 0
remote_addr = "2001:db8:1::3"

[tunnels.far]
tunnel_id = 13
remote_addr = "2001:db8:2::2"

[sessions.on-good]
tunnel_name = "good"
session_id = 100
interface_name = "good0"

[sessions.on-soft]
tunnel_name = "soft"
session_id = 102
interface_name = "soft0"

[sessions.on-hard]
tunnel_name = "hard"
session_id = 103
interface_name = "hard0"

[sessions.on-far]
tunnel_name = "far"
session_id = 104
interface_name = "far0"

[sessions.bad-mac]
tunnel_name = "good"
session_id = 101
interface_name = "badmac0"
interface_hwaddr = "01:00:5e:00:53:01"
EOF
printf '[sessions.on-good]\ninterface_name = [\n' > /etc/rs-l2tpd.toml.d/90-broken.toml

echo 'CASE --check with mistakes'
if /opt/current --check > /tmp/check.out 2> /tmp/check.err; then
    echo "--check must exit 1 when it found problems" >&2
    exit 1
fi
grep -q '^\[tunnels.good\]' /tmp/check.out
grep -q '^\[tunnels.soft\]' /tmp/check.out
grep -q '^\[tunnels.far\]' /tmp/check.out
grep -q '^remote_addr = "100::"$' /tmp/check.out
grep -q '^\[sessions.on-good\]' /tmp/check.out
grep -q '^\[sessions.on-soft\]' /tmp/check.out
grep -q '^\[sessions.bad-mac\]' /tmp/check.out
if grep -q 'tunnels.hard\|sessions.on-hard\|interface_hwaddr' /tmp/check.out; then
    echo "--check must print what would be applied only" >&2
    exit 1
fi
grep -q 'left out: .*90-broken.toml' /tmp/check.err
grep -q 'left out: tunnel hard: tunnel_id is zero' /tmp/check.err
grep -q 'left out: session on-hard: its tunnel hard was rejected' /tmp/check.err
grep -q 'no peer until corrected: tunnel soft: remote_addr 192.0.2.2 is IPv4 but ip_version is IPv6' /tmp/check.err
grep -q 'kernel hardware address until corrected: session bad-mac: interface_hwaddr: hardware address 01:00:5e:00:53:01 is a multicast address' /tmp/check.err
# --check touches nothing.
if ip link show rsl2tpnull0 > /dev/null 2>&1; then
    echo "--check must not create the null device" >&2
    exit 1
fi
echo 'PASS --check with mistakes'

echo 'CASE readiness waits for every configurable interface'
# The far peer has no route, so that tunnel cannot be created yet and the
# parent must not exit: readiness is deferred until every tunnel and
# session exists. The discard address has no route either; the daemon
# provides one through its null device, as the tunnels before it show.
timeout 60 /opt/current --pidfile /run/test.pid > /tmp/daemon.log 2>&1 &
parent=$!
sleep 3
kill -0 "$parent"
grep -q 'initial configuration apply failed; will retry' /tmp/daemon.log
if ip link show soft0 > /dev/null 2>&1 || [ -e /run/test.pid ]; then
    echo "readiness must wait for every configurable interface" >&2
    exit 1
fi
ip link show rsl2tpnull0 > /dev/null
ip -6 route get 100:: | grep -q 'dev rsl2tpnull0'
grep -q 'routed the discard address 100:: to the null device rsl2tpnull0 for tunnel_id=11' /tmp/daemon.log
ip -6 route add 2001:db8:2::/64 dev dummy0
wait "$parent"
[ -e /run/test.pid ]
echo 'PASS readiness waits for every configurable interface'

echo 'CASE degraded start'
ip link show good0 > /dev/null
ip link show soft0 > /dev/null
ip link show far0 > /dev/null
ip link show badmac0 > /dev/null
if ip link show hard0 > /dev/null 2>&1; then
    echo "rejected sessions must not be created" >&2
    exit 1
fi
kernel_mac=$(hwaddr badmac0)
[ -n "$kernel_mac" ]
[ "$kernel_mac" != "02:00:5e:00:53:01" ]
[ "$(tunnel_count)" -eq 3 ]
ip l2tp show tunnel | grep -A1 '^Tunnel 11,' | grep -q 'to 100::'
grep -q 'left out: tunnel hard: tunnel_id is zero' /tmp/daemon.log
grep -q 'left out: .*90-broken.toml' /tmp/daemon.log
grep -q 'no peer until corrected: tunnel soft:' /tmp/daemon.log
grep -q 'kernel hardware address until corrected: session bad-mac:' /tmp/daemon.log
grep -q 'starting with the usable part of the configuration only' /tmp/daemon.log
grep -q 'initial configuration applied' /tmp/daemon.log
soft_index=$(ifindex soft0)
badmac_index=$(ifindex badmac0)
good_index=$(ifindex good0)
echo 'PASS degraded start'

echo 'CASE frames of a tunnel without a peer are discarded locally'
before=$(tx_packets rsl2tpnull0)
ip link set soft0 up
ip address add 198.18.1.1/24 dev soft0
# The neighbour solicitation for a peer on the pseudowire is the frame.
ping -n -q -c 1 -W 1 198.18.1.2 > /dev/null 2>&1 || :
sleep 1
after=$(tx_packets rsl2tpnull0)
[ "$after" -gt "$before" ]
ip link set soft0 down
echo 'PASS frames of a tunnel without a peer are discarded locally'

echo 'CASE reload with an unparsable file keeps the previous configuration'
reload
# The TOML error spans several lines; the verdict follows it.
grep -q 'failed to load configuration: .*90-broken.toml' /tmp/daemon.log
grep -q 'keeping the previous configuration' /tmp/daemon.log
ip link show good0 > /dev/null
[ "$(tunnel_count)" -eq 3 ]
echo 'PASS reload with an unparsable file keeps the previous configuration'

echo 'CASE reload keeps the previous values of a broken entry'
rm /etc/rs-l2tpd.toml.d/90-broken.toml
# The valid tunnel breaks (and keeps its values); the new one stays broken
# (and stays out); the tolerated problems stay tolerated.
sed -i 's/^tunnel_id = 10$/tunnel_id = 0  # was 10/' /etc/rs-l2tpd.toml
reload
wait_for_log 'configuration reload completed'
grep -q 'keeping the previous values until corrected: tunnel good: tunnel_id is zero' /tmp/daemon.log
grep -q 'configuration problem, left out: tunnel hard: tunnel_id is zero' /tmp/daemon.log
[ "$(grep -c 'no peer until corrected: tunnel soft:' /tmp/daemon.log)" -ge 2 ]
[ "$(grep -c 'kernel hardware address until corrected: session bad-mac:' /tmp/daemon.log)" -ge 2 ]
ip link show good0 > /dev/null
[ "$(ifindex good0)" = "$good_index" ]
[ "$(ifindex soft0)" = "$soft_index" ]
[ "$(ifindex badmac0)" = "$badmac_index" ]
[ "$(tunnel_count)" -eq 3 ]
ip l2tp show tunnel | grep -q '^Tunnel 10,'
echo 'PASS reload keeps the previous values of a broken entry'

echo 'CASE reload with corrected identifiers creates the missing entries'
sed -i 's/^tunnel_id = 0  # was 10$/tunnel_id = 10/; s/^tunnel_id = 0$/tunnel_id = 12/' /etc/rs-l2tpd.toml
reload
wait_for_log 'configuration reload completed'
ip link show hard0 > /dev/null
[ "$(ifindex good0)" = "$good_index" ]
[ "$(ifindex soft0)" = "$soft_index" ]
[ "$(ifindex badmac0)" = "$badmac_index" ]
[ "$(hwaddr badmac0)" = "$kernel_mac" ]
[ "$(tunnel_count)" -eq 4 ]
ip l2tp show tunnel | grep -A1 '^Tunnel 11,' | grep -q 'to 100::'
echo 'PASS reload with corrected identifiers creates the missing entries'

echo 'CASE corrected endpoint and address apply in place'
sed -i 's/^ip_version = "V6"$/ip_version = "V4"/; s/^interface_hwaddr = "01:00:5e:00:53:01"$/interface_hwaddr = "02:00:5e:00:53:01"/' /etc/rs-l2tpd.toml
reload
grep -q 'updating tunnel_id=11 remote_addr=192.0.2.2' /tmp/daemon.log
[ "$(ifindex soft0)" = "$soft_index" ]
[ "$(ifindex badmac0)" = "$badmac_index" ]
[ "$(hwaddr badmac0)" = "02:00:5e:00:53:01" ]
[ "$(tunnel_count)" -eq 4 ]
ip l2tp show tunnel | grep -A1 '^Tunnel 11,' | grep -q 'to .*192.0.2.2'
echo 'PASS corrected endpoint and address apply in place'
stop_daemon
grep -q 'removed the null device rsl2tpnull0' /tmp/daemon.log
if ip link show rsl2tpnull0 > /dev/null 2>&1; then
    echo "shutdown must remove the null device" >&2
    exit 1
fi

echo 'CASE nothing usable is a valid start'
printf '[tunnels.hard]\ntunnel_id = 0\nremote_addr = "2001:db8:1::3"\n' > /etc/rs-l2tpd.toml
if /opt/current --check > /tmp/check.out 2> /tmp/check.err; then
    echo "--check must exit 1 when it found problems" >&2
    exit 1
fi
timeout 15 /opt/current --pidfile /run/test.pid > /tmp/daemon.log 2>&1
[ -z "$(ip l2tp show tunnel)" ]
grep -q 'left out: tunnel hard: tunnel_id is zero' /tmp/daemon.log
grep -q 'initial configuration applied' /tmp/daemon.log
# Nothing needs the discard address, so nothing creates the null device.
if ip link show rsl2tpnull0 > /dev/null 2>&1; then
    echo "the null device must be created only when needed" >&2
    exit 1
fi
stop_daemon
echo 'PASS nothing usable is a valid start'

echo 'CASE an empty configuration is a valid start'
: > /etc/rs-l2tpd.toml
# An empty configuration renders as its two empty tables.
/opt/current --check > /tmp/check.out
if grep -q '^\[tunnels\.\|^\[sessions\.' /tmp/check.out; then
    echo "--check must print no entries for an empty configuration" >&2
    exit 1
fi
timeout 15 /opt/current --pidfile /run/test.pid > /tmp/daemon.log 2>&1
[ -z "$(ip l2tp show tunnel)" ]
grep -q 'initial configuration applied' /tmp/daemon.log
stop_daemon
echo 'PASS an empty configuration is a valid start'

echo 'PASS all ten degraded-start cases'
