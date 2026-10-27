#!/bin/sh
# Absorb ordinary link bursts; prove safe behavior after deliberate overflow.
set -eu
MODE=${MODE:-burst}
case "$MODE" in
    burst) default_changes=128 ;;
    overflow) default_changes=50000 ;;
    *) echo 'MODE must be burst or overflow' >&2; exit 1 ;;
esac
NOISE_LINKS=${NOISE_LINKS:-$default_changes}
case "$NOISE_LINKS" in ''|*[!0-9]*) echo 'NOISE_LINKS must be an integer' >&2; exit 1 ;; esac
[ "$NOISE_LINKS" -gt 0 ] && [ "$NOISE_LINKS" -le 200000 ] || {
    echo 'NOISE_LINKS must be between 1 and 200000' >&2
    exit 1
}
cp /artifacts/current /opt/current
chmod 755 /opt/current
daemon_pid=
cleanup() {
    if [ -n "$daemon_pid" ]; then kill -CONT "$daemon_pid" 2>/dev/null || :; kill -TERM "$daemon_pid" 2>/dev/null || :; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
fail() { echo "$*" >&2; cat /tmp/daemon.log >&2; ip -o link show >&2; exit 1; }
write_config() {
    cat > /etc/rs-l2tpd.toml <<'CONFIG'
[tunnels.uplink]
tunnel_id=1001
peer_tunnel_id=2001
ip_version="V6"
remote_addr="2001:db8:1::2"
bind_interface="underlay0"
CONFIG
    if [ "$1" = none ]; then return; fi
    cat >> /etc/rs-l2tpd.toml <<CONFIG
[sessions.lan]
tunnel_name="uplink"
session_id=1001
peer_session_id=2001
interface_name="$1"
CONFIG
    if [ -n "$2" ]; then printf 'interface_hwaddr="%s"\n' "$2" >> /etc/rs-l2tpd.toml; fi
    cat >> /etc/rs-l2tpd.toml <<CONFIG
[sessions.guard]
tunnel_name="uplink"
session_id=1002
peer_session_id=2002
interface_name="$3"
CONFIG
}
reload_config() {
    before=$(grep -Ec 'configuration reload completed|failed to apply reloaded configuration' /tmp/daemon.log || :)
    kill -HUP "$daemon_pid"
    n=0
    while [ "$(grep -Ec 'configuration reload completed|failed to apply reloaded configuration' /tmp/daemon.log || :)" -le "$before" ]; do
        n=$((n+1)); [ "$n" -lt 100 ] || fail 'reload not processed'; sleep 0.1
    done
}
ip link set lo up
for device in underlay0 noise0; do ip link add "$device" type dummy; ip link set "$device" addrgenmode none; ip link set "$device" up; done
ip address add 2001:db8:1::1/64 dev underlay0 nodad
write_config pseudowire0 '' guard0
timeout 15 /opt/current --pidfile /run/test.pid >/tmp/daemon.log 2>&1
daemon_pid=$(cat /run/test.pid)
original_mac=$(cat /sys/class/net/pseudowire0/address)
original_index=$(cat /sys/class/net/pseudowire0/ifindex)
foreign_index=$(cat /sys/class/net/guard0/ifindex)
sleep 0.5
kill -STOP "$daemon_pid"
n=0
until awk '$1 == "State:" {exit $2 != "T"}' /proc/"$daemon_pid"/status; do n=$((n+1)); [ "$n" -lt 50 ]; sleep 0.1; done
awk -v count="$NOISE_LINKS" 'BEGIN { for(i=1;i<=count;i++) printf "link set dev noise0 mtu %d\n", 1400+i%2 }' >/tmp/link-flood
ip -batch /tmp/link-flood
# In overflow mode, this deletion arrives after the paused queues are full.
ip l2tp del session tunnel_id 1001 session_id 1002
ip link add foreign0 index "$foreign_index" type dummy
ip link set foreign0 address 02:aa:bb:cc:dd:ee
ip address add 198.51.100.1/24 dev foreign0
ip address delete 2001:db8:1::1/64 dev underlay0
ip address add 2001:db8:1::3/64 dev underlay0 nodad
kill -CONT "$daemon_pid"
n=0
until ip l2tp show tunnel tunnel_id 1001 | grep -Fq 'From 2001:db8:1::3 to 2001:db8:1::2'; do
    n=$((n+1)); [ "$n" -lt 100 ] || fail 'source recovery not observed'; sleep 0.1
done
echo "PASS $MODE source recovery after $NOISE_LINKS link changes"
write_config pseudowire0 02:00:5e:00:53:01 guard0
reload_config
if [ "$MODE" = burst ]; then
    [ "$(cat /sys/class/net/pseudowire0/address)" = 02:00:5e:00:53:01 ] || fail 'normal burst prevented MAC update'
else
    grep -Fq 'netlink socket buffer full' /tmp/daemon.log || fail 'no overflow occurred; increase NOISE_LINKS'
    [ "$(cat /sys/class/net/pseudowire0/address)" = "$original_mac" ] || fail 'unprovable session MAC changed after overflow'
fi
write_config renamed0 '' guard0
reload_config
if [ "$MODE" = burst ]; then
    original_name=renamed0
    [ "$(cat /sys/class/net/renamed0/ifindex)" = "$original_index" ] || fail 'normal burst prevented rename'
    if grep -Fq 'netlink socket buffer full' /tmp/daemon.log; then fail 'normal burst overflowed'; fi
    echo 'PASS ordinary burst preserves session management without overflow'
else
    original_name=pseudowire0
    [ "$(cat /sys/class/net/pseudowire0/ifindex)" = "$original_index" ] || fail 'unprovable original session was renamed'
    echo 'PASS deliberate overflow refuses MAC and rename without continuity proof'
fi
write_config "$original_name" '' guard1
reload_config
[ "$(cat /sys/class/net/foreign0/ifindex)" = "$foreign_index" ] || fail 'foreign replacement was renamed'
[ "$(cat /sys/class/net/foreign0/address)" = 02:aa:bb:cc:dd:ee ] || fail 'foreign MAC modified'
ip -o address show dev foreign0 | grep -Fq 'inet 198.51.100.1/24' || fail 'foreign address modified'
echo 'PASS replacement created during the burst remains untouched'
write_config none '' ''
reload_config
if [ "$MODE" = burst ]; then
    if ip link show "$original_name" >/dev/null 2>&1; then fail 'normal burst prevented individual removal'; fi
    echo 'PASS ordinary burst preserves individual session removal'
else
    [ "$(cat /sys/class/net/pseudowire0/ifindex)" = "$original_index" ] || fail 'unprovable original session was deleted'
    echo 'PASS unprovable original session retained until owned-tunnel teardown'
fi
kill -TERM "$daemon_pid"
n=0
while [ -e /run/test.pid ] || [ -n "$(ip l2tp show tunnel)" ]; do n=$((n+1)); [ "$n" -lt 100 ] || fail 'shutdown incomplete'; sleep 0.1; done
daemon_pid=
[ "$(cat /sys/class/net/foreign0/ifindex)" = "$foreign_index" ] || fail 'shutdown removed foreign dummy'
echo 'PASS owned-tunnel shutdown cleans original session and preserves replacement'
