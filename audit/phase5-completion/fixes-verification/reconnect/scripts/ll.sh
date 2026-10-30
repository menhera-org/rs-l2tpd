#!/bin/sh
# Link-local zoned peer debug: variant "vrf" (A bound to vrfA, zone bindA member) or "plain" (A unbound, zone bindA).
set -u
V=$1; OUT=/out/ll-$V; mkdir -p "$OUT"; BIN=/bin-new
a() { nsenter --net=/run/netns/a "$@"; }; b() { nsenter --net=/run/netns/b "$@"; }
ip netns add a; ip netns add b; a ip link set lo up; b ip link set lo up
ip link add name bindA type veth peer name vB; ip link set bindA netns a; ip link set vB netns b
b ip link set vB up; b ip -6 addr add fe80::2/64 dev vB nodad
a sh -c 'echo 1 > /proc/sys/net/ipv6/conf/bindA/keep_addr_on_down'
a ip link set bindA up; a ip -6 addr add fd00::1/64 dev bindA nodad; a ip -6 addr add fe80::1/64 dev bindA nodad
sleep 2
printf '[tunnels.t5]\ntunnel_id = 42\npeer_tunnel_id = 41\nremote_addr = "fe80::1%%vB"\nip_version = "v6"\n[sessions.s5]\ntunnel_name = "t5"\nsession_id = 502\npeer_session_id = 501\ninterface_name = "l2tp4"\n' > "$OUT/b.toml"
if [ "$V" = vrf ]; then bind='bind_interface = "vrfA"\n'; a ip link add name vrfA type vrf table 100; a ip link set vrfA up; a ip link set bindA master vrfA; sleep 3; else bind=''; fi
printf '[tunnels.t5]\ntunnel_id = 41\npeer_tunnel_id = 42\nremote_addr = "fe80::2%%bindA"\nip_version = "v6"\n'"$bind"'[sessions.s5]\ntunnel_name = "t5"\nsession_id = 501\npeer_session_id = 502\ninterface_name = "l2tp4"\n' > "$OUT/a.toml"
nsenter --net=/run/netns/b $BIN --foreground --verbose --config "$OUT/b.toml" --config-dir /x --pid-file "$OUT/b.pid" 2>"$OUT/b.log" &
nsenter --net=/run/netns/a $BIN --foreground --verbose --config "$OUT/a.toml" --config-dir /x --pid-file "$OUT/a.pid" 2>"$OUT/a.log" &
sleep 4
a ip link set l2tp4 up; a ip addr add 192.168.4.1/24 dev l2tp4; b ip link set l2tp4 up; b ip addr add 192.168.4.2/24 dev l2tp4; sleep 1
echo "--- A tunnel:"; a ip l2tp show tunnel; echo "--- B tunnel:"; b ip l2tp show tunnel
echo "--- A addrs:"; a ip -6 addr show dev bindA | grep inet6; echo "--- B addrs:"; b ip -6 addr show dev vB | grep inet6
echo "--- ping a->b over l2tp4:"; a ping -c 2 -W 1 192.168.4.2; echo "rc=$?"
echo "--- counters A l2tp4:"; a ip -s link show dev l2tp4 | sed -n '3,6p'; echo "--- counters B l2tp4:"; b ip -s link show dev l2tp4 | sed -n '3,6p'
echo "--- counters A bindA:"; a ip -s link show dev bindA | sed -n '3,6p'; echo "--- counters B vB:"; b ip -s link show dev vB | sed -n '3,6p'
echo "--- ping b->a over l2tp4:"; b ping -c 2 -W 1 192.168.4.1; echo "rc=$?"
echo "--- A nstat:"; a nstat -az 2>/dev/null | grep -E 'Ip6In|Ip6Out|InNoRoutes|InAddrErrors|InDiscards' | grep -v ' 0 '
echo "--- A routes table all fe80:"; a ip -6 route show table all | grep -E 'fe80|local' | head
echo "--- A log:"; grep -v DEBUG "$OUT/a.log"; echo "--- B log:"; grep -v DEBUG "$OUT/b.log"
