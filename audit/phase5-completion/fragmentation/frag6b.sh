#!/bin/sh
# IPv6-underlay probe 2: does the receiver see whole frames on l2tp1, and is netfilter defrag active?
set -u
OUT=/out/probe6b; mkdir -p "$OUT"
a() { nsenter --net=/run/netns/a "$@"; }
b() { nsenter --net=/run/netns/b "$@"; }
ip netns add a; ip netns add b
a ip link set lo up; b ip link set lo up
ip link add name vA mtu 1500 type veth peer name vB mtu 1500
ip link set vA netns a; ip link set vB netns b
a ip link set vA up; b ip link set vB up
a ip -6 addr add fd00::1/64 dev vA nodad; b ip -6 addr add fd00::2/64 dev vB nodad
sleep 1
printf '[tunnels.t2]\ntunnel_id = 12\npeer_tunnel_id = 11\nremote_addr = "fd00::1"\nip_version = "V6"\n[sessions.s2]\ntunnel_name = "t2"\nsession_id = 202\npeer_session_id = 201\ninterface_name = "l2tp1"\n' > "$OUT/b.toml"
printf '[tunnels.t2]\ntunnel_id = 11\npeer_tunnel_id = 12\nremote_addr = "fd00::2"\nip_version = "V6"\n[sessions.s2]\ntunnel_name = "t2"\nsession_id = 201\npeer_session_id = 202\ninterface_name = "l2tp1"\n' > "$OUT/a.toml"
nsenter --net=/run/netns/b /bin-new --foreground --config "$OUT/b.toml" --config-dir /nonexistent 2>"$OUT/b.log" &
nsenter --net=/run/netns/a /bin-new --foreground --config "$OUT/a.toml" --config-dir /nonexistent 2>"$OUT/a.log" &
i=0; while [ $i -lt 100 ]; do a ip link show l2tp1 >/dev/null 2>&1 && b ip link show l2tp1 >/dev/null 2>&1 && break; sleep 0.2; i=$((i+1)); done; sleep 2
a ip link set l2tp1 mtu 1500 up; b ip link set l2tp1 mtu 1500 up
a ip addr add 192.168.11.1/24 dev l2tp1; b ip addr add 192.168.11.2/24 dev l2tp1; sleep 1
echo "== netfilter in netns b: nf_conntrack file: $(b ls /proc/net/nf_conntrack 2>&1); frag6 sysctl: $(b ls /proc/sys/net/netfilter/ 2>/dev/null | grep -c frag6); ip6tables rules: $(b ip6tables -S 2>/dev/null | wc -l)"
echo "== host-side modules: $(grep -E '^(nf_defrag_ipv6|nf_conntrack|br_netfilter) ' /proc/modules | cut -d' ' -f1,3 | tr '\n' ' ')"
rx0=$(b ip -s link show l2tp1 | awk '/RX:/{getline; print $1" "$2}')
r0=$(b cat /proc/net/snmp6 | awk '$1=="Ip6ReasmReqds"||$1=="Ip6ReasmOKs"||$1=="Ip6InReceives"||$1=="Ip6InDelivers"{printf "%s=%s ", $1, $2}')
a ping -c 3 -W 2 -s 1472 192.168.11.2 > "$OUT/ping.txt" 2>&1 && echo "ping ok (3 x 1500-byte inner frames a->b)" || echo "ping FAIL"
rx1=$(b ip -s link show l2tp1 | awk '/RX:/{getline; print $1" "$2}')
r1=$(b cat /proc/net/snmp6 | awk '$1=="Ip6ReasmReqds"||$1=="Ip6ReasmOKs"||$1=="Ip6InReceives"||$1=="Ip6InDelivers"{printf "%s=%s ", $1, $2}')
echo "== b l2tp1 RX bytes/packets before: $rx0  after: $rx1"
echo "== b snmp6 before: $r0"
echo "== b snmp6 after:  $r1"
echo "== b vB RX: $(b ip -s link show vB | awk '/RX:/{getline; print "bytes="$1" packets="$2}')"
pkill -x rs-l2tpd 2>/dev/null; sleep 1
