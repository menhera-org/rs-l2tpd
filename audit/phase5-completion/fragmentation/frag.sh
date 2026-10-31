#!/bin/sh
# H20/K43 live check: session MTU equal to and larger than the underlay's.
#   docker run --rm --privileged --network none -v frag.sh:/frag.sh:ro -v NEW:/bin-new:ro -v OLD:/bin-old:ro -v out:/out --entrypoint sh IMAGE /frag.sh <new|old>
# Two netns (a, b) joined by a veth pair at MTU 1500. Daemon B is the new binary;
# daemon A is the implementation under test. Tunnel t1 over IPv4, t2 over IPv6.
set -u
IMPL=$1
BIN_NEW=/bin-new; BIN_OLD=/bin-old
OUT=/out/$IMPL; mkdir -p "$OUT"; R=$OUT/result.txt; : > "$R"
say() { printf '%s\n' "$*" | tee -a "$R"; }
a() { nsenter --net=/run/netns/a "$@"; }
b() { nsenter --net=/run/netns/b "$@"; }
snmp4() { $1 cat /proc/net/snmp | awk -v f="$2" '/^Ip:/{ if (!h) { for (i = 1; i <= NF; i++) if ($i == f) c = i; h = 1 } else print $c }'; }
snmp6() { $1 cat /proc/net/snmp6 | awk -v f="$2" '$1 == f { print $2 }'; }
tx_dropped() { $1 ip -s link show dev "$2" | awk '/TX:/{getline; print $4}'; }

say "kernel: $(uname -r); implementation under test: $IMPL"
ip netns add a; ip netns add b
a ip link set lo up; b ip link set lo up
ip link add name vA mtu 1500 type veth peer name vB mtu 1500
ip link set vA netns a; ip link set vB netns b
a ip link set vA up; b ip link set vB up
a ip addr add 10.0.0.1/24 dev vA; b ip addr add 10.0.0.2/24 dev vB
a ip -6 addr add fd00::1/64 dev vA nodad; b ip -6 addr add fd00::2/64 dev vB nodad
sleep 1

cat > "$OUT/b.toml" <<EOF
[tunnels.t1]
tunnel_id = 2
peer_tunnel_id = 1
remote_addr = "10.0.0.1"
ip_version = "V4"
[tunnels.t2]
tunnel_id = 12
peer_tunnel_id = 11
remote_addr = "fd00::1"
ip_version = "V6"
[sessions.s1]
tunnel_name = "t1"
session_id = 102
peer_session_id = 101
interface_name = "l2tp0"
[sessions.s2]
tunnel_name = "t2"
session_id = 202
peer_session_id = 201
interface_name = "l2tp1"
EOF
cat > "$OUT/a.toml" <<EOF
[tunnels.t1]
tunnel_id = 1
peer_tunnel_id = 2
remote_addr = "10.0.0.2"
ip_version = "V4"
[tunnels.t2]
tunnel_id = 11
peer_tunnel_id = 12
remote_addr = "fd00::2"
ip_version = "V6"
[sessions.s1]
tunnel_name = "t1"
session_id = 101
peer_session_id = 102
interface_name = "l2tp0"
[sessions.s2]
tunnel_name = "t2"
session_id = 201
peer_session_id = 202
interface_name = "l2tp1"
EOF

nsenter --net=/run/netns/b "$BIN_NEW" --foreground --verbose --config "$OUT/b.toml" --config-dir /nonexistent 2>"$OUT/b.log" &
B_PID=$!
if [ "$IMPL" = new ]; then
  nsenter --net=/run/netns/a "$BIN_NEW" --foreground --verbose --config "$OUT/a.toml" --config-dir /nonexistent 2>"$OUT/a.log" &
else
  cp "$OUT/a.toml" /etc/rs-l2tpd.toml
  nsenter --net=/run/netns/a "$BIN_OLD" -v --pidfile "$OUT/a.pid" 2>"$OUT/a.log" &
fi
# wait for both session devices on both sides
i=0
while [ $i -lt 100 ]; do
  if a ip link show l2tp0 >/dev/null 2>&1 && a ip link show l2tp1 >/dev/null 2>&1 \
     && b ip link show l2tp0 >/dev/null 2>&1 && b ip link show l2tp1 >/dev/null 2>&1; then break; fi
  sleep 0.2; i=$((i+1))
done
sleep 2
say "A daemon log so far:"; sed 's/^/   A| /' "$OUT/a.log" | tee -a "$R" >/dev/null
a ip l2tp show tunnel | sed 's/^/   a tunnel| /' | tee -a "$R" >/dev/null
say "underlay: $(a ip -o link show vA | sed 's/ qdisc.*//')"
say "session devices before the cases: $(a ip -o link show l2tp0 | sed 's/ qdisc.*//'); $(a ip -o link show l2tp1 | sed 's/ qdisc.*//')"

run_case() { # run_case DEV FAMILY(4|6) MTU SUBNET
  dev=$1; fam=$2; mtu=$3; net=$4
  # Either MTU command failing must report the failure and end this case.
  # shellcheck disable=SC2015
  a ip link set "$dev" mtu "$mtu" && b ip link set "$dev" mtu "$mtu" || { say "  $dev: cannot set mtu $mtu"; return; }
  a ip link set "$dev" up; b ip link set "$dev" up
  a ip addr replace "192.168.$net.1/24" dev "$dev"; b ip addr replace "192.168.$net.2/24" dev "$dev"
  sleep 1
  if [ "$fam" = 4 ]; then
    fa0=$(snmp4 a FragCreates); rb0=$(snmp4 b ReasmReqds); fb0=$(snmp4 b FragCreates); ra0=$(snmp4 a ReasmReqds)
  else
    fa0=$(snmp6 a Ip6FragCreates); rb0=$(snmp6 b Ip6ReasmReqds); fb0=$(snmp6 b Ip6FragCreates); ra0=$(snmp6 a Ip6ReasmReqds)
  fi
  d0=$(tx_dropped a "$dev")
  size=$((mtu - 28))
  if a ping -c 3 -W 2 -s "$size" "192.168.$net.2" >"$OUT/ping-$dev-$mtu-ab.txt" 2>&1; then r1=ok; else r1=FAIL; fi
  if b ping -c 3 -W 2 -s "$size" "192.168.$net.1" >"$OUT/ping-$dev-$mtu-ba.txt" 2>&1; then r2=ok; else r2=FAIL; fi
  if [ "$fam" = 4 ]; then
    fa1=$(snmp4 a FragCreates); rb1=$(snmp4 b ReasmReqds); fb1=$(snmp4 b FragCreates); ra1=$(snmp4 a ReasmReqds)
  else
    fa1=$(snmp6 a Ip6FragCreates); rb1=$(snmp6 b Ip6ReasmReqds); fb1=$(snmp6 b Ip6FragCreates); ra1=$(snmp6 a Ip6ReasmReqds)
  fi
  d1=$(tx_dropped a "$dev")
  verdict=PASS
  [ "$r1" = ok ] && [ "$r2" = ok ] || verdict=FAIL
  [ $((fa1 - fa0)) -gt 0 ] && [ $((rb1 - rb0)) -gt 0 ] && [ $((fb1 - fb0)) -gt 0 ] && [ $((ra1 - ra0)) -gt 0 ] || verdict="$verdict(no-fragmentation-seen)"
  say "$dev over IPv$fam underlay, session mtu $mtu, payload $size: ping a->b $r1, b->a $r2; a FragCreates +$((fa1-fa0)) ReasmReqds +$((ra1-ra0)); b FragCreates +$((fb1-fb0)) ReasmReqds +$((rb1-rb0)); tx_dropped +$((d1-d0)) => $verdict"
}
run_case l2tp0 4 1500 10
run_case l2tp0 4 9000 10
run_case l2tp1 6 1500 11
run_case l2tp1 6 9000 11
say "A daemon log lines during the cases: $(wc -l < "$OUT/a.log") total"
kill $B_PID 2>/dev/null; kill "$(cat "$OUT/a.pid" 2>/dev/null)" 2>/dev/null; pkill -x rs-l2tpd 2>/dev/null; sleep 1
