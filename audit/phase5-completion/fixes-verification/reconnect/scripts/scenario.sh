#!/bin/sh
# Reconnection scenarios for rs-l2tpd, run inside
#   docker run --rm --privileged --network none ... --entrypoint sh rs-l2tpd-audit-vm:local /scenario.sh <new|old> <scenario>
# Two netns (a, b) joined by a veth pair. Daemon B (always the new binary, unbound tunnels)
# is the fixed peer; daemon A (new or v0.1.5) is the one under test.
set -u
IMPL=$1; SC=$2
BIN_NEW=/bin-new; BIN_OLD=/bin-old
OUT=/out/$IMPL-$SC; mkdir -p "$OUT"
A_LOG=$OUT/a.log; B_LOG=$OUT/b.log; R=$OUT/result.txt
: > "$R"
T0=$(date +%s)
say() { printf '[%3ds] %s\n' $(( $(date +%s) - T0 )) "$*" | tee -a "$R"; }
step() { say "== $*"; }
a() { nsenter --net=/run/netns/a "$@"; }
b() { nsenter --net=/run/netns/b "$@"; }

# wait_log LOG PATTERN [SECS] [MINCOUNT]: wait until grep -c PATTERN >= MINCOUNT
wait_log() {
  f=$1; p=$2; s=${3:-6}; n=${4:-1}; i=0
  while [ $i -lt $((s*5)) ]; do
    c=$(grep -c -- "$p" "$f" 2>/dev/null || true)
    if [ "${c:-0}" -ge "$n" ]; then say "  seen ($c): $p"; return 0; fi
    sleep 0.2; i=$((i+1))
  done
  say "  MISSING after ${s}s (count $(grep -c -- "$p" "$f" 2>/dev/null)): $p"; return 1
}
count_log() { c=$(grep -c -- "$2" "$1" 2>/dev/null); echo "${c:-0}"; }
# nolog LOG PATTERN COUNT: assert count unchanged
nolog() { c=$(count_log "$1" "$2"); if [ "$c" -eq "$3" ]; then say "  unchanged ($c): $2"; else say "  CHANGED $3->$c: $2"; fi; }
tx_dropped() { $1 ip -s link show dev "$2" | awk '/TX:/{getline; print $4}'; }
# pingcheck NS DEV ADDR: ping over the l2tpeth device; report result and tx_dropped delta
pingcheck() {
  ns=$1; dev=$2; addr=$3
  d0=$(tx_dropped "$ns" "$dev")
  if $ns ping -c 2 -W 1 "$addr" >/dev/null 2>&1; then r=ok; else r=FAIL; fi
  d1=$(tx_dropped "$ns" "$dev")
  say "  ping $dev -> $addr: $r (tx_dropped +$((d1-d0)))"
}
ifindex() { $1 ip -o link show dev "$2" 2>/dev/null | cut -d: -f1; }
tail_new() { sed -n "$(( $2 + 1 )),\$p" "$1"; }

# ---------- topology ----------
ip netns add a; ip netns add b
a ip link set lo up; b ip link set lo up
mk_veth() { # mk_veth ANAME : create veth, move ends, configure B side; A side left down and bare
  ip link add name "$1" type veth peer name vB
  ip link set "$1" netns a; ip link set vB netns b
  b ip link set vB up
  b ip addr add 10.0.0.2/24 dev vB; b ip addr add 10.0.0.3/24 dev vB
  b ip -6 addr add fd00::2/64 dev vB nodad; b ip -6 addr add fe80::2/64 dev vB nodad
  b ip -6 addr add fd00:9::2/128 dev vB nodad
  b sh -c 'echo 1 > /proc/sys/net/ipv4/conf/all/promote_secondaries'
}
a_dev_up() { # a_dev_up NAME : bring A's veth end up with addresses
  a sh -c "echo 1 > /proc/sys/net/ipv6/conf/$1/keep_addr_on_down" 2>/dev/null
  a ip link set "$1" up
  a ip addr add 10.0.0.1/24 dev "$1"
  a ip -6 addr add fd00::1/64 dev "$1" nodad; a ip -6 addr add fe80::1/64 dev "$1" nodad
  sleep 1
}
inner() { # inner NS DEV N : address l2tpeth device
  $1 ip link set "$2" up 2>/dev/null && $1 ip addr add "192.168.$3.$4/24" dev "$2" 2>/dev/null
}
inner_all() { # address every l2tpN in both namespaces
  for n in 0 1 2 3 4; do inner a l2tp$n $n 1; inner b l2tp$n $n 2; done
}
printf '10.0.0.2 peerb.test\n' >> /etc/hosts

# ---------- configs ----------
cat > "$OUT/b.toml" <<EOF
[tunnels.t1]
tunnel_id = 2
peer_tunnel_id = 1
remote_addr = "10.0.0.1"
ip_version = "v4"
[tunnels.t2]
tunnel_id = 12
peer_tunnel_id = 11
remote_addr = "fd00::1"
ip_version = "v6"
[tunnels.t3]
tunnel_id = 22
peer_tunnel_id = 21
remote_addr = "10.0.0.1"
ip_version = "v4"
[tunnels.t4]
tunnel_id = 32
peer_tunnel_id = 31
remote_addr = "10.0.0.1"
ip_version = "v4"
[tunnels.t5]
tunnel_id = 42
peer_tunnel_id = 41
remote_addr = "fe80::1%vB"
ip_version = "v6"
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
[sessions.s3]
tunnel_name = "t3"
session_id = 302
peer_session_id = 301
interface_name = "l2tp2"
[sessions.s4]
tunnel_name = "t4"
session_id = 402
peer_session_id = 401
interface_name = "l2tp3"
[sessions.s5]
tunnel_name = "t5"
session_id = 502
peer_session_id = 501
interface_name = "l2tp4"
EOF

# a_cfg T1BIND T1REMOTE T1VER [extra tunnels: t2 t3 t4 t5] -> stdout
a_cfg() {
  bind=$1; rem=$2; ver=$3; shift 3
  printf '[tunnels.t1]\ntunnel_id = 1\npeer_tunnel_id = 2\nremote_addr = "%s"\nip_version = "%s"\n' "$rem" "$ver"
  [ -n "$bind" ] && printf 'bind_interface = "%s"\n' "$bind"
  printf '[sessions.s1]\ntunnel_name = "t1"\nsession_id = 101\npeer_session_id = 102\ninterface_name = "l2tp0"\n'
  for t in "$@"; do case $t in
    t2) printf '[tunnels.t2]\ntunnel_id = 11\npeer_tunnel_id = 12\nremote_addr = "fd00:9::2"\nip_version = "v6"\n[sessions.s2]\ntunnel_name = "t2"\nsession_id = 201\npeer_session_id = 202\ninterface_name = "l2tp1"\n';;
    t3) printf '[tunnels.t3]\ntunnel_id = 21\npeer_tunnel_id = 22\nremote_addr = "peerb.test"\nip_version = "v4"\n[sessions.s3]\ntunnel_name = "t3"\nsession_id = 301\npeer_session_id = 302\ninterface_name = "l2tp2"\n';;
    t4) printf '[tunnels.t4]\ntunnel_id = 31\npeer_tunnel_id = 32\nremote_addr = "10.0.0.2"\nip_version = "v4"\nbind_interface = "vrfA"\n[sessions.s4]\ntunnel_name = "t4"\nsession_id = 401\npeer_session_id = 402\ninterface_name = "l2tp3"\n';;
    t5) printf '[tunnels.t5]\ntunnel_id = 41\npeer_tunnel_id = 42\nremote_addr = "fe80::2%%bindA"\nip_version = "v6"\nbind_interface = "vrfA"\n[sessions.s5]\ntunnel_name = "t5"\nsession_id = 501\npeer_session_id = 502\ninterface_name = "l2tp4"\n';;
    nofix) printf '[host]\nfix_bindv6only = false\n';;
  esac; done
}

start_b() {
  # not through the a()/b() functions: a backgrounded function is a subshell and $! would be its pid
  nsenter --net=/run/netns/b "$BIN_NEW" --foreground --verbose --config "$OUT/b.toml" --config-dir /nonexistent --pid-file "$OUT/b.pid" 2>"$B_LOG" &
  B_PID=$!
  wait_log "$B_LOG" "tunnel t1 (tunnel_id=2): created" 10 >/dev/null
}
# start_a CONFIGFILE : starts daemon A of $IMPL
start_a() {
  if [ "$IMPL" = new ]; then
    nsenter --net=/run/netns/a "$BIN_NEW" --foreground --verbose --config "$1" --config-dir /nonexistent --pid-file "$OUT/a.pid" 2>"$A_LOG" &
    A_PID=$!
  else
    # v0.1.5's serde attribute is `rename = "lowercase"` (not rename_all), so it accepts only "V4"/"V6".
    sed 's/ip_version = "v\([46]\)"/ip_version = "V\1"/' "$1" > /etc/rs-l2tpd.toml
    # v0.1.5 double-forks; the parent exits at readiness; stderr stays ours.
    nsenter --net=/run/netns/a "$BIN_OLD" -v --pidfile "$OUT/a.pid" 2>"$A_LOG" &
    A_PID=
  fi
}
a_pid() { if [ -n "${A_PID:-}" ]; then echo "$A_PID"; else cat "$OUT/a.pid" 2>/dev/null; fi; }
reload_a() { cp "$1" "$OUT/a.toml"; [ "$IMPL" = old ] && sed 's/ip_version = "v\([46]\)"/ip_version = "V\1"/' "$1" > /etc/rs-l2tpd.toml; kill -HUP "$(a_pid)"; }
a_pat() { # a_pat KEY TUNNELNAME ID : the implementation's log pattern for an event
  if [ "$IMPL" = new ]; then case $1 in
    created) echo "tunnel $2 (tunnel_id=$3): created";;
    connected) echo "tunnel $2 (tunnel_id=$3): connected to";;
    disconnected) echo "tunnel $2 (tunnel_id=$3): disconnected";;
    absent) echo "tunnel $2 (tunnel_id=$3): disconnected: its bind device is absent";;
    pending) echo "tunnel $2 (tunnel_id=$3): disconnected, peer";;
  esac; else case $1 in
    created) echo "adding tunnel_id=$3";;
    connected) echo "tunnel_id=$3";;
    disconnected) echo "tunnel_id=$3";;
    absent) echo "bind interface .* is absent for tunnel_id=$3";;
    pending) echo "tunnel_id=$3";;
  esac; fi
}
dump_state() {
  say "  -- ip l2tp show tunnel (a):"; a ip l2tp show tunnel | sed 's/^/     /' | tee -a "$R"
}
finish() {
  say "== done; A log tail:"; tail -n 40 "$A_LOG" | sed 's/^/   A| /' | tee -a "$R"
  say "-- B log (reconnect-related lines):"; grep -E 'connected|disconnected|pending' "$B_LOG" | sed 's/^/   B| /' | tee -a "$R"
  kill "$(a_pid)" 2>/dev/null; kill "$B_PID" 2>/dev/null; sleep 1
}

case $SC in
# ---------------------------------------------------------------- S1
s1) step "S1: bind device absent at start; appears under another name; renamed to the configured name (T13, E1, E2)"
  start_b
  a_cfg bindA 10.0.0.2 v4 t2 t3 t4 t5 > "$OUT/a.toml"; [ $IMPL = old ] && a_cfg bindA 10.0.0.2 v4 > "$OUT/a.toml"
  start_a "$OUT/a.toml"
  wait_log "$A_LOG" "$(a_pat created t1 1)" 10
  if [ $IMPL = new ]; then wait_log "$A_LOG" "$(a_pat absent t1 1)" 5; else wait_log "$A_LOG" "$(a_pat absent t1 1)" 5; grep -E 'tunnel_id=1|100::|discard|failed' "$A_LOG" | head -5 | sed 's/^/   A| /' | tee -a "$R"; fi
  l0=$(wc -l < "$A_LOG")
  step "create the veth as tmp0 (wrong name), up, addressed"
  mk_veth tmp0; a_dev_up tmp0
  sleep 2; say "  new A log lines since device creation under the wrong name:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  nolog "$A_LOG" "$(a_pat connected t1 1)" 0
  step "rename tmp0 -> bindA"
  a ip link set tmp0 name bindA
  wait_log "$A_LOG" "$(a_pat connected t1 1)" 6
  wait_log "$A_LOG" "bound tunnel_id=1 socket to interface bindA" 6 >/dev/null 2>&1 || true
  inner_all; pingcheck a l2tp0 192.168.0.2
  dump_state
  if [ $IMPL = new ]; then
    step "siblings: t3 (fqdn, unbound) connected; t2 (no route) pending; t4/t5 (vrfA absent) pending"
    wait_log "$A_LOG" "$(a_pat connected t3 21)" 3; wait_log "$A_LOG" "$(a_pat pending t2 11)" 3; wait_log "$A_LOG" "$(a_pat absent t4 31)" 3; wait_log "$A_LOG" "$(a_pat absent t5 41)" 3
  fi
  finish;;
# ---------------------------------------------------------------- S2
s2) step "S2: bind device renamed away / removed; re-added (T11, T12, E2, E3, H13)"
  mk_veth bindA; a_dev_up bindA; start_b
  a_cfg bindA 10.0.0.2 v4 t2 t3 > "$OUT/a.toml"; [ $IMPL = old ] && a_cfg bindA 10.0.0.2 v4 > "$OUT/a.toml"
  start_a "$OUT/a.toml"
  wait_log "$A_LOG" "$(a_pat connected t1 1)" 10; inner_all; pingcheck a l2tp0 192.168.0.2
  c_conn=$(count_log "$A_LOG" "$(a_pat connected t1 1)"); l0=$(wc -l < "$A_LOG")
  step "rename bindA -> tmp0 (name lost)"
  a ip link set bindA name tmp0
  if [ $IMPL = new ]; then wait_log "$A_LOG" "$(a_pat disconnected t1 1)" 4; else sleep 2; fi
  say "  A log since rename:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  pingcheck a l2tp0 192.168.0.2
  step "rename tmp0 -> bindA (name back)"
  a ip link set tmp0 name bindA
  wait_log "$A_LOG" "$(a_pat connected t1 1)" 6 $((c_conn+1)) || wait_log "$A_LOG" "bound tunnel_id=1" 6
  pingcheck a l2tp0 192.168.0.2
  c_conn=$(count_log "$A_LOG" "$(a_pat connected t1 1)"); l0=$(wc -l < "$A_LOG")
  step "delete the veth (bindA and vB vanish)"
  a ip link del bindA
  if [ $IMPL = new ]; then wait_log "$A_LOG" "$(a_pat disconnected t1 1)" 4; else sleep 2; fi
  say "  A log since deletion:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  say "  B log: unbound sources removed -> reconnect attempts:"; grep -E 'pending|disconnected' "$B_LOG" | tail -4 | sed 's/^/   B| /' | tee -a "$R"
  pingcheck a l2tp0 192.168.0.2
  step "re-create the veth under the same name (new index)"
  mk_veth bindA; a_dev_up bindA
  wait_log "$A_LOG" "$(a_pat connected t1 1)" 8 $((c_conn+1)) || wait_log "$A_LOG" "bound tunnel_id=1" 6
  wait_log "$B_LOG" "tunnel t1 (tunnel_id=2): connected to" 6 2
  sleep 1; pingcheck a l2tp0 192.168.0.2
  dump_state; finish;;
# ---------------------------------------------------------------- S3
s3) step "S3: address events on the bind device and on an unbound tunnel's source (T19, E6, E7, E8, H14)"
  mk_veth bindA; a_dev_up bindA; start_b
  a_cfg bindA 10.0.0.2 v4 t2 t3 > "$OUT/a.toml"; [ $IMPL = old ] && a_cfg bindA 10.0.0.2 v4 > "$OUT/a.toml"
  start_a "$OUT/a.toml"
  wait_log "$A_LOG" "$(a_pat connected t1 1)" 10; inner_all; pingcheck a l2tp0 192.168.0.2
  c=$(count_log "$A_LOG" "$(a_pat connected t1 1)"); l0=$(wc -l < "$A_LOG")
  step "add 10.0.0.11/24 to bindA (same family) -> one reconnect expected"
  a ip addr add 10.0.0.11/24 dev bindA
  wait_log "$A_LOG" "$(a_pat connected t1 1)" 4 $((c+1)) || wait_log "$A_LOG" "reconnected tunnel_id=1" 4
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"; pingcheck a l2tp0 192.168.0.2
  c=$(count_log "$A_LOG" "$(a_pat connected t1 1)"); c3=$(count_log "$A_LOG" "$(a_pat connected t3 21)"); l0=$(wc -l < "$A_LOG")
  step "add fd00:1::1/64 to bindA (other family) -> no reconnect of the v4 tunnel expected"
  a ip -6 addr add fd00:1::1/64 dev bindA nodad; sleep 2
  nolog "$A_LOG" "$(a_pat connected t1 1)" $c; say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  l0=$(wc -l < "$A_LOG")
  step "remove 10.0.0.11/24 -> one reconnect expected; unbound t3 untouched"
  a ip addr del 10.0.0.11/24 dev bindA
  wait_log "$A_LOG" "$(a_pat connected t1 1)" 4 $((c+1)) || wait_log "$A_LOG" "reconnected tunnel_id=1" 4
  [ $IMPL = new ] && nolog "$A_LOG" "$(a_pat connected t3 21)" $c3
  pingcheck a l2tp0 192.168.0.2
  step "B side: remove B's source 10.0.0.2 (promote_secondaries=1 keeps 10.0.0.3): unbound tunnels of B reselect their source"
  cb=$(count_log "$B_LOG" "tunnel t1 (tunnel_id=2): connected to"); lb=$(wc -l < "$B_LOG")
  b ip addr del 10.0.0.2/24 dev vB
  wait_log "$B_LOG" "tunnel t1 (tunnel_id=2): connected to 10.0.0.1 from 10.0.0.3" 4
  say "  B log:"; tail_new "$B_LOG" $lb | sed 's/^/   B| /' | tee -a "$R"
  pingcheck a l2tp0 192.168.0.2
  step "B side: add 10.0.0.2 back (unbound: no reconnect expected; A's frames to .2 land again, K15)"
  cb=$(count_log "$B_LOG" "tunnel t1 (tunnel_id=2): connected to")
  b ip addr add 10.0.0.2/24 dev vB; sleep 2
  nolog "$B_LOG" "tunnel t1 (tunnel_id=2): connected to" $cb; pingcheck a l2tp0 192.168.0.2
  dump_state; finish;;
# ---------------------------------------------------------------- S4
s4) step "S4: peer unreachable at start, route appears later; route removed (T16, E13, E9, H6, H8)"
  mk_veth bindA; a_dev_up bindA; start_b
  a_cfg bindA 10.0.0.2 v4 t2 > "$OUT/a.toml"; [ $IMPL = old ] && { printf '[tunnels.t2]\ntunnel_id = 11\npeer_tunnel_id = 12\nremote_addr = "fd00:9::2"\nip_version = "v6"\n[sessions.s2]\ntunnel_name = "t2"\nsession_id = 201\npeer_session_id = 202\ninterface_name = "l2tp1"\n' > "$OUT/a.toml"; }
  start_a "$OUT/a.toml"
  if [ $IMPL = new ]; then wait_log "$A_LOG" "$(a_pat pending t2 11)" 10; wait_log "$A_LOG" "session s2 (tunnel_id=11, session_id=201)" 5; else sleep 4; say "  A log:"; head -20 "$A_LOG" | sed 's/^/   A| /' | tee -a "$R"; fi
  say "  l2tp1 in a: $(a ip -o link show dev l2tp1 2>&1 | cut -c1-60)"
  say "  pid file (readiness) exists: $([ -f "$OUT/a.pid" ] && echo yes || echo no)"
  l0=$(wc -l < "$A_LOG")
  step "add route fd00:9::2/128 dev bindA in a"
  a ip -6 route add fd00:9::2/128 dev bindA
  t1=$(date +%s)
  if [ $IMPL = new ]; then wait_log "$A_LOG" "$(a_pat connected t2 11)" 6 && say "  connected within $(( $(date +%s) - t1 ))s of the route"; else wait_log "$A_LOG" "initial configuration applied" 8 && say "  applied within $(( $(date +%s) - t1 ))s of the route"; fi
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  inner_all; sleep 1; pingcheck a l2tp1 192.168.1.2
  l0=$(wc -l < "$A_LOG"); c=$(count_log "$A_LOG" "$(a_pat connected t2 11)")
  step "remove the route again: no event is subscribed; socket stays connected; frames are dropped by routing"
  a ip -6 route del fd00:9::2/128 dev bindA; sleep 2
  say "  A log lines since route removal: $(tail_new "$A_LOG" $l0 | wc -l)"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  pingcheck a l2tp1 192.168.1.2
  step "re-add the route: connectivity returns without daemon action"
  a ip -6 route add fd00:9::2/128 dev bindA; sleep 1; pingcheck a l2tp1 192.168.1.2
  nolog "$A_LOG" "$(a_pat connected t2 11)" $c
  dump_state; finish;;
# ---------------------------------------------------------------- S5
s5|s5b) step "$SC: FQDN peer; answer changes; answer disappears (T14, T15, E10, E11, V6, G5)"
  mk_veth bindA; a_dev_up bindA; start_b
  a_cfg bindA 10.0.0.2 v4 t3 > "$OUT/a.toml"
  # s5b: a sibling with a peer that stays pending keeps the one-second tick alive
  [ $SC = s5b ] && a_cfg bindA 10.0.0.2 v4 t3 t2 > "$OUT/a.toml"
  [ $IMPL = old ] && printf '[tunnels.t3]\ntunnel_id = 21\npeer_tunnel_id = 22\nremote_addr = "peerb.test"\nip_version = "v4"\n[sessions.s3]\ntunnel_name = "t3"\nsession_id = 301\npeer_session_id = 302\ninterface_name = "l2tp2"\n' > "$OUT/a.toml"
  start_a "$OUT/a.toml"
  wait_log "$A_LOG" "$(a_pat connected t3 21)" 10; inner_all; pingcheck a l2tp2 192.168.2.2
  dump_state
  step "change /etc/hosts: peerb.test -> 10.0.0.3"
  # /etc/hosts is a Docker bind mount: rewrite in place (sed -i renames and silently leaves it unchanged)
  { grep -v peerb.test /etc/hosts; echo '10.0.0.3 peerb.test'; } > /tmp/h && cat /tmp/h > /etc/hosts; l0=$(wc -l < "$A_LOG")
  say "  libc view now: $(a ping -c 1 -W 1 peerb.test 2>&1 | head -1)"
  t1=$(date +%s)
  if [ $IMPL = new ]; then wait_log "$A_LOG" "tunnel t3 (tunnel_id=21): connected to 10.0.0.3" 70 && say "  new answer applied after $(( $(date +%s) - t1 ))s"; else wait_log "$A_LOG" "dns change applied tunnel_id=21 remote_addr=10.0.0.3" 100 && say "  applied after $(( $(date +%s) - t1 ))s"; fi
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  dump_state; pingcheck a l2tp2 192.168.2.2
  step "remove the /etc/hosts entry (lookup fails): tunnel must stay connected"
  grep -v peerb.test /etc/hosts > /tmp/h; cat /tmp/h > /etc/hosts; say "  libc view now: $(a ping -c 1 -W 1 peerb.test 2>&1 | head -1)"
  l0=$(wc -l < "$A_LOG"); c=$(count_log "$A_LOG" "$(a_pat disconnected t3 21)")
  sleep 40; say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  nolog "$A_LOG" "$(a_pat disconnected t3 21)" $c; pingcheck a l2tp2 192.168.2.2; dump_state
  finish;;
# ---------------------------------------------------------------- S6
s6) step "S6: VRF bind device: absent, created, member joins/leaves, replaced; link-local peer with zone (T10-T13, T27, E4, H7, H13)"
  mk_veth bindA; a_dev_up bindA; start_b
  a_cfg bindA 10.0.0.2 v4 t4 t5 > "$OUT/a.toml"; [ $IMPL = old ] && printf '[tunnels.t4]\ntunnel_id = 31\npeer_tunnel_id = 32\nremote_addr = "10.0.0.2"\nip_version = "v4"\nbind_interface = "vrfA"\n[sessions.s4]\ntunnel_name = "t4"\nsession_id = 401\npeer_session_id = 402\ninterface_name = "l2tp3"\n' > "$OUT/a.toml"
  start_a "$OUT/a.toml"
  if [ $IMPL = new ]; then wait_log "$A_LOG" "$(a_pat connected t1 1)" 10; wait_log "$A_LOG" "$(a_pat absent t4 31)" 5; wait_log "$A_LOG" "$(a_pat absent t5 41)" 5; else sleep 3; say "  A log:"; head -20 "$A_LOG" | sed 's/^/   A| /' | tee -a "$R"; fi
  inner_all; l0=$(wc -l < "$A_LOG")
  step "create vrfA (table 100), no members yet"
  a ip link add name vrfA type vrf table 100; a ip link set vrfA up; sleep 2
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"; dump_state
  pingcheck a l2tp3 192.168.3.2
  l0=$(wc -l < "$A_LOG"); c1=$(count_log "$A_LOG" "$(a_pat connected t1 1)")
  step "enslave bindA to vrfA (member joins; t1's device changes L3 domain)"
  a ip link set bindA master vrfA
  # the VRF driver cycles the member down/up and addrconf drops manual link-local addresses even with keep_addr_on_down (addr_is_local)
  a ip -6 addr add fe80::1/64 dev bindA nodad 2>/dev/null
  wait_log "$A_LOG" "$(a_pat connected t4 31)" 6
  [ $IMPL = new ] && { wait_log "$A_LOG" "$(a_pat connected t5 41)" 6; wait_log "$A_LOG" "$(a_pat connected t1 1)" 4 $((c1+1)); }
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  inner_all; sleep 1; pingcheck a l2tp0 192.168.0.2; pingcheck a l2tp3 192.168.3.2; pingcheck a l2tp4 192.168.4.2
  dump_state
  l0=$(wc -l < "$A_LOG")
  step "add 'unreachable default' routes to the VRF table (the usual VRF setup): no event, nothing expected"
  a ip route add unreachable default vrf vrfA; a ip -6 route add unreachable default vrf vrfA; sleep 2
  say "  A log lines since: $(tail_new "$A_LOG" $l0 | wc -l)"; pingcheck a l2tp3 192.168.3.2
  l0=$(wc -l < "$A_LOG"); c1=$(count_log "$A_LOG" "$(a_pat connected t1 1)")
  step "bindA leaves the VRF (nomaster): VRF has no source any more; zone no longer a member"
  a ip link set bindA nomaster; sleep 3
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  pingcheck a l2tp0 192.168.0.2; pingcheck a l2tp3 192.168.3.2; pingcheck a l2tp4 192.168.4.2
  l0=$(wc -l < "$A_LOG")
  step "bindA re-joins the VRF"
  a ip link set bindA master vrfA; a ip -6 addr add fe80::1/64 dev bindA nodad 2>/dev/null; sleep 3
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  pingcheck a l2tp0 192.168.0.2; pingcheck a l2tp3 192.168.3.2; pingcheck a l2tp4 192.168.4.2
  l0=$(wc -l < "$A_LOG")
  step "delete vrfA (bind device disappears; bindA loses its controller)"
  a ip link del vrfA; sleep 3
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  pingcheck a l2tp0 192.168.0.2; pingcheck a l2tp3 192.168.3.2
  l0=$(wc -l < "$A_LOG")
  step "re-create vrfA under the same name (new index) and enslave bindA again (H13 replacement)"
  a ip link add name vrfA type vrf table 100; a ip link set vrfA up; a ip link set bindA master vrfA; a ip -6 addr add fe80::1/64 dev bindA nodad 2>/dev/null; sleep 3
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  pingcheck a l2tp0 192.168.0.2; pingcheck a l2tp3 192.168.3.2; pingcheck a l2tp4 192.168.4.2
  dump_state; finish;;
# ---------------------------------------------------------------- S7
s7) step "S7: reload changing bind_interface, remote_addr and family in place (T22, G3, G18)"
  mk_veth bindA; a_dev_up bindA; start_b
  a_cfg bindA 10.0.0.2 v4 > "$OUT/a.toml"; start_a "$OUT/a.toml"
  wait_log "$A_LOG" "$(a_pat connected t1 1)" 10; inner_all; pingcheck a l2tp0 192.168.0.2
  ix0=$(ifindex a l2tp0); say "  l2tp0 ifindex: $ix0"; l0=$(wc -l < "$A_LOG")
  step "reload: bind_interface -> bindX (absent)"
  a_cfg bindX 10.0.0.2 v4 > "$OUT/r1.toml"; reload_a "$OUT/r1.toml"; sleep 3
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  say "  l2tp0 ifindex: $(ifindex a l2tp0) (was $ix0)"; pingcheck a l2tp0 192.168.0.2
  l0=$(wc -l < "$A_LOG")
  step "reload: bind_interface -> bindA, remote_addr -> 10.0.0.3"
  a_cfg bindA 10.0.0.3 v4 > "$OUT/r2.toml"; reload_a "$OUT/r2.toml"; sleep 3
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  say "  l2tp0 ifindex: $(ifindex a l2tp0) (was $ix0)"; inner a l2tp0 0 1; pingcheck a l2tp0 192.168.0.2; dump_state
  l0=$(wc -l < "$A_LOG")
  step "reload: remote_addr -> fd00::2, ip_version v6 (family change on the same socket)"
  a_cfg bindA fd00::2 v6 > "$OUT/r3.toml"; reload_a "$OUT/r3.toml"; sleep 3
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  say "  l2tp0 ifindex: $(ifindex a l2tp0) (was $ix0)"; inner a l2tp0 0 1; pingcheck a l2tp0 192.168.0.2; dump_state
  l0=$(wc -l < "$A_LOG")
  step "reload: unchanged configuration (nothing expected)"
  reload_a "$OUT/r3.toml"; sleep 2
  say "  A log lines since: $(tail_new "$A_LOG" $l0 | wc -l)"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"
  say "  l2tp0 ifindex: $(ifindex a l2tp0) (was $ix0)"
  finish;;
# ---------------------------------------------------------------- S8
s8) step "S8: bindv6only=1 host with fix off: AF_INET sockets; address events and reloads on them (T26, T4, H18)"
  mk_veth bindA; a_dev_up bindA; start_b
  a sh -c 'echo 1 > /proc/sys/net/ipv6/bindv6only'; say "  bindv6only in a: $(a cat /proc/sys/net/ipv6/bindv6only)"
  a_cfg bindA 10.0.0.2 v4 t2 nofix > "$OUT/a.toml"; start_a "$OUT/a.toml"
  wait_log "$A_LOG" "$(a_pat connected t1 1)" 10; wait_log "$A_LOG" "v6only\|IPv6-only\|bindv6only" 3
  inner_all; pingcheck a l2tp0 192.168.0.2; dump_state
  c=$(count_log "$A_LOG" "$(a_pat connected t1 1)"); l0=$(wc -l < "$A_LOG")
  step "add/remove an IPv4 address on bindA -> two reconnects on the AF_INET socket"
  a ip addr add 10.0.0.11/24 dev bindA; sleep 1; a ip addr del 10.0.0.11/24 dev bindA
  wait_log "$A_LOG" "$(a_pat connected t1 1)" 4 $((c+2)); say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"; pingcheck a l2tp0 192.168.0.2
  l0=$(wc -l < "$A_LOG")
  step "rename bindA away and back"
  a ip link set bindA name tmp0; sleep 1; a ip link set tmp0 name bindA; sleep 2
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"; pingcheck a l2tp0 192.168.0.2
  l0=$(wc -l < "$A_LOG")
  step "reload: t1 remote -> fd00::2 v6 on an AF_INET socket (T4: stays disconnected, reported once)"
  a_cfg bindA fd00::2 v6 t2 nofix > "$OUT/r1.toml"; reload_a "$OUT/r1.toml"; sleep 3
  say "  A log:"; tail_new "$A_LOG" $l0 | sed 's/^/   A| /' | tee -a "$R"; pingcheck a l2tp0 192.168.0.2
  step "t2 (v6 peer, IPv6-only AF_INET6 socket): add route -> connects"
  l0=$(wc -l < "$A_LOG"); a ip -6 route add fd00:9::2/128 dev bindA; wait_log "$A_LOG" "$(a_pat connected t2 11)" 6
  inner_all; sleep 1; pingcheck a l2tp1 192.168.1.2
  dump_state; finish;;
*) say "unknown scenario $SC"; exit 2;;
esac
