#!/bin/sh
# Unbound tunnel with a zoned link-local peer whose first connect fails, then the zone device is
# replaced (new index) before a connect succeeds. Variant "replace" deletes and re-creates the veth;
# variant "keep" only brings the same device up (control).
set -u
V=$1; OUT=/out/ll2-$V; mkdir -p "$OUT"; BIN=/bin-new
a() { nsenter --net=/run/netns/a "$@"; }; b() { nsenter --net=/run/netns/b "$@"; }
mk() { ip link add name bindA type veth peer name vB; ip link set bindA netns a; ip link set vB netns b; }
up() { a ip link set bindA up; a ip -6 addr add fe80::1/64 dev bindA nodad; b ip link set vB up; b ip -6 addr add fe80::2/64 dev vB nodad; }
ip netns add a; ip netns add b; a ip link set lo up; b ip link set lo up
mk   # vB exists but is down: no link-local source -> the connect fails
printf '[tunnels.t5]\ntunnel_id = 42\npeer_tunnel_id = 41\nremote_addr = "fe80::1%%vB"\nip_version = "v6"\n[sessions.s5]\ntunnel_name = "t5"\nsession_id = 502\npeer_session_id = 501\ninterface_name = "l2tp4"\n' > "$OUT/b.toml"
nsenter --net=/run/netns/b $BIN --foreground --verbose --config "$OUT/b.toml" --config-dir /x --pid-file "$OUT/b.pid" 2>"$OUT/b.log" &
sleep 3
echo "--- vB index before: $(b ip -o link show dev vB | cut -d: -f1)"
echo "--- log after start:"; grep -v DEBUG "$OUT/b.log" | grep t5
if [ "$V" = replace ]; then b ip link del vB; sleep 1; mk; fi
up
echo "--- vB index now: $(b ip -o link show dev vB | cut -d: -f1)"
sleep 6
echo "--- log tail (non-debug):"; grep -v DEBUG "$OUT/b.log" | grep t5 | tail -5
echo "--- last debug lines:"; grep DEBUG "$OUT/b.log" | tail -3
echo "--- kernel record:"; b ip l2tp show tunnel
