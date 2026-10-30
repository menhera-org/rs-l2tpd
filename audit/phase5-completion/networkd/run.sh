#!/bin/sh
# run.sh container|native -- runs inside a disposable `docker run --rm --network none --privileged` container.
# container: /sys remounted ro, no udevd (udev_available() false). native: /sys rw, udevd running.
MODE=${1:-container}
LOG=/tmp/networkd.log
ULOG=/tmp/udevd.log
UMON=/tmp/umon.log
say() { printf '\n### %s\n' "$*"; }

say "systemd: $(systemctl --version | head -1) | mode=$MODE | kernel=$(uname -r)"
[ -s /etc/machine-id ] || systemd-machine-id-setup >/dev/null 2>&1 || true
echo "machine-id: $(cat /etc/machine-id)"
mkdir -p /etc/systemd/network /run/systemd /run/udev /run/dbus
cat >/etc/systemd/network/l2tp0.network <<'EOF'
[Match]
Name=l2tp0

[Network]
Address=192.0.2.1/24
EOF
NETWORKD=/lib/systemd/systemd-networkd; [ -x "$NETWORKD" ] || NETWORKD=/usr/lib/systemd/systemd-networkd
UDEVD=/lib/systemd/systemd-udevd; [ -x "$UDEVD" ] || UDEVD=/usr/lib/systemd/systemd-udevd
if command -v dbus-daemon >/dev/null 2>&1; then dbus-daemon --system --fork >/dev/null 2>&1 && echo "dbus started"; fi

if [ "$MODE" = container ]; then
  grep -q ' /sys sysfs ro' /proc/mounts || mount -o remount,ro,nosuid,nodev,noexec /sys || echo "remount failed"
  echo "/sys mount: $(grep ' /sys ' /proc/mounts | tail -1)"
else
  SYSTEMD_LOG_LEVEL=debug SYSTEMD_LOG_TARGET=console "$UDEVD" >"$ULOG" 2>&1 &
  i=0; until [ -S /run/udev/control ] || [ $i -ge 20 ]; do i=$((i+1)); sleep 1; done
  udevadm monitor --udev --property >"$UMON" 2>&1 &
  udevadm settle
  echo "udevd: $(pgrep -a udevd || echo NOT RUNNING)"
fi

SYSTEMD_LOG_LEVEL=debug "$NETWORKD" >"$LOG" 2>&1 &
i=0; until grep -q 'Enumeration completed' "$LOG" || [ $i -ge 30 ]; do i=$((i+1)); sleep 1; done
if grep -q 'Enumeration completed' "$LOG"; then echo "networkd enumerated"; else echo "networkd did NOT enumerate; log:"; cat "$LOG"; fi
grep -iE 'udev|bus' "$LOG" | head -5

LOGMARK=0
mark() { LOGMARK=$(wc -l <"$LOG"); }
since() { tail -n +$((LOGMARK+1)) "$LOG" | grep -E 'rsl2tp|l2tp0' | grep -vE 'rtnl: |link_check_ready|Setting .*proc/sys|Requested to|message type=|LLDP|Gained|Flags change' | head -30; }
settle() { [ "$MODE" = native ] && udevadm settle; :; }
macinfo() { echo "mac=$(cat /sys/class/net/l2tp0/address) addr_assign_type=$(cat /sys/class/net/l2tp0/addr_assign_type)"; }
check_addr() {
  i=0; while [ $i -lt 6 ]; do
    if ip -br addr show l2tp0 2>/dev/null | grep -q 192.0.2.1; then echo "RESULT: address APPLIED after ${i}s"; return 0; fi
    sleep 1; i=$((i+1)); done
  echo "RESULT: address NOT applied within 5s: $(ip -br addr show l2tp0 2>&1)"; return 1
}
udevinfo() { [ "$MODE" = native ] || return 0
  udevadm info /sys/class/net/l2tp0 | grep -E 'ID_NET|ID_PATH|INTERFACE' | sed 's/^/  udevadm: /'
  tail -n +$((ULOGMARK+1)) "$ULOG" | grep -E 'rsl2tp|l2tp0' | grep -iE 'mac|address|link|policy|rename|move|add' | head -20 | sed 's/^/  udevd: /'; }
umark() { ULOGMARK=0; [ "$MODE" = native ] && ULOGMARK=$(wc -l <"$ULOG"); :; }
cleanup() { ip link del l2tp0 2>/dev/null; ip link del "$1" 2>/dev/null; settle; sleep 1; }

mkdev() { # name type
  if [ "$2" = l2tpeth ]; then
    ip l2tp add tunnel tunnel_id 1 peer_tunnel_id 1 encap udp local 127.0.0.1 remote 127.0.0.2 udp_sport 1701 udp_dport 1701 >/dev/null 2>&1
    ip l2tp add session tunnel_id 1 session_id 1 peer_session_id 1 name "$1"
  else
    ip link add name "$1" type "$2"
  fi
}
deldev() { ip link del l2tp0 2>/dev/null; ip link del "$1" 2>/dev/null; [ "$2" = l2tpeth ] && ip l2tp del tunnel tunnel_id 1 2>/dev/null; settle; sleep 1; }

test_rename() { # type
  say "TEST A ($2$1): create rsl2tp-tabc123, sleep 1, rename to l2tp0"
  mark; umark
  mkdev rsl2tp-tabc123 "$1" || { echo "create failed"; return; }
  sleep 1
  ip link set rsl2tp-tabc123 name l2tp0 || echo "rename failed"
  settle
  check_addr; macinfo; udevinfo
  echo "-- networkd log:"; since
  deldev rsl2tp-tabc123 "$1"
}
test_direct() { # type
  say "TEST B ($2$1): create l2tp0 directly"
  mark; umark
  mkdev l2tp0 "$1" || { echo "create failed"; return; }
  settle
  check_addr; macinfo; udevinfo
  echo "-- networkd log:"; since
  deldev l2tp0 "$1"
}

test_rename dummy
test_direct dummy
test_rename l2tpeth
test_direct l2tpeth

if [ "$MODE" = native ]; then
  say "H2: MAC after create rsl2tp-tNNNNNN, sleep 1, rename -> l2tp0 (x3, distinct temp names)"
  for n in 1 2 3; do
    ip link add name rsl2tp-t00000$n type dummy; sleep 1; ip link set rsl2tp-t00000$n name l2tp0; udevadm settle
    echo "run $n: $(macinfo)"; ip link del l2tp0; udevadm settle
  done
  say "H2: MAC after create rsl2tp-tabc123 (same temp name), sleep 1, rename -> l2tp0 (x2)"
  for n in 1 2; do
    ip link add name rsl2tp-tabc123 type dummy; sleep 1; ip link set rsl2tp-tabc123 name l2tp0; udevadm settle
    echo "run $n: $(macinfo)"; ip link del l2tp0; udevadm settle
  done
  say "H2: MAC after direct create l2tp0 (x3)"
  for n in 1 2 3; do
    ip link add name l2tp0 type dummy; udevadm settle
    echo "run $n: $(macinfo)"; ip link del l2tp0; udevadm settle
  done
  say "H2: MAC after create rsl2tp-tNNNNNN + immediate rename (race, x3)"
  for n in 1 2 3; do
    umark
    ip link add name rsl2tp-t10000$n type dummy && ip link set rsl2tp-t10000$n name l2tp0; udevadm settle
    echo "run $n: $(macinfo)"
    tail -n +$((ULOGMARK+1)) "$ULOG" | grep -E 'rsl2tp|l2tp0' | grep -iE 'mac|policy|address' | head -6 | sed 's/^/  udevd: /'
    ip link del l2tp0; udevadm settle
  done
  say "udev monitor events (ACTION/INTERFACE/ID_NET_LINK_FILE), whole run so far"
  grep -E '^(ACTION|INTERFACE|ID_NET_LINK_FILE|ID_NET_NAME|ID_NET_DRIVER)=' "$UMON" | paste -sd' ' | sed 's/ACTION=/\nACTION=/g' | head -60
fi

say "H3: adding .link file OriginalName=l2tp0 MACAddress=02:00:5e:00:53:01"
cat >/etc/systemd/network/10-l2tp0.link <<'EOF'
[Match]
OriginalName=l2tp0

[Link]
MACAddress=02:00:5e:00:53:01
EOF
if [ "$MODE" = native ]; then udevadm control --reload; fi
test_rename dummy H3-
test_direct dummy H3-
test_rename l2tpeth H3-
test_direct l2tpeth H3-

say "full networkd log line count: $(wc -l <"$LOG"); errors/warnings:"
grep -iE 'warn|error|fail' "$LOG" | grep -v 'Failed to connect to bus\|D-Bus\|dbus' | head -10
say DONE
