#!/bin/sh
# Link notifications lost while a session is still being prepared, and lost
# again once it is established. Readiness must still be reached, and later
# re-creation and removal must still work through the kernel's own record.
# Runs in the networkd test image (strace is needed); NET_ADMIN, NET_RAW and
# SYS_PTRACE are required, with the AppArmor override for ptrace.
set -eu
cp /artifacts/current /opt/current
chmod 755 /opt/current
NOISE_LINKS=${NOISE_LINKS:-50000}
daemon_pid=
fail() {
    echo "$*" >&2
    cat /tmp/daemon.log >&2
    ip -o link show | grep -v noise0 >&2 || :
    ip l2tp show session >&2 || :
    exit 1
}
cleanup() {
    if [ -n "$daemon_pid" ]; then
        kill -CONT "$daemon_pid" 2>/dev/null || :
        kill -TERM "$daemon_pid" 2>/dev/null || :
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
write_config() {
    cat > /etc/rs-l2tpd.toml <<CONFIG
[tunnels.t]
tunnel_id = 10
remote_addr = "::1"
[sessions.s]
tunnel_name = "t"
session_id = 100
interface_name = "pw0"
interface_hwaddr = "02:00:5e:00:53:01"
$1
CONFIG
    if [ "$2" = 1 ]; then
        cat >> /etc/rs-l2tpd.toml <<'CONFIG'
[sessions.s2]
tunnel_name = "t"
session_id = 101
interface_name = "pw1"
CONFIG
    fi
}
flood() {
    awk -v count="$NOISE_LINKS" 'BEGIN { for (i = 1; i <= count; i++) printf "link set dev noise0 mtu %d\n", 1400 + i % 2 }' > /tmp/flood
    ip -batch /tmp/flood
}
pause_daemon() {
    kill -STOP "$daemon_pid"
    # A traced process reports a tracing stop (t) rather than a stop (T).
    attempts=0
    until awk '$1 == "State:" { exit !($2 == "T" || $2 == "t") }' "/proc/$daemon_pid/status"; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 50 ] || fail 'daemon did not stop'
        sleep 0.1
    done
}
reload_config() {
    before=$(grep -Ec 'configuration reload completed|failed to apply reloaded configuration' /tmp/daemon.log || :)
    kill -HUP "$daemon_pid"
    attempts=0
    while [ "$(grep -Ec 'configuration reload completed|failed to apply reloaded configuration' /tmp/daemon.log || :)" -le "$before" ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 300 ] || fail 'reload was not processed'
        sleep 0.1
    done
    last_reload=$(grep -E 'configuration reload completed|failed to apply reloaded configuration' /tmp/daemon.log | tail -n 1)
}

ip link set lo up
ip link add noise0 type dummy
ip link set noise0 up
write_config '' 1

echo 'CASE notification loss while a session is staged'
# Netlink receives are slowed down so that the staged device can be caught
# before its MAC is applied; the daemon is then paused there and the link
# monitors overflowed.
strace -ff -o /tmp/trace -e trace=recvmsg,recvfrom \
    -e inject=recvmsg:delay_enter=100ms -e inject=recvfrom:delay_enter=100ms \
    /opt/current --pidfile /run/test.pid > /tmp/daemon.log 2>&1 &
staged=
attempts=0
until [ -n "$staged" ] && [ -n "$daemon_pid" ]; do
    for device in /sys/class/net/*; do
        name=${device##*/}
        case "$name" in rsl2tp-t*) staged=$name ;; esac
    done
    for process in /proc/[0-9]*; do
        if [ "$(readlink "$process/exe" 2>/dev/null || :)" = /opt/current ] &&
            [ "$(awk '/^PPid:/ { print $2 }' "$process/status" 2>/dev/null)" = 1 ]; then
            daemon_pid=${process##*/}
        fi
    done
    attempts=$((attempts + 1))
    [ "$attempts" -lt 3000 ] || fail 'no staged session appeared'
    sleep 0.01
done
pause_daemon
[ "$(cat "/sys/class/net/$staged/address")" != 02:00:5e:00:53:01 ] || fail 'paused after MAC preparation'
flood
kill -CONT "$daemon_pid"
attempts=0
until grep -q 'initial configuration applied' /tmp/daemon.log; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 600 ] || fail 'daemon did not become ready after the loss'
    sleep 0.1
done
grep -q 'netlink socket buffer full' /tmp/daemon.log || fail 'no overflow occurred; increase NOISE_LINKS'
# Either the device is identified again at its registration index by its
# temporary name, or the session is deleted through the kernel record and
# created again.
grep -q 're-creating incomplete session_id=100 in tunnel_id=10: link notifications were lost' /tmp/daemon.log ||
    grep -q "identified the interface created as $staged at index" /tmp/daemon.log ||
    fail 'the staged session was neither identified again nor re-created'
ip link show pw0 > /dev/null || fail 'pw0 is missing'
ip link show pw1 > /dev/null || fail 'pw1 is missing'
[ "$(cat /sys/class/net/pw0/address)" = 02:00:5e:00:53:01 ] || fail 'pw0 has the wrong MAC'
if ip -o link show | grep -q 'rsl2tp-t'; then fail 'a staged device was left behind'; fi
[ "$(ip l2tp show session | grep -c '^Session')" -eq 2 ] || fail 'two sessions expected'
echo 'PASS notification loss while a session is staged'

echo 'CASE notification loss with established sessions'
# The ready daemon loses notifications again: its sessions can no longer be
# proved by their devices, but the kernel still reports them under their
# creation-time names, which lets them be re-created and removed.
sleep 0.5
pw0_index=$(cat /sys/class/net/pw0/ifindex)
pause_daemon
flood
kill -CONT "$daemon_pid"
sleep 2
# A rename is refused, with the reload completing.
write_config '' 1
sed -i 's/interface_name = "pw0"/interface_name = "pw9"/' /etc/rs-l2tpd.toml
reload_config
[ "$(cat /sys/class/net/pw0/ifindex)" = "$pw0_index" ] || fail 'an unprovable device was renamed'
case "$last_reload" in
    *'configuration reload completed'*) ;;
    *) fail 'the reload must complete, not fail' ;;
esac
grep -q 'link notifications were lost; its interface' /tmp/daemon.log || fail 'the unmanageable device was not reported'
# A cookie change re-creates the session: deleted through the kernel record.
write_config 'cookie = "deadbeef"' 1
reload_config
attempts=0
until [ -e /sys/class/net/pw0 ] && [ "$(cat /sys/class/net/pw0/ifindex)" != "$pw0_index" ]; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 100 ] || fail 'the session was not re-created with its cookie'
    sleep 0.1
done
grep -q 'deleting session_id=100 in tunnel_id=10 although link notifications were lost' /tmp/daemon.log ||
    fail 'the deletion through the kernel record was not logged'
ip l2tp show session tunnel_id 10 session_id 100 | grep -Fq 'cookie' || fail 'no cookie on the new session'
# Removing the other session deletes it as well.
write_config 'cookie = "deadbeef"' 0
reload_config
attempts=0
while ip link show pw1 > /dev/null 2>&1; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 100 ] || fail 'the removed session survived'
    sleep 0.1
done
echo 'PASS notification loss with established sessions'

kill -TERM "$daemon_pid"
attempts=0
while [ -e /run/test.pid ] || [ -n "$(ip l2tp show tunnel)" ]; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 100 ] || fail 'shutdown incomplete'
    sleep 0.1
done
daemon_pid=
if ip link show pw0 > /dev/null 2>&1; then fail 'pw0 survived shutdown'; fi
echo 'PASS all staging-loss cases'
