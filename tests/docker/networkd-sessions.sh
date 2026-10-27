#!/bin/sh
# Real networkd/udev integration under an intentionally delayed daemon.
set -eu
NETWORKD=${NETWORKD:-/usr/lib/systemd/systemd-networkd}
UDEVD=${UDEVD:-/usr/lib/systemd/systemd-udevd}
CASES=${CASES:-"name type mac"}
expected_mac=02:00:5e:00:53:01
cp /artifacts/current /opt/current
chmod 755 /opt/current
sh /opt/networkd-sysfs.sh
mkdir -p /run/udev /run/systemd /etc/systemd/network
ip link set lo up
networkd_pid=
monitor_pid=
trace_pid=
paused_pid=
SYSTEMD_LOG_LEVEL=debug "$UDEVD" > /tmp/udev.log 2>&1 &
udev_pid=$!

cleanup() {
    if [ -n "$paused_pid" ]; then
        kill -CONT "$paused_pid" 2>/dev/null || :
        kill -TERM "$paused_pid" 2>/dev/null || :
    fi
    if [ -f /run/test.pid ]; then
        kill -CONT "$(cat /run/test.pid)" 2>/dev/null || :
        kill -TERM "$(cat /run/test.pid)" 2>/dev/null || :
    fi
    for pid in "$networkd_pid" "$monitor_pid" "$trace_pid" "$udev_pid"; do
        if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || :; fi
    done
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

fail() {
    echo "$*" >&2
    cat /tmp/daemon.log /tmp/networkd.log /tmp/link-events.log >&2
    ip -o address show >&2
    ip -4 route show >&2
    ip -6 route show >&2
    exit 1
}

configured() {
    ip -o address show dev "$1" | grep -Fq 'inet 198.18.0.1/30' &&
        ip -o address show dev "$1" | grep -Fq 'inet6 2001:db8:1::1/64' &&
        ip -4 route show 203.0.113.0/24 | grep -Fq "via 198.18.0.2 dev $1" &&
        ip -6 route show 2001:db8:99::/64 | grep -Fq "via 2001:db8:1::2 dev $1"
}

attempts=0
until udevadm control --ping 2>/dev/null; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 50 ] || { cat /tmp/udev.log >&2; exit 1; }
    sleep 0.1
done

for test_case in $CASES; do
    printf 'CASE networkd session %s\n' "$test_case"
    published_mac=$expected_mac
    : > /tmp/daemon.log
    : > /tmp/networkd.log
    : > /tmp/link-events.log
    case "$test_case" in
        name) match='Name=pseudowire0' ;;
        type) match='Type=l2tpeth' ;;
        mac) match="MACAddress=$expected_mac" ;;
        *) fail "unknown CASES entry: $test_case" ;;
    esac
    printf '[Match]\n%s\n' "$match" > /etc/systemd/network/10-session.network
    cat >> /etc/systemd/network/10-session.network <<'NETWORK'
[Network]
LinkLocalAddressing=no
[Address]
Address=198.18.0.1/30
DuplicateAddressDetection=none
[Address]
Address=2001:db8:1::1/64
DuplicateAddressDetection=none
[Route]
Destination=203.0.113.0/24
Gateway=198.18.0.2
[Route]
Destination=2001:db8:99::/64
Gateway=2001:db8:1::2
NETWORK
    cat > /etc/rs-l2tpd.toml <<'CONFIG'
[tunnels.uplink]
tunnel_id = 1001
peer_tunnel_id = 2001
ip_version = "V6"
remote_addr = "::1"
[sessions.lan]
tunnel_name = "uplink"
session_id = 1001
peer_session_id = 2001
interface_name = "pseudowire0"
interface_hwaddr = "02:00:5e:00:53:01"
CONFIG
    SYSTEMD_LOG_LEVEL=debug "$NETWORKD" > /tmp/networkd.log 2>&1 &
    networkd_pid=$!
    ip -o monitor link address route > /tmp/link-events.log &
    monitor_pid=$!
    sleep 0.3
    strace -ff -o /tmp/session-trace -e trace=recvmsg,recvfrom \
        -e inject=recvmsg:delay_enter=100ms -e inject=recvfrom:delay_enter=100ms \
        /opt/current --pidfile /run/test.pid > /tmp/daemon.log 2>&1 &
    trace_pid=$!
    if [ "$test_case" != name ]; then
        # Deterministically exercise a legitimate scheduling pause after
        # creation, so networkd finishes managing the unpublished link.
        staged_name=
        attempts=0
        until [ -n "$staged_name" ] && [ -n "$paused_pid" ]; do
            for device in /sys/class/net/*; do
                candidate=${device##*/}
                if [ "$candidate" != pseudowire0 ] &&
                    grep -Fxq 'DEVTYPE=l2tpeth' "$device/uevent"; then
                    if [ "$test_case" = mac ] && [ "$(cat "$device/address")" != "$expected_mac" ]; then
                        continue
                    fi
                    staged_name=$candidate
                    break
                fi
            done
            # The readiness PID file is intentionally not published yet.
            # Identify the double-forked child in this isolated PID namespace.
            for process in /proc/[0-9]*; do
                if [ "$(readlink "$process/exe" 2>/dev/null || :)" = /opt/current ] &&
                    [ "$(awk '/^PPid:/ { print $2 }' "$process/status" 2>/dev/null)" = 1 ]; then
                    paused_pid=${process##*/}
                    break
                fi
            done
            attempts=$((attempts + 1))
            [ "$attempts" -lt 1000 ] || fail 'no staged session appeared before publication'
            sleep 0.01
        done
        kill -STOP "$paused_pid"
        staged_index=$(cat "/sys/class/net/$staged_name/ifindex")
        if [ "$test_case" = type ]; then
            published_mac=$(cat "/sys/class/net/$staged_name/address")
        fi
        if [ "$test_case" = type ] &&
            ip -o link show dev "$staged_name" | grep -Fq "link/ether $expected_mac"; then
            fail 'scheduling pause occurred after MAC preparation'
        fi
        attempts=0
        until configured "$staged_name"; do
            attempts=$((attempts + 1))
            [ "$attempts" -lt 100 ] || fail 'networkd did not configure the staged interface'
            sleep 0.1
        done
        kill -CONT "$paused_pid"
        paused_pid=
    fi
    attempts=0
    until grep -Fq 'initial configuration applied' /tmp/daemon.log; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 400 ] || fail 'daemon did not become ready'
        sleep 0.1
    done
    daemon_pid=$(cat /run/test.pid)
    session_index=$(ip -o link show dev pseudowire0 | cut -d : -f 1)
    if [ "$test_case" != name ]; then
        [ "$session_index" = "$staged_index" ] || fail 'the staged session was recreated during preparation'
    fi
    attempts=0
    until configured pseudowire0; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 150 ] || fail 'networkd addresses or routes did not converge'
        sleep 0.1
    done
    ip -o link show dev pseudowire0 | grep -Fq "link/ether $published_mac" || fail 'unexpected MAC after publication'
    grep -F ' pseudowire0:' /tmp/link-events.log > /tmp/published-links || fail 'no final-name publication was observed'
    if grep -vF "link/ether $published_mac" /tmp/published-links >/dev/null; then
        fail 'publication changed the expected MAC'
    fi
    grep -Fxq 'NETWORK_FILE=/etc/systemd/network/10-session.network' "/run/systemd/netif/links/$session_index" ||
        fail 'networkd did not manage the session interface'
    if [ "$test_case" != name ]; then
        staged_name=$(awk -v link_index="$session_index:" '
            $1 == link_index && $2 != "pseudowire0:" && /link\/ether/ {
                sub(/:$/, "", $2); print $2; exit
            }
        ' /tmp/link-events.log)
        [ -n "$staged_name" ] || fail 'no staged interface was observed'
        grep -Fq "$staged_name: Configuring with /etc/systemd/network/10-session.network." /tmp/networkd.log ||
            fail 'the non-name rule did not match the staged interface'
        # Require real management before preparation, not just a match after
        # publication. Both address families and static routes must have
        # existed while the staging name still had its original MAC.
    fi
    if [ "$test_case" = type ]; then
        awk -v name="$staged_name" -v mac="$expected_mac" '
            index($0, "link/ether " mac) { prepared = 1 }
            !prepared && index($0, name) {
                if (/link\/ether/ && /<[^>]*UP/) up = 1
                if (/inet 198\.18\.0\.1\/30/) v4 = 1
                if (/inet6 2001:db8:1::1\/64/) v6 = 1
                if (/203\.0\.113\.0\/24 via 198\.18\.0\.2/) r4 = 1
                if (/2001:db8:99::\/64 via 2001:db8:1::2/) r6 = 1
            }
            END { exit !(up && v4 && v6 && r4 && r6) }
        ' /tmp/link-events.log || fail 'staged link was not fully configured before MAC preparation'
        awk -v link_index="$session_index:" '
            $1 == link_index && /link\/ether/ {
                if (/[<,]UP[,>]/) active = 1
                else if (active) exit 1
            }
        ' /tmp/link-events.log || fail 'daemon lowered an externally activated session'
    elif [ "$test_case" = mac ]; then
        awk -v name="$staged_name" -v mac="$expected_mac" '
            / pseudowire0:/ && /link\/ether/ { published = 1 }
            !published && index($0, name) {
                if (index($0, "link/ether " mac) && /<[^>]*UP/) up = 1
                if (/inet 198\.18\.0\.1\/30/) v4 = 1
                if (/inet6 2001:db8:1::1\/64/) v6 = 1
                if (/203\.0\.113\.0\/24 via 198\.18\.0\.2/) r4 = 1
                if (/2001:db8:99::\/64 via 2001:db8:1::2/) r6 = 1
            }
            END { exit !(up && v4 && v6 && r4 && r6) }
        ' /tmp/link-events.log || fail 'MAC match did not configure the staged link before publication'
    fi
    [ "$(cat /run/test.pid)" = "$daemon_pid" ] || fail 'daemon restarted'
    ip l2tp show session tunnel_id 1001 session_id 1001 |
        grep -Fq 'Peer session 2001, tunnel 2001' || fail 'session IDs changed'
    kill -TERM "$daemon_pid"
    attempts=0
    while [ -e /run/test.pid ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 100 ] || fail 'daemon shutdown did not complete'
        sleep 0.1
    done
    wait "$trace_pid"
    trace_pid=
    kill -TERM "$networkd_pid" "$monitor_pid"
    wait "$networkd_pid"
    wait "$monitor_pid" 2>/dev/null || :
    networkd_pid=
    monitor_pid=
    [ -z "$(ip l2tp show tunnel)" ] || fail 'tunnel survived shutdown'
    if ip link show pseudowire0 >/dev/null 2>&1; then fail 'session survived shutdown'; fi
    printf 'PASS networkd session %s\n' "$test_case"
done
echo 'PASS all requested networkd session cases'
