#!/bin/sh
# Preserve children owned by networkd or another network namespace.
set -eu
PUBLICATION_CONFLICT=${PUBLICATION_CONFLICT:-1}
cp /artifacts/current /opt/probed
chmod 755 /opt/probed
sh /opt/networkd-sysfs.sh
mkdir -p /run/udev /run/systemd /etc/systemd/network
ip link set lo up
daemon_pid=
guest=
fail() {
    echo "$*" >&2
    cat /tmp/daemon.log >&2
    ip -o address show >&2
    if [ -n "$guest" ]; then nsenter -t "$guest" -n ip -o address show >&2; fi
    exit 1
}
cleanup() {
    if [ -n "$daemon_pid" ]; then kill -CONT "$daemon_pid" 2>/dev/null || :; kill -TERM "$daemon_pid" 2>/dev/null || :; fi
    if [ -n "$guest" ]; then kill "$guest" 2>/dev/null || :; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
cat > /etc/systemd/network/10-parent.network <<'EOF'
[Match]
Type=l2tpeth
[Network]
LinkLocalAddressing=no
Address=198.18.0.1/30
VLAN=vlan-local
VLAN=vlan-guest
MACVLAN=macvlan-local
MACVLAN=macvlan-guest
EOF
for place in local guest; do
    vlan_id=10
    if [ "$place" = guest ]; then vlan_id=11; fi
    printf '[NetDev]\nName=vlan-%s\nKind=vlan\n[VLAN]\nId=%s\n' "$place" "$vlan_id" > "/etc/systemd/network/20-vlan-$place.netdev"
    printf '[NetDev]\nName=macvlan-%s\nKind=macvlan\n[MACVLAN]\nMode=bridge\n' "$place" > "/etc/systemd/network/20-macvlan-$place.netdev"
done
cat > /etc/systemd/network/30-child.network <<'EOF'
[Match]
Name=vlan-* macvlan-*
[Network]
LinkLocalAddressing=no
[Address]
Address=192.0.2.1/24
DuplicateAddressDetection=none
[Address]
Address=2001:db8:1::1/64
DuplicateAddressDetection=none
EOF
cat > /etc/rs-l2tpd.toml <<'EOF'
[tunnels.uplink]
tunnel_id=1001
peer_tunnel_id=2001
ip_version="V6"
remote_addr="::1"
[sessions.lan]
tunnel_name="uplink"
session_id=1001
peer_session_id=2001
interface_name="pseudowire0"
interface_hwaddr="02:00:5e:00:53:01"
EOF
SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-udevd >/tmp/udev.log 2>&1 &
n=0
until udevadm control --ping 2>/dev/null; do n=$((n+1)); [ "$n" -lt 50 ]; sleep 0.1; done
SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-networkd >/tmp/networkd.log 2>&1 &
ip -o monitor link address route >/tmp/events.log &
sleep 0.3
unshare -n sleep 150 &
guest=$!
strace -ff -o /tmp/trace -e trace=recvmsg,recvfrom -e inject=recvmsg:delay_enter=100ms -e inject=recvfrom:delay_enter=100ms /opt/probed --pidfile /run/test.pid >/tmp/daemon.log 2>&1 &
n=0
parent=
until [ -n "$parent" ] && [ -n "$daemon_pid" ]; do
    for device in /sys/class/net/*; do
        if grep -Fxq 'DEVTYPE=l2tpeth' "$device/uevent"; then parent=${device##*/}; break; fi
    done
    for process in /proc/[0-9]*; do
        if [ "$(readlink "$process/exe" 2>/dev/null || :)" = /opt/probed ] && [ "$(awk '/^PPid:/ {print $2}' "$process/status" 2>/dev/null)" = 1 ]; then daemon_pid=${process##*/}; break; fi
    done
    n=$((n+1)); [ "$n" -lt 1000 ]; sleep 0.01
done
kill -STOP "$daemon_pid"
initial_mac=$(cat "/sys/class/net/$parent/address")
session_index=$(cat "/sys/class/net/$parent/ifindex")
[ "$initial_mac" != 02:00:5e:00:53:01 ] || fail 'pause occurred after MAC preparation'
printf 'staged_parent=%s mac=%s\n' "$parent" "$initial_mac"
n=0
children_configured() {
    for child in vlan-local vlan-guest macvlan-local macvlan-guest; do
        ip -o address show dev "$child" 2>/dev/null | grep -Fq 'inet 192.0.2.1/24' || return 1
        ip -o address show dev "$child" 2>/dev/null | grep -Fq 'inet6 2001:db8:1::1/64' || return 1
    done
}
until children_configured; do
    n=$((n+1)); [ "$n" -lt 100 ] || { cat /tmp/networkd.log; exit 1; }; sleep 0.1
done
grep -Fq "$parent: Configuring with /etc/systemd/network/10-parent.network." /tmp/networkd.log || fail 'Type=l2tpeth did not match the temporary parent'
ip link set vlan-guest netns "$guest"
ip link set macvlan-guest netns "$guest"
for child in vlan-guest macvlan-guest; do
    nsenter -t "$guest" -n ip link set "$child" up
    nsenter -t "$guest" -n ip address add 192.0.2.1/24 dev "$child"
    nsenter -t "$guest" -n ip address add 2001:db8:1::1/64 dev "$child" nodad
done
nsenter -t "$guest" -n ip -4 route add 203.0.113.0/24 via 192.0.2.2 dev vlan-guest
nsenter -t "$guest" -n ip -6 route add 2001:db8:99::/64 via 2001:db8:1::2 dev vlan-guest
snapshot_children() {
    for child in vlan-local macvlan-local; do
        cat "/sys/class/net/$child/ifindex"
        ip -o address show dev "$child" scope global
    done
    nsenter -t "$guest" -n ip -o address show scope global | sort
    nsenter -t "$guest" -n ip -4 route show | sort
    nsenter -t "$guest" -n ip -6 route show | sort
}
socket_identities() {
    # Native IP L2TP sockets are absent from these standard socket tables.
    awk '
        FNR == 1 { next }
        FILENAME ~ /\/unix$/ { print "socket:[" $7 "]"; next }
        { print "socket:[" $10 "]" }
    ' /proc/"$daemon_pid"/net/netlink /proc/"$daemon_pid"/net/unix \
        /proc/"$daemon_pid"/net/udp /proc/"$daemon_pid"/net/udp6 \
        /proc/"$daemon_pid"/net/tcp /proc/"$daemon_pid"/net/tcp6 \
        > /tmp/control-sockets
    for fd in /proc/"$daemon_pid"/fd/*; do
        target=$(readlink "$fd" 2>/dev/null || :)
        case "$target" in socket:*) printf '%s\n' "$target" ;; esac
    done | sort -u | grep -Fvx -f /tmp/control-sockets || :
}
snapshot_children > /tmp/children-before
socket_identities > /tmp/original-sockets
[ -s /tmp/original-sockets ] || fail 'tunnel socket identity unavailable'
check_kernel_preserved() {
    [ "$(cat "/sys/class/net/$parent/ifindex")" = "$session_index" ] || fail 'parent was recreated'
    snapshot_children > /tmp/children-after
    diff -u /tmp/children-before /tmp/children-after || fail 'child identity, addresses or routes changed'
    [ "$(cat "/sys/class/net/$parent/address")" = "$initial_mac" ] || fail 'MAC changed while parent was in use'
    ip l2tp show session tunnel_id 1001 session_id 1001 | grep -Fq 'Peer session 2001, tunnel 2001' || fail 'session IDs changed'
    socket_identities > /tmp/current-sockets
    # A control socket can open between reading /proc/net and enumerating
    # descriptors. Require the original tunnel, allowing transient extras.
    while IFS= read -r socket; do
        grep -Fxq "$socket" /tmp/current-sockets || fail 'tunnel socket replaced'
    done < /tmp/original-sockets
}
if [ "$PUBLICATION_CONFLICT" = 1 ]; then
    ip link add pseudowire0 type dummy
    ip link set pseudowire0 up
    ip address add 198.51.100.1/24 dev pseudowire0
    foreign_index=$(cat /sys/class/net/pseudowire0/ifindex)
fi
kill -CONT "$daemon_pid"
if [ "$PUBLICATION_CONFLICT" = 1 ]; then
    n=0
    until grep -Fq 'File exists' /tmp/daemon.log; do
        n=$((n+1)); [ "$n" -lt 300 ] || fail 'publication conflict was not exercised'; sleep 0.1
    done
    check_kernel_preserved
    sleep 2
    check_kernel_preserved
    [ "$(cat /sys/class/net/pseudowire0/ifindex)" = "$foreign_index" ] || fail 'foreign device was replaced'
    ip -o address show dev pseudowire0 | grep -Fq 'inet 198.51.100.1/24' || fail 'foreign device was modified'
    ip link delete pseudowire0
    echo 'PASS failed publication retains the original parent and all children'
fi
n=0
until grep -Fq 'initial configuration applied' /tmp/daemon.log; do
    n=$((n+1)); [ "$n" -lt 400 ] || fail 'daemon did not become ready'; sleep 0.1
done
parent=pseudowire0
check_preserved() {
    check_kernel_preserved
    [ "$(cat /run/test.pid)" = "$daemon_pid" ] || fail 'daemon restarted'
}
reload_config() {
    before=$(grep -Fc 'configuration reload completed' /tmp/daemon.log || :)
    kill -HUP "$daemon_pid"
    n=0
    while [ "$(grep -Fc 'configuration reload completed' /tmp/daemon.log || :)" -le "$before" ]; do
        n=$((n+1)); [ "$n" -lt 300 ] || fail 'reload did not complete'; sleep 0.1
    done
}
check_preserved
echo 'PASS pre-readiness Type match preserves local and moved VLAN/macvlan children'
ip link set pseudowire0 name external0
parent=external0
check_preserved
reload_config
check_preserved
echo 'PASS external rename and unchanged reload preserve children'
ip address add 2001:db8:20::2/128 dev lo nodad
sed 's/remote_addr="::1"/remote_addr="2001:db8:20::2"/' /etc/rs-l2tpd.toml > /tmp/reloaded.toml
cp /tmp/reloaded.toml /etc/rs-l2tpd.toml
reload_config
n=0
until ip l2tp show tunnel tunnel_id 1001 | grep -Fq 'to 2001:db8:20::2'; do
    n=$((n+1)); [ "$n" -lt 100 ] || fail 'peer reload did not reconnect'; sleep 0.1
done
check_preserved
echo 'PASS peer reconnect preserves renamed parent and children'
sed 's/02:00:5e:00:53:01/02:00:5e:00:53:02/' /etc/rs-l2tpd.toml > /tmp/reloaded.toml
cp /tmp/reloaded.toml /etc/rs-l2tpd.toml
reload_config
check_preserved
echo 'PASS MAC-changing reload defers without disrupting children'
kill -TERM "$daemon_pid"
n=0
while [ -e /run/test.pid ]; do
    n=$((n+1)); [ "$n" -lt 100 ] || fail 'shutdown did not finish'; sleep 0.1
done
n=0
while [ -n "$(ip l2tp show tunnel)" ]; do
    n=$((n+1)); [ "$n" -lt 100 ] || fail 'tunnel survived shutdown'; sleep 0.1
done
daemon_pid=
for child in vlan-local macvlan-local external0; do
    if ip link show "$child" >/dev/null 2>&1; then fail "$child survived shutdown"; fi
done
for child in vlan-guest macvlan-guest; do
    if nsenter -t "$guest" -n ip link show "$child" >/dev/null 2>&1; then fail "$child survived parent teardown"; fi
done
echo 'PASS intentional shutdown removes the parent and dependent children'
