#!/bin/sh
# Runs inside a disposable container, with its own PID and network namespaces.
# /artifacts contains static current and v0.1.5 daemon binaries, mounted read-only.
set -eu
MAC_RELOAD=${MAC_RELOAD:-0}
COOKIES=${COOKIES:-0}

cp /artifacts/current /opt/current
cp /artifacts/baseline /opt/baseline
chmod 755 /opt/current /opt/baseline

# Enter only the network namespace. Unlike `ip netns exec`, this does not
# remount sysfs and also works under nested-container mount restrictions.
netexec() {
    namespace=$1
    shift
    nsenter --net="/run/netns/$namespace" "$@"
}
netip() {
    namespace=$1
    shift
    netexec "$namespace" ip "$@"
}

cleanup() {
    for side in left right; do
        pids=$(ip netns pids "$side" 2>/dev/null || :)
        # These PIDs belong only to this test's container and namespace.
        for pid in $pids; do
            kill "$pid" 2>/dev/null || :
        done
    done
    sleep 0.1
    for side in left right; do
        pids=$(ip netns pids "$side" 2>/dev/null || :)
        for pid in $pids; do
            kill -KILL "$pid" 2>/dev/null || :
        done
        ip netns delete "$side" 2>/dev/null || :
        rm -f "/run/$side.pid"
    done
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

config() {
    side=$1
    local_id=$2
    peer_id=$3
    peer_addr=$4
    mac=$5
    cookie=${6:-}
    peer_cookie=${7:-}
    cat > "/etc/netns/$side/rs-l2tpd.toml" <<EOF
[tunnels.uplink]
tunnel_id = $local_id
peer_tunnel_id = $peer_id
ip_version = "$family"
remote_addr = "$peer_addr"
EOF
    if [ "$binding" != unbound ]; then
        printf 'bind_interface = "%s"\n' "$binding" >> "/etc/netns/$side/rs-l2tpd.toml"
    fi
    cat >> "/etc/netns/$side/rs-l2tpd.toml" <<EOF
[sessions.lan]
tunnel_name = "uplink"
session_id = $local_id
peer_session_id = $peer_id
interface_name = "pseudowire0"
interface_hwaddr = "$mac"
EOF
    if [ -n "$cookie" ]; then
        printf 'cookie = "%s"\npeer_cookie = "%s"\n' "$cookie" "$peer_cookie" \
            >> "/etc/netns/$side/rs-l2tpd.toml"
    fi
}

# Reloads one daemon and waits for the reload to be applied, whether at
# once or after a retry (a re-created session's old device may still be
# going away when the new one is requested).
reload_side() {
    side=$1
    before=$(grep -c -E 'configuration (reload|convergence) completed' "/tmp/$side-daemon.log" || true)
    cp "/etc/netns/$side/rs-l2tpd.toml" /etc/rs-l2tpd.toml
    kill -HUP "$(cat "/run/$side.pid")"
    attempts=0
    until [ "$(grep -c -E 'configuration (reload|convergence) completed' "/tmp/$side-daemon.log" || true)" -gt "$before" ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 100 ] || return 1
        sleep 0.1
    done
}

# Waits until pseudowire0 in a namespace is a different device than before.
wait_new_interface() {
    side=$1
    old_index=$2
    attempts=0
    until index=$(netip "$side" -o link show pseudowire0 2>/dev/null | cut -d: -f1) \
        && [ -n "$index" ] && [ "$index" != "$old_index" ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 100 ] || return 1
        sleep 0.1
    done
}

# A re-created session device comes up bare: restore the test addresses.
configure_left_pseudowire() {
    netip left link set pseudowire0 up
    netip left address replace 198.18.0.1/30 dev pseudowire0
    netip left address replace fd00:2::1/64 dev pseudowire0 nodad
}

traffic() {
    netexec left ping -n -q -c 2 -i 0.1 -W 2 198.18.0.2
    netexec right ping -n -q -c 2 -i 0.1 -W 2 198.18.0.1
    netexec left ping -6 -n -q -c 2 -i 0.1 -W 2 fd00:2::2
    netexec right ping -6 -n -q -c 2 -i 0.1 -W 2 fd00:2::1
}

run_case() {
    left_binary=$1
    right_binary=$2
    family=$3
    binding=$4
    printf '\nCASE %s / %s outer=%s bind=%s\n' "$left_binary" "$right_binary" "$family" "$binding"
    cleanup
    for side in left right; do
        ip netns add "$side"
        netip "$side" link set lo up
        mkdir -p "/etc/netns/$side"
    done
    ip link add ula type veth peer name ulb
    ip link set ula netns left
    ip link set ulb netns right
    netip left link set ula name underlay0
    netip right link set ulb name underlay0
    for side in left right; do
        if [ "$binding" = vrf0 ]; then
            netip "$side" link add vrf0 type vrf table 100
            netip "$side" link set vrf0 up
            netip "$side" link set underlay0 master vrf0
        fi
        netip "$side" link set underlay0 up
    done
    netip left address add 192.0.2.1/24 dev underlay0
    netip right address add 192.0.2.2/24 dev underlay0
    netip left address add 2001:db8:1::1/64 dev underlay0 nodad
    netip right address add 2001:db8:1::2/64 dev underlay0 nodad
    if [ "$family" = V4 ]; then
        left_addr=192.0.2.1
        right_addr=192.0.2.2
    else
        left_addr=2001:db8:1::1
        right_addr=2001:db8:1::2
    fi
    # Cookies exist only in the current daemon; a baseline peer would
    # ignore the keys and drop or misread every frame.
    left_cookie=
    left_peer_cookie=
    right_cookie=
    right_peer_cookie=
    if [ "$COOKIES" = 1 ] && [ "$left_binary" = current ] && [ "$right_binary" = current ]; then
        left_cookie=0011223344556677
        left_peer_cookie=8899aabb
        right_cookie=8899aabb
        right_peer_cookie=0011223344556677
    fi
    config left 1001 2001 "$right_addr" 02:00:5e:00:53:01 "$left_cookie" "$left_peer_cookie"
    config right 2001 1001 "$left_addr" 02:00:5e:00:53:02 "$right_cookie" "$right_peer_cookie"
    cp /etc/netns/left/rs-l2tpd.toml /etc/rs-l2tpd.toml
    timeout 15 nsenter --net=/run/netns/left "/opt/$left_binary" --pidfile /run/left.pid > /tmp/left-daemon.log 2>&1
    cp /etc/netns/right/rs-l2tpd.toml /etc/rs-l2tpd.toml
    timeout 15 nsenter --net=/run/netns/right "/opt/$right_binary" --pidfile /run/right.pid > /tmp/right-daemon.log 2>&1
    for side in left right; do
        netip "$side" link set pseudowire0 up
        netip "$side" l2tp show tunnel
        netip "$side" l2tp show session
    done
    netip left address add 198.18.0.1/30 dev pseudowire0
    netip right address add 198.18.0.2/30 dev pseudowire0
    netip left address add fd00:2::1/64 dev pseudowire0 nodad
    netip right address add fd00:2::2/64 dev pseudowire0 nodad
    traffic

    # The compatibility matrix reloads an unchanged 0.1.5 configuration.
    # MAC_RELOAD=1 additionally exercises the newer MAC-changing behavior.
    original_mac=02:00:5e:00:53:01
    expected_mac=$original_mac
    if [ "$MAC_RELOAD" = 1 ] && [ "$left_binary" = current ]; then
        expected_mac=02:00:5e:00:53:11
    fi
    config left 1001 2001 "$right_addr" "$expected_mac" "$left_cookie" "$left_peer_cookie"
    reload_side left
    # A running interface is never taken down for a MAC change: right after
    # the reload it still carries its original MAC and its addresses, and
    # traffic is intact.
    if [ "$left_binary" = current ]; then
        netip left -o link show pseudowire0 | grep -q "$original_mac"
    fi
    netip left -6 address show dev pseudowire0
    traffic
    if [ "$expected_mac" != "$original_mac" ]; then
        # The deferred change applies on the link-change notification once
        # the interface is down. Taking it down drops its IPv6 address, as
        # the kernel does for any interface; the test restores it.
        netip left link set pseudowire0 down
        attempts=0
        until netip left -o link show pseudowire0 | grep -q "$expected_mac"; do
            attempts=$((attempts + 1))
            [ "$attempts" -lt 50 ] || return 1
            sleep 0.1
        done
        netip left link set pseudowire0 up
        netip left address replace fd00:2::1/64 dev pseudowire0 nodad
        traffic
    fi

    if [ -n "$left_cookie" ]; then
        # A session whose cookies change is re-created. With a peer cookie
        # the right side does not send, every frame from the right is
        # discarded at the left: requests from the right and replies to the
        # left's own requests alike.
        old_index=$(netip left -o link show pseudowire0 | cut -d: -f1)
        config left 1001 2001 "$right_addr" "$expected_mac" "$left_cookie" ffffffff
        reload_side left
        wait_new_interface left "$old_index"
        echo "cookie change re-created pseudowire0 (index $old_index -> $index)"
        configure_left_pseudowire
        if netexec right ping -n -q -c 1 -W 1 198.18.0.1 > /dev/null 2>&1; then
            echo "frames with a wrong cookie were accepted" >&2
            return 1
        fi
        if netexec left ping -n -q -c 1 -W 1 198.18.0.2 > /dev/null 2>&1; then
            echo "replies with a wrong cookie were accepted" >&2
            return 1
        fi
        echo "cookie mismatch: frames discarded in both directions"
        # Restoring the agreed cookies re-creates the session once more and
        # traffic flows again.
        old_index=$(netip left -o link show pseudowire0 | cut -d: -f1)
        config left 1001 2001 "$right_addr" "$expected_mac" "$left_cookie" "$left_peer_cookie"
        reload_side left
        wait_new_interface left "$old_index"
        echo "cookies restored, pseudowire0 re-created (index $old_index -> $index)"
        configure_left_pseudowire
        traffic
    fi

    for side in left right; do
        kill -TERM "$(cat "/run/$side.pid")"
    done
    attempts=0
    while [ -e /run/left.pid ] || [ -e /run/right.pid ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 50 ] || return 1
        sleep 0.1
    done
    for side in left right; do
        [ -z "$(netip "$side" l2tp show tunnel)" ]
        if netip "$side" link show pseudowire0 >/dev/null 2>&1; then
            echo "session interface survived shutdown" >&2
            return 1
        fi
    done
    printf 'PASS %s / %s outer=%s bind=%s\n' "$left_binary" "$right_binary" "$family" "$binding"
}

for family in V4 V6; do
    for binding in unbound underlay0 vrf0; do
        run_case baseline baseline "$family" "$binding"
        run_case current baseline "$family" "$binding"
        run_case current current "$family" "$binding"
    done
done
if [ "$COOKIES" = 1 ]; then
    echo 'PASS all 18 daemon interoperability cases, reloads, cookie checks and shutdown cleanup'
else
    echo 'PASS all 18 daemon interoperability cases, reloads and shutdown cleanup'
fi
