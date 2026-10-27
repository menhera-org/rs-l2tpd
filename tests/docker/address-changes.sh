#!/bin/sh
# Run in a disposable container with NET_ADMIN, NET_RAW and /artifacts/current.
# The container network namespace is the complete test topology.
set -eu

cp /artifacts/current /opt/current
chmod 755 /opt/current

fail() {
    echo "$*" >&2
    cat /tmp/address-daemon.log >&2
    ip l2tp show tunnel >&2
    exit 1
}

stop_daemon() {
    if [ -f /run/address-daemon.pid ]; then
        pid=$(cat /run/address-daemon.pid)
        # The deletion regression briefly stops the daemon to queue kernel
        # events. Always resume it before attempting graceful cleanup.
        kill -CONT "$pid" 2>/dev/null || :
        kill -TERM "$pid" 2>/dev/null || :
        attempts=0
        while [ -e /run/address-daemon.pid ]; do
            attempts=$((attempts + 1))
            [ "$attempts" -lt 50 ] || return 1
            sleep 0.1
        done
    fi
}

cleanup() {
    stop_daemon || :
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# Kernel tunnel dumps expose the connected socket's selected endpoints.
# IPv4 sockets use the same IPv4-mapped IPv6 representation as the daemon.
endpoint_matches() {
    ip l2tp show tunnel tunnel_id 1001 | grep -Fq "From $1 to $peer_endpoint"
}

wait_endpoint() {
    attempts=0
    until endpoint_matches "$1"; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 100 ] || fail "source did not change to $1"
        sleep 0.1
    done
}

reconnect_count() {
    grep -c 'after local address change' /tmp/address-daemon.log || :
}

failed_reconnect_count() {
    grep -c 'failed to reconnect tunnel_id=1001' /tmp/address-daemon.log || :
}

socket_identities() {
    for fd in /proc/"$daemon_pid"/fd/*; do
        # Interface/controller queries may briefly open another netlink
        # socket, which can disappear between the glob and readlink.
        target=$(readlink "$fd" 2>/dev/null || :)
        case "$target" in
            socket:*) printf '%s\n' "$target" ;;
        esac
    done | sort -u
}

session_index() {
    ip -o link show dev pseudowire0 | cut -d : -f 1
}

check_identity() {
    [ "$(cat /run/address-daemon.pid)" = "$daemon_pid" ] || fail 'daemon restarted'
    [ "$(session_index)" = "$original_index" ] || fail 'session interface was recreated'
    socket_identities > /tmp/address-sockets-current
    # Temporary query sockets are allowed; every persistent original
    # socket, including the managed tunnel socket, must still be open.
    while IFS= read -r socket; do
        grep -Fxq "$socket" /tmp/address-sockets-current || fail 'daemon socket was recreated'
    done < /tmp/address-sockets-original
    [ "$(ip -o address show dev pseudowire0 scope global)" = "$original_addresses" ] || fail 'session addresses changed'
    ip l2tp show tunnel tunnel_id 1001 | grep -Fq 'Peer tunnel 2001' || fail 'peer tunnel ID changed'
    ip l2tp show session tunnel_id 1001 session_id 1001 |
        grep -Fq 'Peer session 2001, tunnel 2001' || fail 'session IDs changed'
}

assert_no_reconnect() {
    # Allow queued notifications and one retry interval to be processed.
    sleep 1.2
    [ "$(reconnect_count)" = "$before_events" ] || fail "$1 triggered a reconnect"
    endpoint_matches "$original_endpoint" || fail "$1 changed the source"
    check_identity
}

run_case() {
    family=$1
    binding=$2
    printf 'CASE address notifications outer=%s bind=%s\n' "$family" "$binding"
    stop_daemon
    : > /tmp/address-daemon.log
    for device in underlay0 fallback0 retired0 decoy0 other0 vrf0 retired-vrf other-vrf; do
        ip link delete "$device" 2>/dev/null || :
    done
    ip link set lo up
    ip link add underlay0 type dummy
    ip link set underlay0 addrgenmode none
    if [ "$binding" = vrf0 ]; then
        ip link add vrf0 type vrf table 100
        ip link set vrf0 addrgenmode none
        ip link set vrf0 up
        ip link set underlay0 master vrf0
    fi
    ip link set underlay0 up
    ip link add decoy0 type dummy
    ip link set decoy0 addrgenmode none
    ip link set decoy0 up
    ip link add other-vrf type vrf table 200
    ip link set other-vrf addrgenmode none
    ip link set other-vrf up
    ip link add other0 type dummy
    ip link set other0 addrgenmode none
    ip link set other0 master other-vrf
    ip link set other0 up

    if [ "$family" = V4 ]; then
        first=192.0.2.1
        replacement=192.0.2.3
        replacement_device_source=192.0.2.4
        fallback_source=192.0.2.5
        peer=192.0.2.2
        decoy=192.0.2.99
        prefix=24
        original_endpoint=::ffff:$first
        replacement_endpoint=::ffff:$replacement
        replacement_device_endpoint=::ffff:$replacement_device_source
        fallback_endpoint=::ffff:$fallback_source
        peer_endpoint=::ffff:$peer
        ip address add "$first/$prefix" dev underlay0 metric 100
        ip address add "$decoy/$prefix" dev decoy0 metric 1
    else
        first=2001:db8:1::1
        replacement=2001:db8:1::3
        replacement_device_source=2001:db8:1::4
        fallback_source=2001:db8:1::5
        peer=2001:db8:1::2
        decoy=2001:db8:1::99
        prefix=64
        original_endpoint=$first
        replacement_endpoint=$replacement
        replacement_device_endpoint=$replacement_device_source
        fallback_endpoint=$fallback_source
        peer_endpoint=$peer
        ip address add "$first/$prefix" dev underlay0 metric 100 nodad
        ip address add "$decoy/$prefix" dev decoy0 metric 1 nodad
    fi
    # A lost device/VRF binding must select the wrong source, so endpoint
    # checks also detect accidentally falling back to the main routing table.
    ip route get "$peer" | grep -Fq "src $decoy" || fail 'main-table decoy route is missing'

    cat > /etc/rs-l2tpd.toml <<CONFIG
[tunnels.uplink]
tunnel_id = 1001
peer_tunnel_id = 2001
ip_version = "$family"
remote_addr = "$peer"
bind_interface = "$binding"
[sessions.lan]
tunnel_name = "uplink"
session_id = 1001
peer_session_id = 2001
interface_name = "pseudowire0"
CONFIG
    timeout 15 /opt/current --pidfile /run/address-daemon.pid > /tmp/address-daemon.log 2>&1 ||
        fail 'daemon did not become ready'
    daemon_pid=$(cat /run/address-daemon.pid)
    wait_endpoint "$original_endpoint"
    ip link set pseudowire0 up
    ip address add 198.18.0.1/30 dev pseudowire0
    ip address add fd00:2::1/64 dev pseudowire0 nodad
    sleep 0.2
    original_index=$(session_index)
    socket_identities > /tmp/address-sockets-first
    sleep 0.2
    socket_identities > /tmp/address-sockets-second
    comm -12 /tmp/address-sockets-first /tmp/address-sockets-second > /tmp/address-sockets-original
    [ -s /tmp/address-sockets-original ] || fail 'daemon socket identities are unavailable'
    original_addresses=$(ip -o address show dev pseudowire0 scope global)
    before_events=$(reconnect_count)

    # A notification for the other address family on the bound interface
    # must not disturb a working socket.
    if [ "$family" = V4 ]; then
        ip address add 2001:db8:99::1/64 dev underlay0 nodad
    else
        ip address add 198.51.100.1/24 dev underlay0
    fi
    assert_no_reconnect 'unrelated address family'
    if [ "$family" = V4 ]; then
        ip address delete 2001:db8:99::1/64 dev underlay0
        ip address add 198.51.100.1/24 dev other0
    else
        ip address delete 198.51.100.1/24 dev underlay0
        ip address add 2001:db8:99::1/64 dev other0 nodad
    fi
    assert_no_reconnect 'unrelated VRF slave address'

    # Delete the primary first: deleting an IPv4 primary can also remove
    # same-prefix secondary addresses. A bound IPv4 socket may legitimately
    # select another interface's source while its own interface has none;
    # require the notification, then the correct replacement source.
    before_removal=$(reconnect_count)
    ip address delete "$first/$prefix" dev underlay0
    attempts=0
    while [ "$(reconnect_count)" = "$before_removal" ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 50 ] || fail 'source deletion did not trigger a reconnect'
        sleep 0.1
    done
    if [ "$family" = V4 ]; then
        ip address add "$replacement/$prefix" dev underlay0 metric 100
    else
        ip address add "$replacement/$prefix" dev underlay0 metric 100 nodad
    fi
    wait_endpoint "$replacement_endpoint"
    check_identity

    # Force an actual outage without removing the session's inner addresses.
    # Taking an IPv6 underlay down normally removes its address immediately;
    # IPv4 retains it, so explicitly delete any address still present.
    before_failure=$(failed_reconnect_count)
    ip link set underlay0 down
    if ip -o address show dev underlay0 | grep -Fq "$replacement/$prefix"; then
        ip address delete "$replacement/$prefix" dev underlay0
    fi
    attempts=0
    while [ "$(failed_reconnect_count)" = "$before_failure" ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 50 ] || fail 'underlay outage did not trigger a failed reconnect'
        sleep 0.1
    done
    sleep 1.2
    if [ "$family" = V4 ]; then
        ip address add "$replacement/$prefix" dev underlay0 metric 100
    else
        ip address add "$replacement/$prefix" dev underlay0 metric 100 nodad
    fi
    ip link set underlay0 up
    wait_endpoint "$replacement_endpoint"
    check_identity
    # A successful retry must stop retrying rather than repeatedly resetting
    # the otherwise usable connected socket.
    sleep 0.2
    after_recovery=$(reconnect_count)
    sleep 1.2
    [ "$(reconnect_count)" = "$after_recovery" ] || fail 'reconnect retries continued after recovery'
    endpoint_matches "$replacement_endpoint" || fail 'recovered source did not persist'
    check_identity

    # Retain the original device under another name, then reuse the
    # configured name. The old index is still valid, so recovery requires
    # resolving the configured name again, not merely detecting deletion.
    binding_index=$(ip -o link show dev "$binding" | cut -d : -f 1)
    if [ "$binding" = underlay0 ]; then
        retired=retired0
        ip link set underlay0 name "$retired"
        ip link add underlay0 type dummy
        ip link set underlay0 addrgenmode none
        ip link set underlay0 up
    else
        retired="retired-vrf"
        ip link set vrf0 name "$retired"
        ip link add vrf0 type vrf table 101
        ip link set vrf0 addrgenmode none
        ip link set vrf0 up
        ip link set underlay0 nomaster
        ip link set underlay0 master vrf0
        ip link set underlay0 up
        # Moving between VRFs may remove IPv6 addresses on some kernels.
        if ip -o address show dev underlay0 | grep -Fq "$replacement/$prefix"; then
            ip address delete "$replacement/$prefix" dev underlay0
        fi
    fi
    [ "$(ip -o link show dev "$retired" | cut -d : -f 1)" = "$binding_index" ] ||
        fail 'original interface was not retained under its new name'
    [ "$(ip -o link show dev "$binding" | cut -d : -f 1)" != "$binding_index" ] ||
        fail 'configured name did not acquire a new interface index'
    if [ "$family" = V4 ]; then
        ip address add "$replacement_device_source/$prefix" dev underlay0 metric 100
    else
        ip address add "$replacement_device_source/$prefix" dev underlay0 metric 100 nodad
    fi
    wait_endpoint "$replacement_device_endpoint"
    check_identity
    sleep 1.2
    endpoint_matches "$replacement_device_endpoint" || fail 'replacement interface source did not persist'
    check_identity

    if [ "$binding" = vrf0 ]; then
        # Configure the fallback before deletion, and let its notifications
        # drain. When the selected slave disappears, no new address event
        # from the survivor should be needed to refresh the VRF socket.
        before_fallback=$(reconnect_count)
        ip link add fallback0 type dummy
        ip link set fallback0 addrgenmode none
        ip link set fallback0 master vrf0
        ip link set fallback0 up
        if [ "$family" = V4 ]; then
            ip address add "$fallback_source/$prefix" dev fallback0 metric 200
        else
            ip address add "$fallback_source/$prefix" dev fallback0 metric 200 nodad
        fi
        attempts=0
        while [ "$(reconnect_count)" = "$before_fallback" ]; do
            attempts=$((attempts + 1))
            [ "$attempts" -lt 50 ] || fail 'fallback slave address notification was not handled'
            sleep 0.1
        done
        sleep 1.2
        endpoint_matches "$replacement_device_endpoint" || fail 'fallback route displaced the preferred source'
        # Queue DELADDR/DELLINK until the interface can no longer be looked
        # up, making loss of its previous VRF membership deterministic.
        kill -STOP "$daemon_pid"
        attempts=0
        until grep -q '^State:.*T' /proc/"$daemon_pid"/status; do
            attempts=$((attempts + 1))
            [ "$attempts" -lt 50 ] || fail 'daemon did not stop before slave deletion'
            sleep 0.1
        done
        ip link delete underlay0
        kill -CONT "$daemon_pid"
        ip route get "$peer" oif vrf0 | grep -Fq "src $fallback_source" ||
            fail 'surviving VRF slave route is missing'
        wait_endpoint "$fallback_endpoint"
        check_identity
        sleep 0.2
        after_removal=$(reconnect_count)
        sleep 1.2
        [ "$(reconnect_count)" = "$after_removal" ] || fail 'retries continued after VRF slave removal recovery'
        endpoint_matches "$fallback_endpoint" || fail 'surviving VRF slave source did not persist'
        check_identity
    fi

    stop_daemon || fail 'daemon shutdown did not complete'
    [ -z "$(ip l2tp show tunnel)" ] || fail 'tunnel survived shutdown'
    if ip link show pseudowire0 >/dev/null 2>&1; then
        fail 'session interface survived shutdown'
    fi
    printf 'PASS address notifications outer=%s bind=%s\n' "$family" "$binding"
}

for family in V4 V6; do
    for binding in underlay0 vrf0; do
        run_case "$family" "$binding"
    done
done
echo 'PASS all four daemon address-notification cases'
