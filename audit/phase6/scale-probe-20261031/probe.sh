#!/bin/sh
set -eu
binary=$1
work=$(mktemp -d)
pid=
cleanup() { if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi; rm -rf "$work"; }
trap cleanup 0
trap 'exit 1' 1 2 3 15
config() {
    count=$1
    {
        printf '[host]\nfix_bindv6only=false\n'
        n=1
        while [ "$n" -le "$count" ]; do
            printf '[tunnels.t%s]\ntunnel_id=%s\nremote_addr="::1"\n[sessions.s%s]\ntunnel_name="t%s"\nsession_id=%s\ninterface_name="scale%s"\n' "$n" "$n" "$n" "$n" "$n" "$n"
            n=$((n+1))
        done
    } > "$work/main.toml"
}
wait_for() {
    count=$1
    limit=$(( $(date +%s) + 30 ))
    while :; do
        sessions=$(ip l2tp show session | grep -c '^Session' || :)
        tunnels=$(ip l2tp show tunnel | grep -c '^Tunnel' || :)
        if [ "$sessions" = "$count" ] && [ "$tunnels" = "$count" ]; then break; fi
        [ "$(date +%s)" -lt "$limit" ] || { cat "$work/log"; exit 1; }
        sleep 0.1
    done
    set -- /proc/"$pid"/fd/*
    fds=$#
    [ "$fds" -ge "$count" ] && [ "$fds" -le "$((count+20))" ]
    printf 'objects=%s descriptors=%s ' "$count" "$fds"
    grep '^VmRSS:' /proc/"$pid"/status
}
uname -r
printf '%s\n' 'features: all; target: x86_64-unknown-linux-musl' 'scope: exploratory 300-object/reload/shrink probe, not the full H17 gate'
ip link set lo up
config 300
"$binary" --foreground --config "$work/main.toml" --config-dir "$work/absent" > "$work/log" 2>&1 &
pid=$!
wait_for 300
limit=$(( $(date +%s) + 30 ))
while ! grep -q "ready pid=$pid" "$work/log"; do
    [ "$(date +%s)" -lt "$limit" ] || exit 1
    sleep 0.1
done
for count in 1 300 1 300 1; do
    config "$count"
    kill -HUP "$pid"
    wait_for "$count"
done
kill -TERM "$pid"
wait "$pid"
pid=
[ -z "$(ip l2tp show tunnel)" ] && [ -z "$(ip l2tp show session)" ]
echo SCALE_PROBE_RESULT=0
