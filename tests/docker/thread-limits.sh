#!/bin/sh
# Refuse signal-thread creation and both daemon forks with container task limits.
set -eu
[ "$#" = 4 ] || { echo "usage: $0 IMAGE BINARY RECORD PROFILES" >&2; exit 2; }
image=$1; binary=$2; record=$3; profiles=$4
case $binary in /*) ;; *) binary=$(pwd)/$binary ;; esac
case $record in /*) ;; *) record=$(pwd)/$record ;; esac
case $profiles in /*) ;; *) profiles=$(pwd)/$profiles ;; esac
[ -x "$binary" ] || { echo 'missing daemon executable' >&2; exit 1; }
mkdir -p "$record" "$profiles"
chmod 777 "$profiles"
uname -r > "$record/kernel.log"
git --no-pager rev-parse HEAD > "$record/revision"
printf 'daemon git-blob: ' > "$record/artifacts.log"
git --no-pager hash-object "$binary" >> "$record/artifacts.log"
docker image inspect --format '{{.Id}}' "$image" > "$record/image.log"
printf '[host]\nfix_bindv6only=false\n' > "$record/config.toml"
name=
cleanup() {
    status=$?
    if [ -n "$name" ]; then docker rm -f "$name" >> "$record/cleanup.log" 2>&1 || :; fi
    exit "$status"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
for mode in thread fork; do
    if [ "$mode" = thread ]; then set -- --foreground; else set --; fi
    for limit in 1 2; do
    name=rs-l2tpd-$mode-limit-$-$limit
    pattern=$mode-$-$limit-%p-%m.profraw
    if [ "$mode" = thread ]; then log=$record/limit-$limit.log; else log=$record/fork-limit-$limit.log; fi
    printf 'command: timeout 60 docker create --network none --init=false --pids-limit %s IMAGE DAEMON; timeout 20 docker start --attach NAME\n' "$limit" > "$log"
    timeout 60 docker create --name "$name" --network none --init=false --pids-limit "$limit" \
        --mount "type=bind,source=$binary,target=/daemon,readonly" \
        --mount "type=bind,source=$record/config.toml,target=/config.toml,readonly" \
        --mount "type=bind,source=$profiles,target=/profiles" \
        --env "LLVM_PROFILE_FILE=/profiles/$pattern" --entrypoint /daemon "$image" \
        "$@" --config /config.toml --config-dir /absent --pid-file /probe.pid \
        >> "$log" 2>&1
    result=0
    timeout 20 docker start --attach "$name" >> "$log" 2>&1 || result=$?
    cat "$log"
    [ "$result" = 1 ] || { echo "unexpected exit: $result" >&2; exit 1; }
    grep -q 'os error 11' "$log"
    if grep -Eq 'opening kernel interfaces|ready pid=|panicked' "$log"; then exit 1; fi
    if [ "$mode" = thread ]; then
        printf 'THREAD_LIMIT_CHECKED=%s\n' "$limit"
    else
        printf 'FORK_LIMIT_CHECKED=%s\n' "$limit"
    fi
    docker rm "$name" >> "$record/cleanup.log" 2>&1
    name=
    done
done
printf 'THREAD_LIMIT_RESULT=0\nFORK_LIMIT_RESULT=0\n' | tee "$record/result.log"
