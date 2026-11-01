#!/bin/sh
# Refuse each signal-thread creation with a real container task limit.
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
for limit in 1 2; do
    name=rs-l2tpd-thread-limit-$$-$limit
    pattern=thread-$$-$limit-%p-%m.profraw
    printf 'command: timeout 20 docker run --rm --network none --pids-limit %s IMAGE DAEMON --foreground --config /config.toml --config-dir /absent --pid-file /probe.pid\n' "$limit" > "$record/limit-$limit.log"
    result=0
    timeout 20 docker run --rm --name "$name" --network none --pids-limit "$limit" \
        --mount "type=bind,source=$binary,target=/daemon,readonly" \
        --mount "type=bind,source=$record/config.toml,target=/config.toml,readonly" \
        --mount "type=bind,source=$profiles,target=/profiles" \
        --env "LLVM_PROFILE_FILE=/profiles/$pattern" --entrypoint /daemon "$image" \
        --foreground --config /config.toml --config-dir /absent --pid-file /probe.pid \
        >> "$record/limit-$limit.log" 2>&1 || result=$?
    cat "$record/limit-$limit.log"
    [ "$result" = 1 ] || { echo "unexpected exit: $result" >&2; exit 1; }
    grep -q 'os error 11' "$record/limit-$limit.log"
    if grep -q 'opening kernel interfaces\|ready pid=\|panicked' "$record/limit-$limit.log"; then exit 1; fi
    printf 'THREAD_LIMIT_CHECKED=%s\n' "$limit"
    name=
done
printf 'THREAD_LIMIT_RESULT=0\n' | tee "$record/result.log"
