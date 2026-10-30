#!/bin/sh
# Whole-daemon tests; privileged operations stay in the disposable container.
set -eu
repo=$(CDPATH= cd -P "$(dirname "$0")/../.." && pwd)
cd "$repo"
[ "$#" -gt 0 ] || { echo "usage: $0 scenarios [libtest arguments] | incus" >&2; exit 2; }
case $1 in
    scenarios) shift ;;
    incus) shift; exec sh "$repo/tests/docker/incus.sh" "$@" ;;
    *) echo "usage: $0 scenarios [libtest arguments] | incus" >&2; exit 2 ;;
esac
image=rs-l2tpd-audit-vm:local
target=x86_64-unknown-linux-musl
record=$repo/audit/phase6/scenarios-$(date -u +%Y%m%dT%H%M%SZ)-$$
mkdir -p "$record"
{
    uname -r
    printf '%s\n' "features: all; target: $target" \
        "command: cargo test --locked --all-features --target $target --test scenarios --no-run"
    cargo test --locked --all-features --target "$target" --test scenarios --no-run
} > "$record/build.log" 2>&1 || {
    cat "$record/build.log"
    exit 1
}
test_binary=$(sed -n 's/^  Executable .* (\(.*\))$/\1/p' "$record/build.log")
case $test_binary in
    /*) ;;
    *) test_binary=$repo/$test_binary ;;
esac
[ -x "$test_binary" ] || { cat "$record/build.log"; echo "cannot identify scenario executable" >&2; exit 1; }
# Prepare the image from tests/kernel/Dockerfile.review separately; the runner
# never gives a test container external networking.
docker image inspect --format '{{.Id}}' "$image" > "$record/image.log"
set -- docker run --rm --privileged --network none \
    --mount "type=bind,source=$repo,target=$repo,readonly" \
    --env RS_L2TPD_SCENARIO_CONTAINER=1 \
    --entrypoint sh "$image" -ec 'uname -r; exec "$@"' run \
    "$test_binary" --ignored --test-threads=1 --nocapture --skip incus::system_container_store_tunable_networkd_and_udev "$@"
{
    printf 'command:'
    printf ' %s' "$@"
    printf '\n'
} > "$record/run.log"
result=0
"$@" >> "$record/run.log" 2>&1 || result=$?
cat "$record/run.log"
printf 'SCENARIO_RESULT=%s\nrecord: %s\n' "$result" "$record"
exit "$result"
