#!/bin/sh
# Invoked by run.sh. No profile is inherited, so no host NIC is attached.
set -eu
repo=$(CDPATH='' cd -P "$(dirname "$0")/../.." && pwd)
cd "$repo"
if ! command -v incus >/dev/null 2>&1 || ! incus list > /dev/null 2>&1; then
    echo "skipped: no Incus access"
    exit 77
fi
record=$repo/audit/phase6/incus-$(date -u +%Y%m%dT%H%M%SZ)-$$
mkdir -p "$record"
{
    uname -r
    printf '%s\n' 'command: cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --test scenarios --no-run'
    cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --test scenarios --no-run
} > "$record/build.log" 2>&1 || { cat "$record/build.log"; exit 1; }
sed 's/\(Finished .*\) in .*/\1/' "$record/build.log" > "$record/build.tmp"
mv "$record/build.tmp" "$record/build.log"
unit=$(sed -n 's/^  Executable unittests src\/lib.rs (\(.*\))$/\1/p' "$record/build.log")
scenario=$(sed -n 's/^  Executable tests\/scenarios\/main.rs (\(.*\))$/\1/p' "$record/build.log")
absolute() {
    case $1 in /*) printf '%s\n' "$1" ;; *) printf '%s/%s\n' "$repo" "$1" ;; esac
}
unit=$(absolute "$unit")
scenario=$(absolute "$scenario")
# Refuse the run if either test executable is missing or is not executable.
# shellcheck disable=SC2015
[ -x "$unit" ] && [ -x "$scenario" ] || { cat "$record/build.log"; exit 1; }
binary=$repo/target/x86_64-unknown-linux-musl/debug/rs-l2tpd
name=rs-l2tpd-phase6-$$
cleanup() {
    result=$?
    incus exec "$name" -- journalctl --no-pager -n 200 -u rs-l2tpd.service > "$record/journal.log" 2>&1 || true
    incus exec "$name" -- sh -c '
        ip -details addr show
        udevadm info /sys/class/net/incusl2tp
        networkctl --no-pager status incusl2tp
        journalctl --no-pager -n 100 -u systemd-networkd.service -u systemd-udevd.service
        cat /usr/lib/systemd/network/99-default.link
    ' > "$record/managers.log" 2>&1 || true
    if ! incus delete -f "$name" > "$record/cleanup.log" 2>&1; then
        result=1
    fi
    printf 'INCUS_RESULT=%s\nrecord: %s\n' "$result" "$record"
    exit "$result"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
# Reuse the default root disk's pool, with no network or other profile devices.
pool=$(incus profile device get default root pool)
[ -n "$pool" ]
# Log the command literally; the pool lookup must not execute while formatting it.
# shellcheck disable=SC2016
printf 'command: incus --quiet launch images:ubuntu/24.04 %s --no-profiles --storage "$(incus profile device get default root pool)" -c security.privileged=false\n' "$name"
incus --quiet launch images:ubuntu/24.04 "$name" --no-profiles --storage "$pool" -c security.privileged=false
config=$(incus config show "$name" --expanded)
printf '%s\n' "$config" | awk '
    /^  volatile\./ { skip=1; next }
    skip && /^    / { next }
    { skip=0 }
    /^    pool: / { print "    pool: <host storage pool omitted>"; next }
    { print }
' > "$record/config.log"
set -x
incus exec "$name" -- uname -r > "$record/kernel.log"
incus --quiet file push --create-dirs "$binary" "$name$binary"
incus --quiet file push --create-dirs "$unit" "$name/opt/phase6/kernel-unit"
incus --quiet file push --create-dirs "$scenario" "$name/opt/phase6/scenarios"
incus exec "$name" -- /opt/phase6/kernel-unit --ignored --exact \
    kernel::linux::request::buffer_tests::subscription_buffer_matches_force_or_capped_fallback \
    --nocapture > "$record/buffer.log" 2>&1
cat "$record/buffer.log"
grep -q 'FORCE_RESULT=EPERM' "$record/buffer.log"
incus exec "$name" -- env RS_L2TPD_INCUS=1 /opt/phase6/scenarios --ignored --exact \
    incus::system_container_store_tunable_networkd_and_udev --nocapture \
    > "$record/scenario.log" 2>&1 || { cat "$record/scenario.log"; exit 1; }
cat "$record/scenario.log"
