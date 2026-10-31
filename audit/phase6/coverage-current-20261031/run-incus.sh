#!/bin/sh
# Coverage profile transport; the full fixture remains tests/scenarios/incus.rs.
set -eu
repo=$(pwd)
record=$repo/audit/phase6/coverage-current-20261031
coverage=$repo/target/phase6-coverage-current-20261031
find_test() {
    awk -v label="Running $1 (" -v root="$repo/" '{
        at=index($0,label)
        if(at) {line=substr($0,at+length(label));sub(/\)$/, "",line);print root line}
    }' "$record/native.log"
}
unit=$(find_test 'unittests src/lib.rs')
scenario=$(find_test 'tests/scenarios/main.rs')
binary=$coverage/x86_64-unknown-linux-gnu/debug/rs-l2tpd
for artifact in "$unit" "$scenario" "$binary"; do
    if [ ! -f "$artifact" ] || [ ! -x "$artifact" ]; then
        echo "missing coverage executable: $artifact" >&2
        exit 1
    fi
done
name=rs-l2tpd-coverage-current-$$
cleanup() {
    result=$?
    incus exec "$name" -- journalctl --no-pager -n 200 -u rs-l2tpd.service > "$record/incus-journal.log" 2>&1 || :
    if incus exec "$name" -- sh -ec '
        find /opt/phase6/profiles /run/rs-l2tpd -type f -name "*.profraw" -exec chmod a+r {} + -print
    ' > "$record/incus-profiles.list"; then
        while IFS= read -r profile; do
            case $profile in /opt/phase6/profiles/*.profraw|/run/rs-l2tpd/*.profraw) ;; *) result=1; continue ;; esac
            destination=$coverage/incus-${profile##*/}
            incus --quiet file pull "$name$profile" "$destination" || result=1
        done < "$record/incus-profiles.list"
        daemon_profiles=$(awk '/^\/run\/rs-l2tpd\/daemon-[0-9]+-[0-9]+(_[0-9]+)?\.profraw$/ {count++} END {print count+0}' "$record/incus-profiles.list")
        printf 'INCUS_DAEMON_PROFILES=%s\n' "$daemon_profiles"
        if [ "$daemon_profiles" -lt 2 ]; then
            echo 'missing per-process daemon profiles' >&2
            result=1
        fi
    else
        result=1
    fi
    incus delete -f "$name" > "$record/incus-cleanup.log" 2>&1 || result=1
    printf 'INCUS_COVERAGE_RESULT=%s\n' "$result"
    exit "$result"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
pool=$(incus profile device get default root pool)
[ -n "$pool" ]
printf '%s\n' 'features: all; target: x86_64-unknown-linux-gnu; nightly branch coverage'
printf '%s\n' 'command: incus launch images:ubuntu/24.04 NAME --no-profiles --storage ROOT_POOL -c security.privileged=false'
incus --quiet launch images:ubuntu/24.04 "$name" --no-profiles --storage "$pool" -c security.privileged=false
incus exec "$name" -- uname -r
incus --quiet file push --create-dirs "$binary" "$name$binary"
incus --quiet file push --create-dirs "$unit" "$name/opt/phase6/kernel-unit"
incus --quiet file push --create-dirs "$scenario" "$name/opt/phase6/scenarios"
incus exec "$name" -- sh -ec '
    mkdir -p /opt/phase6/profiles /etc/systemd/system/rs-l2tpd.service.d
    cat > /etc/systemd/system/rs-l2tpd.service.d/coverage.conf <<"CONFIG"
[Service]
Environment=LLVM_PROFILE_FILE=/run/rs-l2tpd/daemon-%%p-%%m.profraw
RuntimeDirectoryPreserve=yes
CONFIG
'
incus exec "$name" -- env LLVM_PROFILE_FILE=/opt/phase6/profiles/buffer-%p-%m.profraw \
    /opt/phase6/kernel-unit --ignored --exact \
    kernel::linux::request::buffer_tests::subscription_buffer_matches_force_or_capped_fallback \
    --nocapture > "$record/incus-buffer.log" 2>&1
cat "$record/incus-buffer.log"
grep -q 'FORCE_RESULT=EPERM' "$record/incus-buffer.log"
incus exec "$name" -- env RS_L2TPD_INCUS=1 \
    LLVM_PROFILE_FILE=/opt/phase6/profiles/fixture-%p-%m.profraw \
    /opt/phase6/scenarios --ignored --exact \
    incus::system_container_store_tunable_networkd_and_udev --nocapture \
    > "$record/incus-scenario.log" 2>&1 || { cat "$record/incus-scenario.log"; exit 1; }
cat "$record/incus-scenario.log"
