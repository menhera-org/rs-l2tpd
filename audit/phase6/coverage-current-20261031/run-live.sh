#!/bin/sh
set -eu
repo=$(pwd)
record=$repo/audit/phase6/coverage-current-20261031
coverage=$repo/target/phase6-coverage-current-20261031
profiles=$coverage/live-profiles
mkdir -p "$profiles"
chmod 777 "$profiles"
find_test() {
    awk -v label="Running $1 (" -v root="$repo/" '{
        at=index($0,label)
        if(at) {line=substr($0,at+length(label));sub(/\)$/, "",line);print root line}
    }' "$record/native.log"
}
run() {
    label=$1; shift
    test_binary=$(find_test "$label")
    if [ ! -f "$test_binary" ] || [ ! -x "$test_binary" ]; then
        echo "missing coverage executable: $test_binary" >&2
        exit 1
    fi
    printf 'command: %s' "$test_binary"
    printf ' %s' "$@"
    printf '\n'
    docker run --rm --privileged --network none \
        --mount "type=bind,source=$repo,target=$repo,readonly" \
        --mount "type=bind,source=$profiles,target=$profiles" \
        --env "LLVM_PROFILE_FILE=$profiles/live-%p-%m.profraw" \
        --env RS_L2TPD_SCENARIO_CONTAINER=1 \
        --env "RS_L2TPD_BASELINE=$repo/target/phase6-baseline/$(git --no-pager rev-parse 'v0.1.5^{commit}')/target/x86_64-unknown-linux-musl/release/rs-l2tpd" \
        --entrypoint sh rs-l2tpd-coverage:phase6 -ec 'uname -r; exec "$@"' run \
        "$test_binary" "$@"
}
printf '%s\n' 'features: all; target: x86_64-unknown-linux-gnu; nightly branch coverage'
run 'unittests src/lib.rs' --ignored --test-threads=1 --nocapture
run 'tests/kernel/linux.rs' --ignored --test-threads=1 --nocapture
run 'tests/kernel/review.rs' --ignored --test-threads=1 --nocapture
for test in pidfile::permission_tests::precreated_permissions_links_and_owner \
    pidfile::removal_tests::removal_uses_inode_after_directory_owner_changes \
    files::filesystem_tests::permission_errors_name_unreadable_unlistable_and_uninspectable_paths; do
    run 'unittests src/bin/rs-l2tpd/main.rs' --ignored --exact "$test" --nocapture
done
run 'tests/process.rs' --include-ignored --test-threads=1 --nocapture
run 'tests/scenarios/main.rs' --ignored --test-threads=1 --nocapture --skip incus::system_container_store_tunable_networkd_and_udev
docker run --rm --network none --mount "type=bind,source=$profiles,target=/profiles" \
    --entrypoint sh rs-l2tpd-coverage:phase6 -ec 'chmod a+r /profiles/*.profraw'
cp "$profiles/"*.profraw "$coverage/"
echo LIVE_COVERAGE_RESULT=0
