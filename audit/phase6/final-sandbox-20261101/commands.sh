set -eu
record=$PWD/audit/phase6/final-sandbox-20261101
coverage=$CARGO_LLVM_COV_TARGET_DIR
mkdir "$record"
git --no-pager rev-parse HEAD > "$record/revision"
git --no-pager diff HEAD -- src tests Cargo.toml Cargo.lock build.rs contrib > "$record/source.patch"
test ! -s "$record/source.patch"
cp audit/phase6/resolver-default-capacity-20261101/native.log "$record/native.log"
profiles=$(mktemp -d "$coverage/sandbox-profiles.XXXXXXXX")
chmod 777 "$profiles"
run_id=${profiles##*/}
unit_binary=$(awk -v root="$PWD/" -v label='Running unittests src/bin/rs-l2tpd/main.rs (' '{at=index($0,label);if(at){line=substr($0,at+length(label));sub(/[)]$/, "",line);if(substr(line,1,1)!="/")line=root line;print line}}' "$record/native.log")
test -f "$unit_binary" && test -x "$unit_binary"
families=$(sed -n 's/^RestrictAddressFamilies=//p' contrib/rs-l2tpd.service.in)
for repeat in 1 2 3; do
 unit=rs-l2tpd-phase6-final-manager-$$-$repeat.service
 full=/tmp/phase6-final-manager-$repeat.log
 systemd-run --user --no-pager --quiet --wait --pipe --collect --unit="$unit" --property=Type=notify --property=NotifyAccess=all --property=FileDescriptorStoreMax=16 --property="RestrictAddressFamilies=$families" --setenv="PHASE5_NOTIFY_UNIT=$unit" --setenv="LLVM_PROFILE_FILE=$profiles/manager-$run_id-$repeat-%p-%m.profraw" "$unit_binary" --ignored --exact fdstore::manager_tests::actual_manager_processing_and_address_family_filter --nocapture > "$full" 2>&1
 awk '/^running 1 test$/,/^test result:/' "$full" > "$record/manager-$repeat.log"
 grep -q 'test result: ok. 1 passed; 0 failed' "$record/manager-$repeat.log"
 printf 'MANAGER_RESULT=0\n' >> "$record/manager-$repeat.log"
 sh tests/docker/thread-limits.sh rs-l2tpd-coverage:phase6 "$coverage/x86_64-unknown-linux-gnu/debug/rs-l2tpd" "$record/thread-limits-$repeat" "$profiles" > "$record/thread-limits-$repeat.log" 2>&1
done
docker run --rm --network none --mount "type=bind,source=$profiles,target=/profiles" --entrypoint sh rs-l2tpd-coverage:phase6 -ec 'chmod a+r /profiles/*.profraw'
cp "$profiles/"*.profraw "$coverage/"
uname -r > "$record/kernel"
printf 'MANAGER_AND_THREAD_LIMITS_RESULT=0\n'

set -eu
record=$PWD/audit/phase6/final-sandbox-20261101
kernel_root=$PWD/target/phase6-kernels/ubuntu-noble-6.8.0-147.147/root
sh tests/kernel/run-guest.sh "$kernel_root/boot/vmlinuz-6.8.0-147-generic" "$kernel_root/lib/modules/6.8.0-147-generic" "$kernel_root/boot/config-6.8.0-147-generic" systemd "$record/root-systemd" > "$record/root-systemd.log" 2>&1
grep -q 'ROOT_SYSTEMD_RESULT=0' "$record/root-systemd/run.log"
git --no-pager diff HEAD -- src tests Cargo.toml Cargo.lock build.rs contrib > "$record/final-source.patch"
cmp "$record/source.patch" "$record/final-source.patch"
test ! -s "$record/final-source.patch"
printf 'FINAL_ROOT_SYSTEMD_RESULT=0\n'
