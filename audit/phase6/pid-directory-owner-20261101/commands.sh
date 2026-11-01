set -eu
record=$PWD/audit/phase6/pid-directory-owner-20261101
coverage=$CARGO_LLVM_COV_TARGET_DIR
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --bin rs-l2tpd --branch --no-report > /tmp/phase6-owner-native.log 2>&1
sed '/Finished .*target(s) in /s/ in .*$/ in <build duration>/' /tmp/phase6-owner-native.log > "$record/native.log"
cargo test --color never --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd --no-run > /tmp/phase6-owner-musl-build.log 2>&1
sed '/Finished .*target(s) in /s/ in .*$/ in <build duration>/' /tmp/phase6-owner-musl-build.log > "$record/musl-build.log"
profiles=$(mktemp -d "$coverage/pid-owner-profiles.XXXXXXXX")
chmod 777 "$profiles"
run_id=${profiles##*/}
for flavor in gnu musl; do
 if test "$flavor" = gnu; then build=$record/native.log; label='Running unittests src/bin/rs-l2tpd/main.rs ('; else build=$record/musl-build.log; label='Executable unittests src/bin/rs-l2tpd/main.rs ('; fi
 unit=$(awk -v label="$label" -v root="$PWD/" '{at=index($0,label);if(at){line=substr($0,at+length(label));sub(/[)]$/, "",line);if(substr(line,1,1)!="/")line=root line;print line}}' "$build")
 test -x "$unit"
 for repeat in 1 2 3; do
  set --
  if test "$flavor" = gnu; then set -- --mount "type=bind,source=$profiles,target=$profiles" --env "LLVM_PROFILE_FILE=$profiles/owner-$run_id-$repeat-%p-%m.profraw"; fi
  docker run --rm --privileged --network none "$@" --mount "type=bind,source=$PWD,target=$PWD,readonly" --entrypoint "$unit" rs-l2tpd-coverage:phase6 --ignored --exact pidfile::permission_tests::precreated_permissions_links_and_owner --nocapture > "$record/owner-$flavor-$repeat.log" 2>&1
  grep -q 'test result: ok. 1 passed; 0 failed' "$record/owner-$flavor-$repeat.log"
 done
done
docker run --rm --network none --mount "type=bind,source=$profiles,target=/profiles" --entrypoint sh rs-l2tpd-coverage:phase6 -ec 'chmod a+r /profiles/*.profraw'
cp "$profiles/"*.profraw "$coverage/"
printf 'OWNER_GNU_MUSL_REPETITIONS_RESULT=0\n'

set -eu
record=$PWD/audit/phase6/pid-directory-owner-20261101
./test-ci-gates.sh > /tmp/phase6-pid-directory-owner-common.log 2>&1
sed '/Finished .*target(s) in /s/ in .*$/ in <build duration>/; s/; merged doctests compilation took .*$/; merged doctests compilation took <build duration>/' /tmp/phase6-pid-directory-owner-common.log > "$record/common.log"
cargo +1.89.0 check --locked --all-features --all-targets > /tmp/phase6-pid-directory-owner-msrv.log 2>&1
sed '/Finished .*target(s) in /s/ in .*$/ in <build duration>/' /tmp/phase6-pid-directory-owner-msrv.log > "$record/msrv.log"
for target in aarch64-unknown-linux-musl riscv64gc-unknown-linux-musl powerpc64le-unknown-linux-musl; do
 cargo check --locked --all-features --all-targets --target "$target" > "/tmp/phase6-pid-directory-owner-cross-$target.log" 2>&1
 sed '/Finished .*target(s) in /s/ in .*$/ in <build duration>/' "/tmp/phase6-pid-directory-owner-cross-$target.log" > "$record/cross-$target.log"
done
printf 'PID_OWNER_COMMON_RESULT=0\n'

set -eu
record=$PWD/audit/phase6/pid-directory-owner-20261101
snapshot=$PWD/audit/phase6/matrix-20261101T205406Z-3041229
for suite in noble resolute; do
 version=$(sed -n 's/^UBUNTU_META_VERSION=//p' "$snapshot/initial/$suite.log")
 release=$(sed -n 's/^KERNEL_RELEASE=//p' "$snapshot/initial/$suite.log")
 kernel_root=$PWD/target/phase6-kernels/ubuntu-$suite-$version/root
 original_root=$(sed -n 's/^KERNEL_ROOT=//p' "$snapshot/$suite-packages.log")
 original_modules=$(sed -n 's/^KERNEL_MODULES=//p' "$snapshot/$suite-packages.log")
 module_suffix=${original_modules#"$original_root"/}
 timeout 360 tests/kernel/run-guest.sh "$kernel_root/boot/vmlinuz-$release" "$kernel_root/$module_suffix" "$kernel_root/boot/config-$release" binary "$record/binary-$suite" > "$record/binary-$suite.log" 2>&1
 grep -q 'test result: ok. 65 passed; 0 failed; 5 ignored' "$record/binary-$suite/run.log"
done
for line in 2 4 5; do
 version=$(sed -n "${line}p" "$snapshot/initial/versions")
 kernel_root=$PWD/target/phase6-kernels/linux-$version-ipv6
 timeout 360 tests/kernel/run-guest.sh "$kernel_root/arch/x86/boot/bzImage" - "$kernel_root/.config" binary "$record/binary-$version" > "$record/binary-$version.log" 2>&1
 grep -q 'test result: ok. 65 passed; 0 failed; 5 ignored' "$record/binary-$version/run.log"
done
printf 'OWNER_ALL_FIVE_BINARY_KERNEL_PROFILES_RESULT=0\n'
