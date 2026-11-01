set -eu
record=$PWD/audit/phase6/pidfile-inspection-errors-20261101
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report > /tmp/phase6-pidfile-inspection-errors-native.log 2>&1
sed '/Finished .*target(s) in /s/ in .*$/ in <build duration>/; s/; merged doctests compilation took .*$/; merged doctests compilation took <build duration>/' /tmp/phase6-pidfile-inspection-errors-native.log > "$record/native.log"
for seed in 1 2 3 4 5 6 7 8 9 10; do
 TEST_SEED=$seed cargo test --locked --all-features --target x86_64-unknown-linux-gnu --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup > "/tmp/phase6-pidfile-inspection-errors-model-$seed.log" 2>&1
 sed '/Finished .*target(s) in /s/ in .*$/ in <build duration>/' "/tmp/phase6-pidfile-inspection-errors-model-$seed.log" > "$record/model-$seed.log"
 TEST_SEED=$seed cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup --branch --no-report > "/tmp/phase6-pidfile-inspection-errors-coverage-model-$seed.log" 2>&1
 sed '/Finished .*target(s) in /s/ in .*$/ in <build duration>/' "/tmp/phase6-pidfile-inspection-errors-coverage-model-$seed.log" > "$record/coverage-model-$seed.log"
done
for seed in 1 2 3; do
 TEST_SEED=$seed cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup > "/tmp/phase6-pidfile-inspection-errors-musl-model-$seed.log" 2>&1
 sed '/Finished .*target(s) in /s/ in .*$/ in <build duration>/' "/tmp/phase6-pidfile-inspection-errors-musl-model-$seed.log" > "$record/musl-model-$seed.log"
done
printf 'PIDFILE_INSPECTION_MODELS_RESULT=0\n'

set -eu
record=$PWD/audit/phase6/pidfile-inspection-errors-20261101
./test-ci-gates.sh > /tmp/phase6-pidfile-inspection-errors-common.log 2>&1
sed '/Finished .*target(s) in /s/ in .*$/ in <build duration>/; s/; merged doctests compilation took .*$/; merged doctests compilation took <build duration>/' /tmp/phase6-pidfile-inspection-errors-common.log > "$record/common.log"
cargo +1.89.0 check --locked --all-features --all-targets > /tmp/phase6-pidfile-inspection-errors-msrv.log 2>&1
sed '/Finished .*target(s) in /s/ in .*$/ in <build duration>/' /tmp/phase6-pidfile-inspection-errors-msrv.log > "$record/msrv.log"
for target in aarch64-unknown-linux-musl riscv64gc-unknown-linux-musl powerpc64le-unknown-linux-musl; do
 cargo check --locked --all-features --all-targets --target "$target" > "/tmp/phase6-pidfile-inspection-errors-cross-$target.log" 2>&1
 sed '/Finished .*target(s) in /s/ in .*$/ in <build duration>/' "/tmp/phase6-pidfile-inspection-errors-cross-$target.log" > "$record/cross-$target.log"
done
printf 'PIDFILE_INSPECTION_COMMON_RESULT=0\n'

set -eu
record=$PWD/audit/phase6/pidfile-inspection-errors-20261101
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
printf 'ALL_FIVE_BINARY_KERNEL_PROFILES_RESULT=0\n'

set -eu
record=$PWD/audit/phase6/pidfile-inspection-errors-20261101
probe=$(mktemp -d /tmp/phase6-binary-markers.XXXXXXXX)
trap 'rm -rf "$probe"' 0
sed -n '/^markers=/,$p' tests/kernel/run-guest.sh > "$probe/check.sh"
test -s "$probe/check.sh"
for profile in normal binary systemd clock; do
 case $profile in
 normal) required='CONFORMANCE_RESULT=0 SCENARIO_RESULT=0 MATRIX_GUEST_RESULT=0' ;;
 binary) required='BINARY_UNIT_RESULT=0 MATRIX_GUEST_RESULT=0' ;;
 systemd) required='ROOT_SYSTEMD_RESULT=0' ;;
 clock) required='CONFORMANCE_RESULT=0 SCENARIO_RESULT=0 MATRIX_GUEST_RESULT=0 H16_CONTROLLER_RESULT=0' ;;
 esac
 for marker in $required; do printf '%s\n' "$marker"; done > "$probe/full.log"
 cp "$probe/full.log" "$probe/run.log"
 mode=$profile record=$probe sh -eu "$probe/check.sh"
 printf 'MARKERS profile=%s complete=accepted\n' "$profile"
 for marker in $required; do
  grep -vx "$marker" "$probe/full.log" > "$probe/run.log" || test "$?" -eq 1
  result=0
  mode=$profile record=$probe sh -eu "$probe/check.sh" || result=$?
  test "$result" -eq 1
  printf 'MARKERS profile=%s missing=%s rejected=%s\n' "$profile" "$marker" "$result"
 done
done
result=0
tests/kernel/run-guest.sh - - - invalid-mode "$probe/unused" > "$record/invalid-mode.log" 2>&1 || result=$?
test "$result" -eq 2
printf 'INVALID_MODE_REJECTED=%s\n' "$result"
