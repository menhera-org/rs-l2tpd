#!/bin/sh
set -eu
[ "$#" = 5 ] || { echo "usage: $0 IMAGE MODULES|- CONFIG|- normal|ipv6-disable|no-ipv6|no-ethernet|clock|systemd RECORD" >&2; exit 2; }
repo=$(CDPATH='' cd -P "$(dirname "$0")/../.." && pwd)
cd "$repo"
kernel=$1; modules=$2; config=$3; mode=$4; record=$5
case $kernel in /*) ;; *) kernel=$repo/$kernel ;; esac
case $record in /*) ;; *) record=$repo/$record ;; esac
case $mode in normal|ipv6-disable|no-ipv6|no-ethernet|clock|systemd) ;; *) exit 2 ;; esac
[ -f "$kernel" ] && [ -s "$kernel" ] || exit 1
[ "$modules" = - ] || [ -d "$modules" ] || { echo 'module directory missing' >&2; exit 1; }
[ "$config" = - ] || [ -f "$config" ] || { echo 'kernel config missing' >&2; exit 1; }
[ "$mode" != no-ethernet ] || [ "$modules" != - ] || { echo 'no-ethernet needs a modular stock kernel' >&2; exit 2; }
mkdir -p "$record"
image=rs-l2tpd-audit-vm:local
if [ "$mode" = systemd ]; then image=nd-test:u2404; fi
image_id=$(docker image inspect --format '{{.Id}}' "$image")
printf '%s\n' "$image_id" > "$record/image.log"
base=$repo/target/phase6-kernels/base-${image_id#sha256:}
guest=$(mktemp -d /tmp/rs-l2tpd-phase6-qemu.XXXXXX)
container=
cleanup() {
    if [ -n "$container" ]; then docker rm -f "$container" >/dev/null 2>&1 || :; fi
    rm -rf "$guest"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15
if [ ! -f "$base/complete" ]; then
    mkdir -p "$base"
    container=$(docker create --network none "$image")
    docker export --output "$base/root.tar" "$container"
    docker rm "$container" >/dev/null
    container=
    rm -rf "$base/root"
    mkdir "$base/root"
    tar -xf "$base/root.tar" --exclude=dev --no-same-owner -C "$base/root"
    : > "$base/complete"
fi
{
    printf '%s\n' 'features: all; target: x86_64-unknown-linux-musl' \
        'command: cargo test --locked --all-features --target x86_64-unknown-linux-musl --no-run'
    cargo test --locked --all-features --target x86_64-unknown-linux-musl --no-run
} > "$record/build.log" 2>&1 || { cat "$record/build.log"; exit 1; }
# Build-time duration is a machine fact, not verification evidence.
sed 's/\(Finished .*\) in .*/\1/' "$record/build.log" > "$record/build.tmp"
mv "$record/build.tmp" "$record/build.log"
cp -Rp "$base/root" "$guest/root"
mkdir -p "$guest/root/dev"
copy_test() {
    path=$(awk -v label="Executable $1 (" '{
        at=index($0,label)
        if(at) { line=substr($0,at+length(label)); sub(/\)$/,"",line); print line }
    }' "$record/build.log")
    case $path in /*) ;; *) path=$repo/$path ;; esac
    [ -x "$path" ] || { echo "missing executable for $1" >&2; exit 1; }
    cp "$path" "$guest/root/$2"
    strip --strip-debug "$guest/root/$2"
    printf '%s git-blob: ' "$2" >> "$record/artifacts.log"
    git --no-pager hash-object "$path" >> "$record/artifacts.log"
}
: > "$record/artifacts.log"
copy_test 'unittests src/lib.rs' kernel-unit
copy_test 'unittests src/bin/rs-l2tpd/main.rs' binary-unit
copy_test 'tests/kernel/linux.rs' kernel-linux
copy_test 'tests/kernel/review.rs' review-kernel
copy_test 'tests/process.rs' process-test
copy_test 'tests/scenarios/main.rs' scenarios
copy_test 'tests/scenarios/boot.rs' boot-scenarios
if [ "$mode" = systemd ]; then copy_test 'tests/scenarios/systemd.rs' systemd-scenarios; fi
binary=$repo/target/x86_64-unknown-linux-musl/debug/rs-l2tpd
mkdir -p "$guest/root$(dirname "$binary")"
cp "$binary" "$guest/root$binary"
strip --strip-debug "$guest/root$binary"
printf 'daemon git-blob: ' >> "$record/artifacts.log"
git --no-pager hash-object "$binary" >> "$record/artifacts.log"
baseline_revision=$(git --no-pager rev-parse 'v0.1.5^{commit}')
baseline=$(sh tests/docker/baseline.sh "$record")
cp "$baseline" "$guest/root/baseline"
if [ "$modules" != - ]; then
    release=${modules##*/}
    mkdir -p "$guest/root/lib/modules/$release"
    cp -Rp "$modules/." "$guest/root/lib/modules/$release/"
fi
if [ "$config" != - ]; then cp "$config" "$record/kernel.config"; fi
cp tests/kernel/matrix-init.sh "$guest/root/init"
if [ "$mode" = systemd ]; then
    cp tests/kernel/systemd-init.sh "$guest/root/init"
    cp -Rp "$modules/../../../usr/." "$guest/root/usr/"
fi
chmod 755 "$guest/root/init"
printf '%s\n' "$mode" > "$guest/root/matrix-mode"
(cd "$guest/root" && find . -print | cpio -o -H newc -R 0:0 > "$guest/initramfs.cpio") > "$record/initramfs.log" 2>&1
append='console=ttyS0 rdinit=/init panic=1 rootfstype=ramfs'
# KHO scratch can starve the cold-boot initramfs; these tests never kexec.
if [ "$config" != - ] && grep -q '^CONFIG_KEXEC_HANDOVER_ENABLE_DEFAULT=y$' "$config"; then
    append="$append kho=off"
fi
if [ "$modules" = - ]; then append="$append l2tp_builtin=1"; fi
if [ "$mode" = ipv6-disable ]; then append="$append ipv6.disable=1"; fi
if [ "$mode" = clock ]; then append="$append rs_l2tpd_clock_guest=1"; fi
{
    printf 'mode: %s\nkernel image git-blob: ' "$mode"
    git --no-pager hash-object "$kernel"
    printf 'baseline commit: %s\n' "$baseline_revision"
    printf 'baseline binary git-blob: '
    git --no-pager hash-object "$baseline"
    printf '%s\n' "command: qemu-system-x86_64 -accel tcg -machine q35 -cpu max -m 2048 -smp 2 -nodefaults -nographic -serial stdio -no-reboot -kernel IMAGE -initrd INITRAMFS -append '$append'"
} > "$record/command.log"
set -- qemu-system-x86_64 -accel tcg -machine q35 -cpu max -m 2048 -smp 2 \
    -nodefaults -nographic -serial stdio -no-reboot -kernel "$kernel" \
    -initrd "$guest/initramfs.cpio" -append "$append"
if [ "$mode" = clock ]; then
    {
        printf '%s\n' 'command: rustc --edition=2024 -D warnings tests/kernel/clock-control.rs; rustc --test; execute controller unit tests'
        rustc --edition=2024 -D warnings tests/kernel/clock-control.rs -o "$guest/clock-control"
        rustc --edition=2024 -D warnings --test tests/kernel/clock-control.rs -o "$guest/clock-control-tests"
        "$guest/clock-control-tests"
    } > "$record/clock-control-build.log" 2>&1
    set -- "$@" -qmp "unix:$guest/qmp,server=on,wait=off"
    set -- "$guest/clock-control" "$guest/qmp" "$@"
    {
        printf '%s\n' 'controller: tests/kernel/clock-control.rs; QMP stop/query-status/cont; three-second measured pause' \
            'qmp argument: -qmp unix:QMP_SOCKET,server=on,wait=off' \
            'host command: timeout 900 CLOCK_CONTROL QMP_SOCKET QEMU_COMMAND'
        printf 'controller source git-blob: '
        git --no-pager hash-object tests/kernel/clock-control.rs
        printf 'controller executable git-blob: '
        git --no-pager hash-object "$guest/clock-control"
    } >> "$record/command.log"
fi
result=0
timeout 900 "$@" > "$record/run.log" 2>&1 || result=$?
tr -d '\r' < "$record/run.log" > "$record/run.tmp"
mv "$record/run.tmp" "$record/run.log"
grep -E 'Linux version|GUEST_KERNEL_RELEASE|scope:|test result:|_RESULT=' "$record/run.log" || :
[ "$result" = 0 ] || exit "$result"
markers='CONFORMANCE_RESULT=0 SCENARIO_RESULT=0 MATRIX_GUEST_RESULT=0'
if [ "$mode" = systemd ]; then markers='ROOT_SYSTEMD_RESULT=0'; fi
if [ "$mode" = clock ]; then markers="$markers H16_CONTROLLER_RESULT=0"; fi
for marker in $markers; do
    grep -q "^$marker" "$record/run.log" || exit 1
done
