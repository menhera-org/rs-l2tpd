#!/bin/sh
set -eu
[ "$#" = 4 ] || { echo "usage: $0 UNIT KERNEL_ROOT RECORD PROFILES" >&2; exit 2; }
repo=$(pwd)
unit=$1; kernel_root=$2; record=$3; profiles=$4
for path in "$unit" "$kernel_root" "$record" "$profiles"; do
    case $path in /*) ;; *) echo 'use absolute paths' >&2; exit 2 ;; esac
done
[ -f "$unit" ] && [ -x "$unit" ]
[ ! -e "$record" ] && [ ! -e "$profiles" ]
set -- "$kernel_root"/boot/vmlinuz-*
[ "$#" = 1 ] && [ -f "$1" ]
kernel=$1
release=${kernel##*/vmlinuz-}
modules=$kernel_root/lib/modules/$release
config=$kernel_root/boot/config-$release
[ -d "$modules" ] && [ -f "$config" ]
mkdir -p "$record" "$profiles"
image=rs-l2tpd-coverage:phase6
image_id=$(docker image inspect --format '{{.Id}}' "$image")
printf '%s\n' "$image_id" > "$record/image.log"
base=$repo/target/phase6-kernels/base-${image_id#sha256:}
guest=$(mktemp -d /tmp/rs-l2tpd-phase6-io-qemu.XXXXXX)
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
cp -Rp "$base/root" "$guest/root"
mkdir -p "$guest/root/dev" "$guest/root/proc" "$guest/root/sys" "$guest/root/profiles" "$guest/root/lib/modules/$release"
cp -Rp "$modules/." "$guest/root/lib/modules/$release/"
cp "$unit" "$guest/root/kernel-coverage"
strip --strip-debug "$guest/root/kernel-coverage"
cp "$config" "$record/kernel.config"
cat > "$guest/root/init" <<'INIT'
#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
finish() {
    result=$?
    trap - 0
    sync
    printf 'GUEST_COVERAGE_RESULT=%s\n' "$result"
    poweroff -f
}
trap finish 0
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
depmod -a
modprobe virtio_pci
modprobe 9pnet_virtio
modprobe 9p
mount -t 9p -o trans=virtio,version=9p2000.L profiles /profiles
# This cap is confined to this disposable guest.
printf '262144\n' > /proc/sys/net/core/rmem_max
printf 'GUEST_KERNEL_RELEASE='
uname -r
printf 'GUEST_RMEM_MAX='
cat /proc/sys/net/core/rmem_max
export LLVM_PROFILE_FILE=/profiles/request-%p-%m.profraw
test=kernel::linux::request::io_fault_tests::request_io_failures_are_fallible_and_buffers_degrade
/kernel-coverage --ignored --exact "$test" --test-threads=1 --nocapture
RS_L2TPD_TEST_REQUEST_IO_FAULT=buffers-force /kernel-coverage --ignored --exact "$test" --test-threads=1 --nocapture
sync
umount /profiles
INIT
chmod 755 "$guest/root/init"
(cd "$guest/root" && find . -print | cpio -o -H newc -R 0:0 > "$guest/initramfs.cpio") > "$record/initramfs.log" 2>&1
append='console=ttyS0 rdinit=/init panic=1 rootfstype=ramfs'
if grep -q '^CONFIG_KEXEC_HANDOVER_ENABLE_DEFAULT=y$' "$config"; then append="$append kho=off"; fi
{
    printf 'scope: real netlink buffer force/fallback, receive and poll faults; GNU instrumented unit\n'
    printf 'unit git-blob: '; git --no-pager hash-object "$unit"
    printf 'kernel git-blob: '; git --no-pager hash-object "$kernel"
    printf 'fixture git-blob: '; git --no-pager hash-object "$0"
    printf 'command: timeout 900 qemu-system-x86_64 -accel tcg -machine q35 -cpu max -m 2048 -smp 2 -nodefaults -nographic -serial stdio -no-reboot -kernel IMAGE -initrd INITRAMFS -append %s -fsdev local,id=profiles,path=PROFILE_DIRECTORY,security_model=none -device virtio-9p-pci,fsdev=profiles,mount_tag=profiles\n' "$append"
} > "$record/command.log"
result=0
timeout 900 qemu-system-x86_64 -accel tcg -machine q35 -cpu max -m 2048 -smp 2 \
    -nodefaults -nographic -serial stdio -no-reboot -kernel "$kernel" \
    -initrd "$guest/initramfs.cpio" -append "$append" \
    -fsdev "local,id=profiles,path=$profiles,security_model=none" \
    -device virtio-9p-pci,fsdev=profiles,mount_tag=profiles > "$record/run.log" 2>&1 || result=$?
tr -d '\r' < "$record/run.log" > "$record/run.tmp"
mv "$record/run.tmp" "$record/run.log"
grep -E 'GUEST_|REQUEST_IO_FAULT_|test result:' "$record/run.log" || :
[ "$result" = 0 ] || exit "$result"
grep -q '^GUEST_COVERAGE_RESULT=0$' "$record/run.log"
grep -q 'REQUEST_IO_FAULT_CHECKED=buffers-force$' "$record/run.log"
[ "$(grep -c 'test result: ok. 1 passed; 0 failed' "$record/run.log")" = 2 ]
if grep -q 'LLVM Profile Error' "$record/run.log"; then exit 1; fi
count=$(find "$profiles" -name '*.profraw' -type f -size +0c -print | awk 'END { print NR }')
printf 'NONEMPTY_GUEST_PROFILES=%s\n' "$count"
[ "$count" -eq 7 ]
printf 'REQUEST_IO_GUEST_RESULT=0\n'
