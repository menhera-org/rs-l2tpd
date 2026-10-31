# Kernel verification

Phase 2–3 results and the per-K classification are in
[the verification record](../../audit/PHASE23_VERIFICATION_2026-10-29.md)
and [kernel evidence map](../../docs/kernel-evidence.md).
[Phase 4 verification](../../audit/PHASE4_VERIFICATION_2026-10-29.md)
adds a live service/runtime case to `kernel-linux` and re-runs the host
suites. The
[Phase 5 conformance follow-up](../../audit/PHASE5_CONFORMANCE_FIXES_2026-10-30.md)
adds fresh actual-process runs on musl/glibc and QEMU 6.12.114, 6.18.59
and 7.3. These scoped runs leave the complete required Ubuntu/vanilla
kernel matrix as a separate Phase 6 gate.

Build every test executable, including the production adapter's private live
cases in the library test executable:

```sh
cargo test --locked --all-features --target x86_64-unknown-linux-musl --no-run
```

Set `KERNEL_UNIT`, `KERNEL_TEST` and `REVIEW_TEST` to the absolute library,
`kernel-linux` and `review-kernel` executable paths printed by Cargo. Run all
three in an isolated container. `--privileged` also makes the namespace-local
tunable writable; the narrower capability list below is insufficient for that
particular test because Docker mounts `/proc/sys` read-only.

```sh
docker run --rm --network none --privileged \
  --mount "type=bind,source=$KERNEL_UNIT,target=/kernel-unit,readonly" \
  --mount "type=bind,source=$KERNEL_TEST,target=/kernel-linux,readonly" \
  --mount "type=bind,source=$REVIEW_TEST,target=/review-kernel,readonly" \
  --entrypoint sh rs-l2tpd-audit-vm:local -ec '
    uname -r
    /kernel-unit --ignored --test-threads=1 --nocapture
    /kernel-linux --ignored --test-threads=1 --nocapture
    /review-kernel --ignored --test-threads=1 --nocapture
  '
```

For QEMU, copy those three executables to the same absolute guest paths and
use `init.sh` below. For a kernel with built-in L2TP support, append
`l2tp_builtin=1` to the boot command line. The full suite also needs VRF,
IPv6 multiple tables, veth, dummy and network namespaces. Require the final
`REVIEW_RESULT=0` marker and each suite's result, not merely a zero QEMU exit.

## Real manager reference

`store-kernel` has two ignored halves. The first runs in a user systemd notify
service; the second owns a fresh network namespace inside the container.
They transfer only one test socket over a read-only Unix-socket mount. The
test proves that manager storage keeps the actual tunnel alive after local
close, then acknowledged withdrawal releases it. It does not implement the
Phase 5 binary's crash/re-exec protocol.

Set `STORE_TEST` to Cargo's absolute `store-kernel` executable path:

```sh
transfer_dir=$(mktemp -d /tmp/rs-l2tpd-store.XXXXXX)
unit=rs-l2tpd-store-$$
systemd-run --user --no-pager --collect --unit="$unit" \
  --property=Type=notify --property=NotifyAccess=all \
  --property=FileDescriptorStoreMax=1 --property=NoNewPrivileges=yes \
  --property=TimeoutStartSec=10s --property=RuntimeMaxSec=45s \
  env TRANSFER_SOCKET="$transfer_dir/socket" "$STORE_TEST" \
  --exact manager_bridge --ignored --nocapture
docker run --rm --network none --privileged \
  --mount "type=bind,source=$STORE_TEST,target=/store-kernel,readonly" \
  --mount "type=bind,source=$transfer_dir/socket,target=/transfer,readonly" \
  --env TRANSFER_SOCKET=/transfer --entrypoint /store-kernel \
  rs-l2tpd-audit-vm:local --exact kernel_reference --ignored --nocapture
journalctl --user --no-pager -n 60 -u "$unit.service"
rmdir "$transfer_dir"
```

Both halves must report success. They need a `systemd-notify` with `--fd`
and its default processing barrier; `--no-block` would invalidate the proof.

## Phase 1 review probes

These probes test the kernel assumptions behind the documentation corrections,
not the future reconciler's policy. They are ignored in ordinary Cargo runs.
The five live tests cover duplicate stored creation names, cross-namespace
deletion announcements (delivered before 7.3, namespace-local from 7.3 on;
the probe expects whichever its kernel does), eventual session-ID reuse,
socket-duplicate ownership, and outgoing drops on an unconnected tunnel. The reuse test tolerates immediate
or delayed release; a run with zero EEXIST retries does not prove synchronous
deletion. Only the kernel source establishes the upstream v6.11/v6.12 boundary.

Build the static executable:

```sh
cargo test --locked --all-features --target x86_64-unknown-linux-musl --test review-kernel --no-run
```

Set `REVIEW_TEST` to the absolute executable path Cargo prints. Use an isolated
container with no host networking or writable host mounts. SYS_ADMIN and the
seccomp setting permit the test's child network namespace; neither grants
additional privileges to the invoking host user.

```sh
tests/kernel/build-review-image.sh
timeout 60 docker run --rm --network none \
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --mount "type=bind,source=$REVIEW_TEST,target=/review-kernel,readonly" \
  --entrypoint /review-kernel rs-l2tpd-audit-vm:local \
  --ignored --test-threads=1 --nocapture
```

The conformance suite and the method-level tests of `kernel::linux`
(`tests/kernel/linux.rs`) run the same way: build `--test kernel-linux`
instead and mount it as `/kernel-linux`. Each fixture unshares a network
namespace of its own, which needs the same SYS_ADMIN and seccomp setting.

Docker uses the host kernel. To test a different kernel without KVM or elevated
host privileges, export that image into a disposable directory, copy the test
executable to `root/review-kernel` and `init.sh` to `root/init` (mode 0755),
and build an initramfs. The image contains its own Alpine kernel and modules.

```sh
# From a fresh disposable directory:
mkdir root
review_container=$(docker create rs-l2tpd-audit-vm:local)
docker export -o root.tar "$review_container"
docker rm "$review_container"
tar --exclude=dev --no-same-owner -xf root.tar -C root
# Copy REVIEW_TEST and this directory's init.sh as described above.
mkdir -p root/dev
(cd root && find . -print | cpio -o -H newc -R 0:0 > ../initramfs.cpio)
timeout 120 qemu-system-x86_64 -accel tcg -machine q35 -cpu max \
  -m 2048 -smp 2 -nodefaults -nographic -serial stdio -no-reboot \
  -kernel root/boot/vmlinuz-virt -initrd initramfs.cpio \
  -append 'console=ttyS0 rdinit=/init panic=-1' > run.log 2>&1
grep 'REVIEW_RESULT=0' run.log
```

The initramfs holds three unstripped test binaries (about 265 MB), which
the kernel unpacks into memory; with `-m 512` the unpacking fails and the
guest panics before `/init`, so give the guest 2048 MB.

QEMU returning zero alone is insufficient: require the result marker. The outer
timeout also bounds upstream blocking calls used by this disposable test
fixture. These helpers are not the daemon's future bounded request adapter.
Record the guest kernel version and image hash; the Alpine tag receives updates.

The systemd filter/store check needs only a working user systemd manager and
a systemd-notify supporting --fd, not root:

```sh
LC_ALL=C sh tests/kernel/notify.sh
```

It verifies that a real descriptor is stored and removed when AF_UNIX is
allowed, and that notification fails when it is excluded. It tests this
restriction and protocol, not the full future system unit or restart binary.
Saved results and remaining phase-specific cases are in
[audit](../../audit/PHASE1_REMEDIATION_2026-10-28.md).
