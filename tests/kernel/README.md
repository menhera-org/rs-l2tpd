# Phase 1 review probes

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
docker build --progress=plain -t rs-l2tpd-audit-vm:local -f tests/kernel/Dockerfile.review .
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
  -m 512 -smp 2 -nodefaults -nographic -serial stdio -no-reboot \
  -kernel root/boot/vmlinuz-virt -initrd initramfs.cpio \
  -append 'console=ttyS0 rdinit=/init panic=-1' > run.log 2>&1
grep 'REVIEW_RESULT=0' run.log
```

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
