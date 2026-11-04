# Kernel verification

The [current verification record](../../audit/VERIFICATION.md) identifies
executed kernels and results. The [evidence map](../../docs/developer.md#kernel-evidence)
classifies each K fact; the [qualification page](../../docs/kernel-support.md)
keeps source-only/delegated claims separate from actual guest results.

## Maintained runners

From the repository root:

```sh
tests/kernel/build-review-image.sh
tests/docker/run.sh scenarios
tests/docker/run.sh matrix required
tests/docker/run.sh incus
```

The required matrix resolves current published Ubuntu/vanilla/mainline
targets before and after the run. It fetches and parses HTML indexes in
temporary storage, retaining parsed selections and artifact identities.
Each normal guest runs kernel, binary/process and scenario checks. Clock,
IPv6-absent and missing-driver profiles have separate result markers.
The driver requires expected kernel releases and passing suite markers;
QEMU exit status alone is insufficient. Run clock-sensitive profiles serially.

To run one prepared kernel:

```sh
tests/kernel/run-guest.sh "$KERNEL_IMAGE" "$KERNEL_MODULES" "$KERNEL_CONFIG" normal "$RECORD"
```

Use `-` for built-in modules or an unavailable configuration as permitted
by the runner. `clock`, `binary`, `ipv6-disable`, `no-ipv6`, `no-ethernet`,
`no-vrf` and `systemd` select scoped profiles; they are not substitutes for
the normal suite. Build the root-systemd input with
`tests/kernel/build-systemd-image.sh`. It fetches on the caller, authenticates
Ubuntu metadata, and resolves/installs packages in networkless containers.
Use `--offline` to rebuild from the cached inputs. The runner consumes
`rs-l2tpd-systemd:ubuntu24.04` and leaves the supplied unit unmodified.
See [root systemd unit](../../docs/developer.md#root-systemd-unit) for prerequisites
and verification scope.

## Optional stock kernels

`fetch-optional.sh` selects the Debian 13 and Rocky 9/10 qualification package
versions, verifies metadata/package digests and extracts without host
installation. It needs prepared `debian:trixie-slim` and `rockylinux:9` images;
Docker extraction uses `--network none`. `run-optional.sh` runs normal and
clock profiles serially, records each result and checks source consistency.

```sh
record=target/verification/optional-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$record"
for kind in debian13 rocky9 rocky10; do
    sh tests/kernel/fetch-optional.sh "$kind" "$record/$kind-packages" > "$record/$kind-fetch.log" 2>&1
    sed -n '/^KERNEL_/p' "$record/$kind-fetch.log" > "$record/$kind-packages/kernel.env"
done
sh tests/kernel/run-optional.sh "$record"
```

These are fixed qualification versions, not an automatic moving-target
resolver. Refresh the selections and rerun when qualifying newer packages.
Each normal guest must pass 28 scenarios and 37 process cases. The
capture-startup regression proves capture remains inactive before nlmon
binding. Debian 12 is outside support. Kernel-only results do not qualify
distribution userspace, SELinux or packaging; see
[kernel support](../../docs/kernel-support.md#optional-distribution-kernels).

## Direct live conformance

Build every executable, including private production-adapter live cases:

```sh
cargo test --locked --all-features --target x86_64-unknown-linux-musl --no-run
```

Set `KERNEL_UNIT`, `KERNEL_TEST` and `REVIEW_TEST` to the absolute library,
`kernel-linux` and `review-kernel` executable paths printed by Cargo.
Run them serially in a disposable container:

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

The fixtures create their own network namespaces. Privileged execution
makes namespace-local sysctls writable; do not run these cases directly
on the host. Docker shares the host kernel. GNU coverage uses the separate
review runtime from `tools/coverage/Dockerfile`; the shipped tests/binary
remain stable musl.

Review probes cover stored-name ambiguity, namespace notification scope,
identifier reuse, descriptor ownership and disconnected drops. A zero-retry
reuse result does not prove synchronous deletion. Source checks establish
that boundary, including distribution backports.

## Real manager reference

`store-kernel` has two ignored halves: a user-systemd manager bridge and
a disposable-container kernel reference. The first transfers an actual
stored descriptor to the second; acknowledged withdrawal must release the
tunnel. This is a focused ownership test, separate from binary crash/re-exec
and the full root-unit sandbox.

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

The transport/filter probe can run under a user manager:

```sh
LC_ALL=C sh tests/kernel/notify.sh
```

It requires `systemd-notify --fd` with its processing barrier and checks
AF_UNIX admission/refusal. Full process and root-unit commands are in
[binary verification](../process/README.md) and
[Developer guide](../../docs/developer.md#root-systemd-unit).
