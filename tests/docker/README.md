# Container verification

Current kernel and process tests run in disposable containers with no host
networking or writable host mounts. Their commands and prerequisites are in:

- [Kernel verification](../kernel/README.md): shared kernel operations,
  adapter tests, source probes and QEMU.
- [Binary verification](../process/README.md): daemon readiness, PID files,
  signals, crash/adoption, re-exec, tunables and the optional installer.
- [Testing plan](../../docs/testing.md): the remaining Phase 6 scenario suite,
  required Ubuntu/vanilla kernel matrix, Incus/LXD and coverage gates.

The current review image is built from `tests/kernel/Dockerfile.review`:

```sh
docker build --progress=plain -t rs-l2tpd-audit-vm:local -f tests/kernel/Dockerfile.review .
```

Build the test executables as described in the linked instructions before
running them. Docker containers share the host kernel; changing the image
selects userspace. A different kernel requires the QEMU instructions.

The [October 30 conformance record](../../audit/PHASE5_CONFORMANCE_FIXES_2026-10-30.md)
contains the fresh musl/glibc, systemd, procfs-hidden and QEMU process
results and their limits. The full Phase 6 runners are not implemented.

## Historical shell scenarios

The pre-rewrite shell scenarios were removed in Phase 0. The retained
`Dockerfile` and `Dockerfile.networkd` refer to those removed scripts and
cannot be built from the current checkout. They are historical fixtures,
not the runner for the rewritten daemon.

The old guide and scripts remain in commit `741117b`. Read its guide with:

```sh
git --no-pager show 741117b:tests/docker/README.md
```

Those scenarios assert the old discard-address/null-device behavior and
other baseline assumptions. They do not establish conformance of the
rewrite against the current specification.
