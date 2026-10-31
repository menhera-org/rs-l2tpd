# Live scenario runner

Run the implemented host/manager subset on the host kernel:

```sh
tests/docker/run.sh scenarios
```

The runner builds the daemon and Rust integration executable for
`x86_64-unknown-linux-musl`, mounts the checkout read-only at its absolute
path, and uses a disposable privileged Docker container with
`--network none`. It records the command, features, kernel, image ID,
build output and test results under `audit/phase6/scenarios-<run>/`.

Provide `rs-l2tpd-audit-vm:local`, prepared from
`tests/kernel/Dockerfile.review` with iproute2, busybox and util-linux.
The runner uses the prepared image; it does not give test containers
external networking. The runner also builds the archived v0.1.5 tag with
its own lockfile in an isolated cache, and records its commit and binary
hash for the interoperability case. The historical `Dockerfile` and
`Dockerfile.networkd` reference removed pre-rewrite scripts.

A libtest filter can select a case while debugging, for example:

```sh
tests/docker/run.sh scenarios vrf_membership
```

The current subset covers dual stack, IPv4-only, IPv6-only, sysctl-disabled
IPv6, early readiness without routes, VRF membership, procfs-hidden
operation with the three capabilities, hotplug, address churn,
`bindv6only`, a VLAN child in another namespace, and foreign identifiers
and names, non-systemd parent/PID/signal behavior, 0.1.5 configuration
and peer interoperability, and 100,000 routes per family without a default.
The route case requires an already available nlmon module: its packet
socket sees unicast requests too, uses positive controls and rejects any
capture loss. Guards kill daemons and delete namespaces on panic. Frame
delivery and drop counters are asserted, along with interface identity,
kernel objects, logs and bounded event waits.

This is **not the complete Phase 6 scenario gate**. Boot-only cases,
large session tables, missing modules/capability fallbacks,
networkd version combinations and the full promise case
list remain open. H20 now covers full-MTU frames and 1 MiB transfers over both families,
1500/9000 session MTUs and VRF/no-VRF binding, with sender fragment and
session receive/drop counters. A separate live socket test reads back
T5's options; a child-only seccomp case checks actual option refusals.
The matrix driver runs this implemented subset; it cannot close missing
scenario coverage by itself.

## Kernel matrix

```sh
tests/docker/run.sh matrix required
tests/docker/run.sh matrix v6.8..v7.3
```

The required selection resolves the published Ubuntu updates/security
packages for the two LTS suites, each vanilla equivalent, and kernel.org
mainline. It records publication metadata before and after the run and
fails if a required version changes. Each guest must print passing
conformance and scenario markers and its expected kernel release; QEMU
exiting successfully is insufficient. H20 runs in every normal guest.
Two extra mainline boots cover `ipv6.disable=1` and `CONFIG_IPV6=n`.
The range selects the newest patch release in each requested series.

Provide QEMU, cpio, strip, curl, xz and the prepared review and kernel
builder images from `tests/kernel/Dockerfile.review` and
`tests/kernel/Dockerfile.builder`. Downloads occur outside test containers;
all Docker invocations use `--network none`. Kernels and the archived
0.1.5 peer are cached under `target/`. Records include exact artifact
hashes under `audit/phase6/matrix-<run>/`. Missing or changed publication
formats fail closed. Mainline release candidates are not yet accepted by
the tarball builder; add and verify that path when mainline moves to one.

## Unprivileged system container

```sh
tests/docker/run.sh incus
```

The host needs Incus access, the `images:` remote, a storage pool for the
default profile's root disk, and the kernel modules required by
[Phase 6](../../docs/phase6.md#p5-the-unprivileged-system-container).
The driver inherits no profiles or devices, sets
`security.privileged=false` explicitly, and never attaches a host network
interface. It pushes static executables into a disposable container and
deletes it on success or failure. Missing Incus access exits 77 with an
explicit skip; that does not pass the gate.

The buffer test must execute the `SO_RCVBUFFORCE=EPERM` path and verify
the production fallback's buffer. The system-unit case checks tunable
correction, networkd/udev, exact capabilities, descriptor storage across
a kill, re-exec, clean re-creation and shutdown. Execution stops on the
first failed assertion; later assertions are not counted as passed.
Logs and cleanup evidence are under `audit/phase6/incus-<run>/`.

The initial fixture exposed H11's concurrent MAC/activation race:
networkd raised the direct session before udev applied its persistent
MAC, whose write failed with `EBUSY`. The maintainer approved combined
acceptance: the concurrent case allows either persistent assignment or
that documented refusal and requires the active interface to be
preserved; a separate case holds networkd inactive until udev assigns
the persistent MAC while down, then checks activation and stable MAC
across clean re-creation. The latter proves an ordering prerequisite,
not unconditional success with concurrent managers. The daemon's
configured-MAC rules are unchanged. See the precise limitations in
[H11](../../docs/spec/hosts.md#other-network-managers) and the
[verification record](../../audit/PHASE6_VERIFICATION_2026-10-30.md).

For the existing live kernel and process suites, see
[kernel verification](../kernel/README.md) and
[binary verification](../process/README.md).
