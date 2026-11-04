# Live scenario runner

Run the complete host/manager suite on the host kernel:

```sh
tests/docker/run.sh scenarios
```

The runner builds the daemon and Rust integration executable for
`x86_64-unknown-linux-musl`, mounts the checkout read-only at its absolute
path, and uses a disposable privileged Docker container with
`--network none`. It records the command, features, kernel, image ID,
build output and test results under `audit/phase6/scenarios-<run>/`.

Run one host-kernel scale workload at a time, including GNU coverage and
musl scenario runs. Network namespaces share the kernel's ARP neighbour
budget; two concurrent 300-session workloads can exceed it. Provide enough
shared capacity for one workload, or run parallel workloads in separate
QEMU guests with independent kernels. The packet assertions remain unchanged.

Prepare `rs-l2tpd-audit-vm:local` with
`tests/kernel/build-review-image.sh`. It fetches signed Alpine indexes and
packages on the caller, then builds `tests/kernel/Dockerfile.review` with
networking disabled. The image includes iproute2, BusyBox and util-linux.
The runner uses the prepared image; it does not give test containers
external networking. The runner also builds the archived v0.1.5 tag with
its own lockfile in an isolated cache, and records its commit and binary
hash for the interoperability case. Current gating code lives under `tests/`, `tools/` and the repository root.
Keep current summaries and immutable archive links in `audit/VERIFICATION.md`;
full execution records can be archived in Git or retained as CI artifacts.

A libtest filter can select a case while debugging, for example:

```sh
tests/docker/run.sh scenarios vrf_membership
```

The suite covers dual stack, IPv4-only, IPv6-only, sysctl-disabled
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

Production source `c599b1f` passes all thirteen required profiles, three musl
scenario/Incus pairs and the unmodified root-systemd unit. The separate CI
coverage gate reaches 8,582/8,582 merged production lines and 1,844/1,844
condition outcomes. Optional Rocky 9/10 normal and clock profiles pass.
Debian 12 fails older MAC/UP-device rename assumptions; later normal suites
are not reached. See the [current record](../../audit/VERIFICATION.md) for
exact identities, commands and limits.

Released iphost 0.4.4 supplies V12's corrected anonymous Reply validation.
The approved checked-libc signal exception is applied; no nix contribution or
release is required.
The normal suite includes the 300-tunnel/session case. H20 now covers full-MTU frames and 1 MiB transfers over both families,
1500/9000 session MTUs and VRF/no-VRF binding, with sender fragment and
session receive/drop counters. A separate live socket test reads back
T5's options; a child-only seccomp case checks actual option refusals.
The matrix driver runs the complete scenario suite and the separate kernel and
process suites. Its publication and source-identity checks remain independent
acceptance conditions.

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
all Docker invocations use `--network none`. HTML indexes are fetched and
parsed in temporary storage; records retain parsed selections and digests. Kernels and the archived
0.1.5 peer are cached under `target/`. Records include exact artifact
hashes under `audit/phase6/matrix-<run>/`. Missing or changed publication
formats fail closed. The tarball builder accepts and verifies mainline
release candidates; the final matrix uses 7.4-rc1.

Optional Debian/Rocky stock kernels use the maintained
`tests/kernel/fetch-optional.sh` and `tests/kernel/run-optional.sh` helpers.
The complete fresh-record recipe is in [kernel verification](../kernel/README.md#optional-stock-kernels).
Optional kernels extend the record without replacing a required target or
qualifying distribution userspace.

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

H11 checks concurrent persistent-MAC/activation outcomes while preserving
the active interface. A separate case assigns the persistent MAC while down,
then requires stable re-creation. That ordering does not promise persistent
assignment always wins concurrent activation. Configured-MAC fixtures supply
`MACAddressPolicy=none` for both creation names; later manager overrides
remain authoritative. See [H11](../../docs/spec/hosts.md#other-network-managers)
and the [current record](../../audit/VERIFICATION.md).

For the existing live kernel and process suites, see
[kernel verification](../kernel/README.md) and
[binary verification](../process/README.md).
