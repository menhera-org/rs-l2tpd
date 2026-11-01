# Required-kernel matrix, 2026-11-01

The driver returns **MATRIX_RESULT=0**. Initial and final publication checks
select the same five versions; `initial/versions` and `final/versions`
match, as do `initial/mainline` and `final/mainline`. No unpublished Ubuntu
ABI is substituted into the required set.

| Required target | Guest release | Normal scenarios | H16 clock/pause |
|---|---|---|---|
| Ubuntu 24.04, 6.8.0-147.147 | 6.8.0-147-generic | 26 pass, 525.88 s | Pass, 64.50 s |
| Vanilla equivalent | 6.8.12 | 26 pass, 500.67 s | Pass, 64.77 s |
| Ubuntu 26.04, 7.0.0-42.42 | 7.0.0-42-generic | 26 pass, 545.23 s | Pass, 65.20 s |
| Vanilla equivalent | 7.0.14 | 26 pass, 466.16 s | Pass, 64.38 s |
| Mainline | 7.3.0 | 26 pass, 475.12 s | Pass, 64.79 s |

Every normal guest also passes 14 privileged library, 20 Linux, five
kernel-review, 51 ordinary binary, three privileged binary and 28 process
cases. Subprocess fixtures can add their own one-case result lines. The
normal scenarios include all H20 fragmentation combinations and the H17
300-tunnel/session workload. Incus and clock control are separate profiles.

The two mainline IPv6-absent profiles pass their scoped assertion: boot-time
`ipv6.disable=1` (2.99 s) and a kernel built without IPv6 (2.92 s). The stock
Ubuntu 7.0 missing-Ethernet-driver profile passes in 4.68 s. Each guest
returns `MATRIX_GUEST_RESULT=0`; clock profiles also finish the host QMP
controller successfully before the driver can succeed.

## Source and limits

The checkout is frozen at **bdf81b5ccc8fc1b03676c0ab9d41ff4ea2422b88**.
`source.patch` and `final-source.patch` match and are empty. Kernel image,
configuration and module identities and each QEMU command are retained per
profile. Builds use all features and stable x86_64 musl. Cargo build
lengths and archive-transfer throughput are omitted from retained logs.
Guest scenario/clock durations above are execution evidence.

This snapshot includes the later monitor, descriptor, process and index-
reuse assertions absent from the preceding five-target run. It predates
`eeec257`'s tunnel application/cleanup fixes and the November 1 approved
MAC/timing fixture changes. It is **not final qualification** of those
changes or the upcoming streamed inventories. The newer Ubuntu 6.8 manager
results remain separately scoped in the maintainer-decision record.

Per-target errno, notification, cleanup, boot and manager distinctions are
in `docs/kernel-behavior.md`. Broader distributions/architectures remain
unrun; a bare-kernel guest is not proof of another distribution's udev or
networkd behavior.

```sh
tests/docker/run.sh matrix required
```
