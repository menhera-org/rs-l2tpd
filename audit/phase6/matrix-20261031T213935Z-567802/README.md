# Required-kernel refresh: all profiles pass

`tests/docker/run.sh matrix required` returns `MATRIX_RESULT=0`.
The driver resolves the published target set before and after testing;
`initial/versions` and `final/versions` match. Ubuntu 6.8.0-148.148 and
6.8.0-149.149 are not substituted for the published 6.8.0-147.147 target.

| Target | Normal scenarios | H16 clock/pause |
|---|---|---|
| Ubuntu 24.04, 6.8.0-147.147 / 6.8.0-147-generic | 26 pass, 542.06 s | Pass, 64.74 s |
| Vanilla 6.8.12 | 26 pass, 474.47 s | Pass, 64.30 s |
| Ubuntu 26.04, 7.0.0-42.42 / 7.0.0-42-generic | 26 pass, 492.10 s | Pass, 64.50 s |
| Vanilla 7.0.14 | 26 pass, 459.38 s | Pass, 64.27 s |
| Mainline 7.3 / release 7.3.0 | 26 pass, 446.56 s | Pass, 64.40 s |

Every normal guest also passes twelve live library cases, nineteen Linux
cases (including all seventeen shared conformance cases), five review cases,
fifty ordinary binary cases, three privileged binary cases and all 27
process cases. Eight file/stream fault paths execute in separate binary
invocations. H20 includes all eight MTU/family/VRF combinations. H17 starts
both 300-tunnel/300-session daemons. Real-manager and clock declarations are
outside the normal scenario profile.

Each separate clock profile records wall-clock steps and a controller-confirmed
QMP pause/resume. Mainline's `ipv6.disable=1` and `CONFIG_IPV6=n` boots each
pass their one scoped case. Ubuntu 7.0's missing-Ethernet-driver profile
passes degradation and recovery. Every guest has explicit conformance,
scenario and guest-result markers. Stock Ubuntu 7.0 uses the documented
cold-boot `kho=off` setting; this suite does not test kexec handover.

## Tested source and ownership behavior

The matrix ran in an isolated checkout. `revision` is
`3e3b921e83020ed17a50335ed96e2f272f2d94ad`; `source.patch` adds the exact
I/O-fault package subsequently committed as
`6f832c453479b12d16d68a69c763f26625a3f401`. It matches that package's
recorded patch. `final-source.patch` matches the initial patch, so later
main-checkout work did not change this matrix. The initial source and final
publication comparisons pass in `scope-check.log`.

The strengthened shared cases establish both families' ownership behavior
on every target: closed local handles return EBADF for five socket
operations while external descriptors can retain the tunnel; unregistered
adoption returns ENODEV; an external descriptor of an unregistered socket
reserves its connection ID until the last close. Identifier reclamation is
eventual. The fake backend now matches these live observations.

The approved empty-IPv6-VRF distinction remains: vanilla 6.8.12 returns
ENETUNREACH; the other four targets return EADDRNOTAVAIL. The older four
kernels deliver colliding deletion notices across namespaces; mainline 7.3
confines them. All local foreign-collision objects survive the review probe.
The [kernel behavior page](../../../docs/kernel-behavior.md) documents these
differences, source boundaries and the limits of each profile.

## Limits

This record proves this source and fixture set on the resolved versions.
Later monitor, process/service and inheritance test additions have separate
Ubuntu 6.8 runs and are absent here. No system-container or real-systemd
result is inferred for other kernels. H11/P5 remains unresolved by the
[staged configured-MAC override](../staged-mac-override-20261031/README.md).
Final consistent-source qualification, complete clause/resource/event-cost
proof and 100% production coverage remain open. Cargo build durations are
omitted from retained logs; scenario and clock measurements are retained.

```sh
tests/docker/run.sh matrix required
cmp initial/versions final/versions
cmp source.patch final-source.patch
```
