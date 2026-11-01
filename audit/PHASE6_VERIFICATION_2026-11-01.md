# Phase 6 verification, 2026-11-01

Phase 6 is incomplete. Production source `2051827` has completed the
[required matrix](phase6/matrix-20261101T075850Z-1691154/README.md).
It includes kernel-selected inventories, VRF inventory-completion tracking
and checked libc signal calls. Later commits add tests and measurement
infrastructure; they do not change shipping behavior.

The latest test harness is `5741e89`. Its
[record](phase6/shared-rule-harness-20261101/README.md) identifies the source,
commands, failures, isolation changes and current coverage. Earlier packages
and the [October 31 record](PHASE6_VERIFICATION_2026-10-31.md) retain their
original execution scope.

## Gate status

| Requirement | Executed evidence | Still required |
|---|---|---|
| P1 rule/source maps | Current strict common checks pass: 333 active rules cited, 43 kernel facts classified/cited. The ten-run CI qualification remains retained | Maintain enforcement; declarations do not establish complete clause proof |
| P2 scenarios | All 27 normal cases pass on each of five required kernels, including H20, H17 and the new VRF reload regression. Three current musl host suites also pass | Complete clause, history and resource/event-cost proof |
| P3 required kernels | Frozen `2051827` passes five normal, five clock, two IPv6-absent and one missing-driver profiles; publication selections agree | Later test-only additions have separate qualification; repeat after relevant production changes |
| P4 coverage | 8,354/8,660 lines (96.47%); 1,642/1,848 branches (88.85%). No production exclusions, profile mismatches or saturated regions | Cover 306 lines and 206 branches; enable the completed 100% gate in CI |
| P5 Incus/LXD | Cache-fix source passes the full GNU case in 19.85 s and three unprivileged musl cases in 18.82, 9.43 and 20.28 s | Preserve the recorded userspace/kernel scope; repeat after relevant production changes |
| P6 root sandbox | The unmodified supplied unit passes in 29.97 s on Ubuntu 24.04 / 6.8.0-147-generic; ROOT_SYSTEMD_RESULT=0 | Other distribution userspaces remain untested |
| P7 docs/CI | Per-target behavior and approved limitations are documented. Strict flags and bounded workflow budgets remain active | Final consistent-source proof and complete coverage enforcement |

The [VRF cache record](phase6/vrf-inventory-state-20261101/README.md)
contains the host scenario, Incus and root-systemd results above. Its three
normal musl suites pass in 162.48, 159.70 and 162.57 s. The serialized GNU
normal suite passes in 159.06 s with zero unrelated-event queries.

## Required-kernel snapshot

Initial and final publication checks select the same five stable targets:

| Package/version | Guest release | Normal scenarios | H16 clock/pause |
|---|---|---|---|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 27 pass | pass |
| Vanilla 6.8.12 | 6.8.12 | 27 pass | pass |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 27 pass | pass |
| Vanilla 7.0.14 | 7.0.14 | 27 pass | pass |
| Mainline 7.3 | 7.3.0 | 27 pass | pass |

Each frozen normal guest also passes 14 serial library, 23 Linux, five review,
58 ordinary binary, three privileged binary and 28 process cases. All eight
daemon setup faults pass. Mainline passes both IPv6-absent boots; Ubuntu 7.0
passes missing-Ethernet-driver degradation and recovery. All thirteen profiles
have zero result markers, and both tracked-source patches are empty.

The matrix includes the selected link/address inventory checks and the live
reload that adds a binding to an already-known parent VRF. Existing siblings
must be discovered so their address changes reconnect only the VRF-bound
tunnel. The source and failure controls are retained in the
[selected-inventory](phase6/event-inventory-cost-20261101/README.md) and
[VRF completion](phase6/vrf-inventory-state-20261101/README.md) records.

[Per-target behavior](../docs/kernel-behavior.md) records precise errno,
namespace-notification, lifetime, boot and manager differences. The first
matrix attempt stopped during publication resolution because its curl
wrapper failed TLS; the successful run uses the system curl.
Broader distributions and live non-x86 architectures remain unrun.
Bare-kernel guests establish no per-distribution udev/networkd or Incus result.

## Current coverage evidence

The shared harness compiles the same 88 public rule declarations into both
the library and external target. Private cases and public behavior therefore
exercise the same library instantiations. The declaration lists compare
exactly; line and branch denominators are unchanged.

The ordinary library passes 226 cases. Three child-launching cases join the
existing isolated profile to avoid global logger and fake lifetime
interference; all 17 serial cases pass three GNU and three musl runs.
Ten ordinary and ten instrumented seeded repetitions, three musl runs,
cross-target compile checks and final common checks pass.

The [stream-fault record](phase6/coverage-stream-fault-20261101/README.md)
checks that the daemon still returns the original stdin-probe error while
LLVM writes its profile. The old broad-fcntl control fails the new profile
check. [Resolver validation](phase6/resolver-validation-20261101/README.md)
checks link scopes, explicit identities and MAC-query fallback;
[adapter drop](phase6/resolver-drop-20261101/README.md) checks per-owner cleanup.
Their incorrect-scope, lost-identity and foreign-job controls fail.

Both [public service constructors](phase6/service-constructors-20261101/README.md)
also pass live creation, repeated readiness, late-capacity refusal and complete
cleanup. Three GNU and three musl runs pass all 24 Linux cases. Their
ignored-configuration control fails. Those later counts are separate from
the frozen matrix's 23 Linux and 14 serial library cases.

Test-only bodies remain excluded under the approved production scope while
their tests execute. The mapping catalog has three placeholder-to-concrete
replacements with identical shapes and one added default-trait instantiation.
No counter mismatch or saturation is hidden. ARM64, RISC-V64 and PowerPC64LE
results remain compile checks only.

## Decisions, interference and remaining work

The maintainer-approved decisions are applied:

- H11 documents later udev authority and uses an explicit MAC policy for the
  configured-MAC fixture; concurrent and ordered persistent-MAC cases remain.
- G23 counts current dependency state, requires streamed inventories and releases
  state after its final dependency. Completed inventories must not commit
  partial evidence.
- H6 keeps exact fake-clock retry deadlines and distinguishes them from observed
  live completion within the existing fixture timeout.
- Broken nix signal wrappers use the documented checked libc exception.
  Contributing to nix or waiting for its release is not a daemon gate.

The [maintainer decisions](phase6/maintainer-decisions-20261101/README.md) and
[libc signal record](phase6/libc-signals-20261101/README.md) give the contracts,
sources, original failures and GNU/musl controls.

Host-kernel request-count windows run without overlapping matching-ID deletions:
the controlled K41 witness reproduces legitimate identity queries across
namespaces. The separate
[neighbour-pressure control](phase6/neighbour-pressure-20261101/README.md)
also requires serial scale workloads sharing one kernel. Independent QEMU
kernels isolate both effects; the packet and zero-query assertions remain.

Production `2051827` passes both jobs in
[CI run 41286660781](https://github.com/menhera-org/rs-l2tpd/actions/runs/41286660781).
The later public-constructor test head `8844ed7` passes both jobs in
[run 41290353555](https://github.com/menhera-org/rs-l2tpd/actions/runs/41290353555).
The shared harness has passing local qualification; its new CI run is not yet
claimed here.

Full clause/history and resource/event-cost proof, the remaining coverage
paths, and final CI enforcement still require work. No Phase 6 completion
or Phase 7 release is claimed.
