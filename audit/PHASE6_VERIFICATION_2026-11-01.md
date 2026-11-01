# Phase 6 verification, 2026-11-01

Phase 6 is incomplete. Released iphost 0.4.4 fixes the
[anonymous Reply defect](phase6/anonymous-reply-20261101/README.md).
Three live witnesses fail with 0.4.3 and pass with the downloaded registry
release. Upstream qualification and publication pass; full downstream
qualification is in progress. The specification remains unchanged. Production source `11bef84` has completed the
[required matrix](phase6/matrix-20261101T115808Z-2050597/README.md).
It includes kernel-selected inventories, VRF inventory-completion tracking
and checked libc signal calls. Later commits add tests and measurement
infrastructure. The current E27 correction changes session-verification
behavior: a queued-deletion witness fails on the preceding code and passes
with the correction. Repeated models, GNU/musl live suites, three musl Incus
runs and the root sandbox pass. Its required matrix passes all thirteen profiles. Fresh coverage for
0.4.4 and the standard-library boundary changes is 97.06% lines / 90.05%
branches. Common checks, ten native and instrumented seeds, three musl
model runs, GNU live/Incus, manager, task limits and root-systemd pass.
Three musl scenario/Incus repetitions are running; the new required matrix
remains open.

The current [E27 correction](phase6/event-verification-20261101/README.md)
is committed as `11bef84`, based on `4881c32` plus its retained source patch.
The [serial startup harness](phase6/shared-startup-harness-20261101/README.md)
adds test-only qualification. The [worker-pressure case](phase6/worker-pressure-reporting-20261101/README.md)
adds complete warning/recovery episodes. The [input boundaries](phase6/input-boundaries-20261101/README.md)
add tunable and empty-path cases. The [blocking transport cases](phase6/blocking-transport-20261101/README.md)
add queue/reply failure checks. The [resolver wire case](phase6/resolver-wire-identity-20261101/README.md)
adds live identity/binding checks and the latest merged coverage. The preceding
[model controls](phase6/model-controls-20261101/README.md) preserve their
original test-only scope. The preceding
[fallback case](phase6/family-fallback-20261101/README.md) preserves sessions
through peer-family changes. The
[descriptor record](phase6/descriptor-inheritance-20261101/README.md), the
[session races](phase6/session-races-20261101/README.md) and the
[shared harness](phase6/shared-rule-harness-20261101/README.md) identify
the source, commands, failures, controls and current coverage. Earlier packages
and the [October 31 record](PHASE6_VERIFICATION_2026-10-31.md) retain their
original execution scope.

## Gate status

| Requirement | Executed evidence | Still required |
|---|---|---|
| P1 rule/source maps | Current strict common checks pass: 333 active rules cited, 43 kernel facts classified/cited. The ten-run CI qualification remains retained | Maintain enforcement; declarations do not establish complete clause proof |
| P2 scenarios | All 27 normal cases pass on each of five required kernels, including H20, H17 and the new VRF reload regression. Three current musl host suites also pass | Complete clause, history and resource/event-cost proof |
| P3 required kernels | Frozen `11bef84` passes five normal, five clock, two IPv6-absent and one missing-driver profiles; publication selections agree | Requalify the released iphost 0.4.4 integration and boundary changes; later test-only additions have separate records |
| P4 coverage | Fresh 0.4.4/boundary profiles: 8,416/8,671 lines (97.06%); 1,666/1,850 branches (90.05%). No production exclusions, profile mismatches or saturated regions | Cover 255 lines and 184 branches; enable the completed 100% gate in CI |
| P5 Incus/LXD | E27 source passes the full GNU case in 17.20 s and three unprivileged musl cases in 29.47, 24.78 and 24.53 s; all containers deleted | Preserve the recorded Ubuntu 24.04 / 6.8.0-147 scope |
| P6 root sandbox | E27 source and the unmodified supplied unit pass in 30.93 s on Ubuntu 24.04 / 6.8.0-147-generic; ROOT_SYSTEMD_RESULT=0 | Other distribution userspaces remain untested |
| P7 docs/CI | Per-target behavior and approved limitations are documented. Strict flags and bounded workflow budgets remain active | Final consistent-source proof and complete coverage enforcement |

The [E27 record](phase6/event-verification-20261101/README.md) contains the
current local results above. Its three normal musl suites pass in 162.11,
166.26 and 163.51 s; GNU passes in 158.14 s. The real user-manager case and
three GNU task-limit runs pass. Earlier cache results retain their original
source scope in the [VRF record](phase6/vrf-inventory-state-20261101/README.md).

## Required-kernel snapshot

Initial and final publication checks select the same five stable targets:

| Package/version | Guest release | Normal scenarios | H16 clock/pause |
|---|---|---|---|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 27 pass | pass |
| Vanilla 6.8.12 | 6.8.12 | 27 pass | pass |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 27 pass | pass |
| Vanilla 7.0.14 | 7.0.14 | 27 pass | pass |
| Mainline 7.3 | 7.3.0 | 27 pass | pass |

Each frozen normal guest also passes 17 serial library, 24 Linux, five review,
59 ordinary binary, three privileged binary and 29 process cases. All eight
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
earlier matrix attempt's publication failure remains in its own record.
Broader distributions and live non-x86 architectures remain unrun.
Bare-kernel guests establish no per-distribution udev/networkd or Incus result.

## Current coverage evidence

The [0.4.4 integration](phase6/iphost044-integration-20261101/README.md)
uses a fresh collector after the production boundary changes. It includes
all native tests, ten distinct instrumented seeds, GNU live/Incus, the
actual user manager and three task-limit runs. It reports 8,416/8,671 lines
and 1,666/1,850 branches. A test-only barrier budget correction preserves
all 4,302 production coverage mappings. Four boundary controls and the
invalid-barrier-data control fail as intended. The Rust 1.89 and three
additional musl architecture compile checks pass.

The following earlier packages retain their original source scope.

The [startup harness](phase6/shared-startup-harness-20261101/README.md)
reuses three subprocess declarations in the instrumented serial library
profile. Ordinary external startup tests still run. Ten final model seeds,
ten instrumented repetitions, GNU/musl qualification and common checks pass;
the incorrect child-name control fails all three cases. Failed parallel and
child-selection attempts are retained and their profiles quarantined. The
fresh report includes E27 live, Incus, manager and task-limit profiles and
now leaves 259 lines and 187 branches after the worker-pressure, input
boundary, blocking transport and resolver wire cases. The latter passes
three GNU and three musl live runs on Ubuntu 6.8.0-147; its other required
kernel targets remain unrun. The ordinary binary has 61 passing cases and four ignored
privileged cases. Faulty writer guards run only in networkless containers. Generic-instance catalog changes are
listed explicitly; production source regions remain unchanged by this harness.

The shared harness compiles the same 94 public rule declarations into both
the library and external target. Private cases and public behavior therefore
exercise the same library instantiations. The declaration lists compare
exactly. The corrected production source has 8,663 executable lines and
1,850 branches; these denominators differ from the preceding implementation.

The ordinary library passes 237 cases after the blocking transport and E27
additions and earlier
[staging-bound cases](phase6/staging-bounds-20261101/README.md), which preserve
original refusals and test the seventh/eighth-name boundary. Three child-launching cases join the
existing isolated profile to avoid global logger and fake lifetime
interference in the earlier shared-rule record. Its 17 serial cases pass
three GNU and three musl runs. The later resolver wire case raises the
ordinary serial library set to 18; three coverage-only startup cases raise
the instrumented set to 21.
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
The [session races](phase6/session-races-20261101/README.md) add five callback
instantiations while preserving all preceding mappings. Their three broken
controls fail; ten ordinary and ten instrumented repetitions, three musl
service runs and common checks pass. The
[inheritance cases](phase6/descriptor-inheritance-20261101/README.md) add eleven
subprocess checks for malformed announcements and descriptor cleanup fallback.
Three faulty controls fail; repeated GNU/musl runs and common checks pass.
Previously unexecuted binary-test instances now expose branch records with
unchanged source regions. The earlier fallback case compares both catalogs
at 89 entries; the current E27 additions raise that shared set to 94. No counter mismatch
or saturation is hidden. The three model cases additionally cover VRF/stale
address selection, unregistered socket lifetimes and MAC rules, with four
faulty controls and repeated GNU/musl checks. ARM64, RISC-V64 and PowerPC64LE
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
The later descriptor tests `2cfe6e8` pass CI in
[run 41297940211](https://github.com/menhera-org/rs-l2tpd/actions/runs/41297940211).

Full clause/history and resource/event-cost proof, the remaining coverage
paths, and final CI enforcement still require work. No Phase 6 completion
or Phase 7 release is claimed.
