# Phase 6 verification, 2026-11-01

Phase 6 is incomplete. Released iphost 0.4.4 fixes the
[anonymous Reply defect](phase6/anonymous-reply-20261101/README.md).
Three live witnesses fail with 0.4.3 and pass with the downloaded registry
release. Upstream, local integration and required-kernel qualification pass.
The specification remains unchanged. Production source `584062d` has completed
the [required matrix](phase6/matrix-20261101T141907Z-2368484/README.md).
It includes kernel-selected inventories, VRF inventory-completion tracking
and checked libc signal calls. Later commits add tests and measurement
infrastructure. The current E27 correction changes session-verification
behavior: a queued-deletion witness fails on the preceding code and passes
with the correction. Repeated models, GNU/musl live suites, three musl Incus
runs and the root sandbox pass. Its required matrix passes all thirteen profiles. Fresh coverage for
0.4.4, the standard-library boundaries and host-adapter cases is 97.27% lines / 90.76%
branches. Common checks, ten native and instrumented seeds, three musl
model runs, GNU live/Incus, manager, task limits and root-systemd pass.
Three musl scenario/Incus repetitions pass. The required matrix passes all
thirteen profiles on frozen signed commit `584062d`.

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
| P3 required kernels | Frozen `584062d` with released iphost 0.4.4 passes five normal, five clock, two IPv6-absent and one missing-driver profiles; publication selections agree and source patches are empty | Preserve the per-target scope; later test-only additions have separate records |
| P4 coverage | Fresh 0.4.4/boundary profiles plus host-adapter cases: 8,434/8,671 lines (97.27%); 1,679/1,850 branches (90.76%). No production exclusions, profile mismatches or saturated regions | Cover 237 lines and 171 branches; enable the completed 100% gate in CI |
| P5 Incus/LXD | The 0.4.4/boundary source passes GNU in 17.79 s and three unprivileged musl cases in 10.71, 19.44 and 20.06 s; all containers deleted | Preserve the recorded Ubuntu 24.04 / 6.8.0-147 scope |
| P6 root sandbox | The 0.4.4/boundary source and the unmodified supplied unit pass in 30.97 s on Ubuntu 24.04 / 6.8.0-147-generic; ROOT_SYSTEMD_RESULT=0 | Other distribution userspaces remain untested |
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

Each frozen 584062d normal guest also passes 19 serial library, 24 Linux,
five review, 62 ordinary binary, three privileged binary and 29 process cases.
The positive client-ID/binding and anonymous Reply cases pass on all five
required kernels with released iphost 0.4.4. All eight
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

The [host-adapter cases](phase6/host-adapter-success-20261101/README.md)
verify capability warnings against effective bits and independent container
expectations, successful host-worker descriptor transfer/withdrawal, and
isolated tunable writes. Ten native/instrumented binary repetitions, three
musl runs, three GNU/musl container repetitions and common gates pass. Seven
production controls and a namespace-fixture control fail. Three further
namespace repetitions per target preserve an enclosing value of 1. All
4,320 mappings remain identical. Coverage reaches 8,434/8,671 lines and
1,679/1,850 branches, leaving 237 lines and 171 branches. The initial count-
guard failure is retained. Live scope is Ubuntu 6.8.0-147; the matrix frozen
at fb0620d is running separately and excludes these later declarations.

The [generic-family cases](phase6/generic-family-recovery-20261101/README.md)
check missing-group refusal, family retention after transport timeout and
live ENOENT cache recovery. Ten native and instrumented seeds, three musl
library runs, three GNU/musl live repetitions and common gates pass. Three
controls fail. All 4,320 mappings remain identical. Coverage reaches
8,431/8,671 lines and 1,677/1,850 branches, leaving 240 lines and 173 branches.
These new live declarations currently have Ubuntu 6.8.0-147 execution scope;
the frozen production matrix retains its separate scope.

The [shared live harness](phase6/shared-live-harness-20261101/README.md)
compiles the same 24 Linux declarations inside the instrumented library;
the external target remains enabled. All 46 serial library cases pass three
repetitions, and the full GNU live collection passes. Ten instrumented
seeds, three musl library runs and common gates pass. Constructor success
and refusal counters now belong to the same library instance. Coverage
reaches 8,429/8,671 lines and 1,676/1,850 branches. All 4,302 common mappings
are identical; two placeholder names become concrete with identical source
regions, and sixteen further instances are added. The production matrix
at 584062d retains its separate scope.

The [startup open-error cases](phase6/startup-open-errors-20261101/README.md)
add direct Runtime and async Service socket refusals to the existing
fixture. Ten native and serial instrumented repetitions, three musl runs
and common gates pass. Four controls reject lost descriptors, changed
errno and panics. All 4,304 mappings remain identical. Constructor success
and refusal counters exist in different compiled instances; the aggregate
remains 97.14% / 90.38%. The fixture now checks eight startup faults.

The [netlink peer cases](phase6/netlink-peer-boundaries-20261101/README.md)
exercise expired transmission, malformed framing and forged replies over
real userspace netlink sockets. Ten native and instrumented seeds, three
musl runs and common gates pass; four fault controls fail. All 4,304
coverage mappings remain identical. The ordinary library has 247 passing
cases and 19 ignored. The new live socket cases run on Ubuntu 6.8.0-147
with GNU/musl; they are not in the frozen 584062d matrix. Coverage reaches
8,423/8,671 lines and 1,672/1,850 branches.

The [service dequeue case](phase6/service-dequeue-shutdown-20261101/README.md)
forces shutdown between dequeue and dispatch using a blocked sender's waker.
A public API case checks store-capacity acknowledgement before convergence
and refusal afterward. Ten native and instrumented seeds, three musl runs
and common gates pass. Five controls fail; the run guard alone can be
bypassed because reconciliation independently refuses shutdown work. The
combined control fails. The library now has 244 ordinary passing cases.
Coverage remains 97.12% / 90.27%; per-instance counters and the unchanged
aggregate are recorded explicitly.

The [runtime boundaries](phase6/runtime-boundaries-20261101/README.md)
add canonical adopted-name, descriptor ownership, shutdown admission and
queued-tunable checks. Ten native and instrumented seeds, three musl
library runs and common checks pass; six controls fail. All 4,302 coverage
mappings remain identical. The library has 242 ordinary passing cases and
19 ignored cases (22 in the instrumented serial profile). Coverage reaches
8,421/8,671 lines and 1,670/1,850 branches; no production code changed.

The [host-worker case](phase6/host-worker-boundaries-20261101/README.md)
adds test-only refusal, completion-ID and descriptor-release checks. Ten
native and instrumented binary repetitions, three musl repetitions and
common checks pass. Five deliberately broken controls fail. Coverage rises
to 8,420/8,671 lines and 1,667/1,850 branches. All 4,302 production source
region mappings are unchanged; one first-executed worker instance gains
branch metadata. The binary has 63 ordinary passing cases and four ignored
privileged cases.

Three 0.4.4 musl host scenario runs pass in 161.71, 162.55 and 160.21 s.
Their paired Incus runs pass in 10.71, 19.44 and 20.06 s. The required
matrix passes all thirteen profiles on frozen 584062d.

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
