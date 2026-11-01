# Phase 6 verification, 2026-11-01

Phase 6 is incomplete. The current [reply correction](phase6/netlink-reply-state-20261101/README.md)
rejects malformed signed completion statuses without overflow, preserving
valid errno, sequence filtering, interruption and first-error precedence.
Two synthetic debug witnesses fail three GNU and three musl repetitions;
eight corrected cases pass three repetitions per target. Eight isolated
broken controls fail. These synthetic cases establish no live malformed
kernel reply or release-mode daemon panic.

Ten native and instrumented model/rule/service/startup repetitions, three
musl model runs, common checks, Rust 1.89 and three additional musl
architecture compile checks pass. GNU live/Incus, user manager, three thread-
limit runs and the root sandbox pass. Three shipped-musl scenario/Incus
pairs pass. Local live scope is Ubuntu 6.8.0-147. Fresh coverage is 98.01%
lines / 92.01% branches, leaving 173 lines and 148 branches. Request handling
now covers 156/156 lines and 34/34 branches; socket handling covers
103/103 lines and 12/12 branches.

The [2d5ae45 matrix](phase6/matrix-20261101T205406Z-3041229/README.md)
passes all thirteen profiles with the production reply correction and
released iphost 0.4.4. Publication selections agree and source patches are
empty. Controlled request I/O and synthetic socket-error cases run in its
22 serial library cases. Later test-only lifetime, policy and resolver
assertions retain their separate qualification. Earlier
[anonymous Reply](phase6/anonymous-reply-20261101/README.md),
[E27](phase6/event-verification-20261101/README.md) and other packages below
retain their original source scope. The specification is unchanged.

The later [host qualification](phase6/current-head-qualification-20261101/README.md)
freezes code at signed 1b3d876. GNU live and GNU Incus pass, followed by
three stable-musl scenario/Incus pairs. All containers are deleted. Unique
profile transport fixes a rejected directory-reuse attempt and preserves
274 earlier exports. This adds no other kernel/userspace scope.

The refreshed [sandbox record](phase6/final-sandbox-20261101/README.md)
freezes signed code 419c9b1. Three GNU manager and task-limit repetitions
pass; the unmodified root system unit passes in 26.72 s on Ubuntu
24.04 / 6.8.0-147. All transient units and containers are gone.

**Publication changed before pause:** mainline is now 7.4-rc1. Its source
archive is verified and cached, but build/source review/live qualification
are pending. P3 is open again. The [RC record](phase6/mainline-rc-20261101/README.md)
retains parser tests and actual publication documents; earlier 7.3 results
do not qualify the new target.

## Gate status

| Requirement | Executed evidence | Still required |
|---|---|---|
| P1 rule/source maps | Current strict common checks pass: 333 active rules cited, 43 kernel facts classified/cited. The ten-run CI qualification remains retained | Maintain enforcement; declarations do not establish complete clause proof |
| P2 scenarios | Frozen 2d5ae45 passes 27 normal cases on every required kernel; the corrected reply source also passes three shipped-musl suites locally | Complete clause/history/resource/event-cost proof |
| P3 required kernels | Frozen 2d5ae45 passed thirteen profiles for the former 7.3 snapshot. The 23:11 publication recheck selects untested 7.4-rc1; the four other targets are unchanged | Build/review 7.4-rc1 and run its normal, clock and IPv6-absent profiles; refresh the full required set |
| P4 coverage | PID-directory ownership profiles: 8,514/8,687 lines (98.01%); 1,704/1,852 branches (92.01%). No production exclusions, profile mismatches or saturated regions | Cover 173 lines and 148 branches; enable the completed 100% gate in CI |
| P5 Incus/LXD | Signed 1b3d876 passes GNU in 17.19 s and three unprivileged musl cases in 24.81, 17.88 and 16.02 s; containers deleted | Preserve the recorded Ubuntu 24.04 / 6.8.0-147 scope |
| P6 root sandbox | Signed 419c9b1 and the unmodified supplied unit pass in 26.72 s on Ubuntu 24.04 / 6.8.0-147-generic; ROOT_SYSTEMD_RESULT=0 | Other distribution userspaces remain untested |
| P7 docs/CI | Per-target behavior and approved limitations are documented. Strict flags and bounded workflow budgets remain active | Final consistent-source proof and complete coverage enforcement |

The earlier [E27 record](phase6/event-verification-20261101/README.md) retains
its original local results. Its three normal musl suites pass in 162.11,
166.26 and 163.51 s; GNU passes in 158.14 s. The real user-manager case and
three GNU task-limit runs pass. Earlier cache results retain their original
source scope in the [VRF record](phase6/vrf-inventory-state-20261101/README.md).

## Required-kernel snapshot

The completed 2d5ae45 matrix's initial and final publication checks select
the same five stable targets. This snapshot includes the reply correction:

| Package/version | Guest release | Normal scenarios | H16 clock/pause |
|---|---|---|---|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 27 pass | pass |
| Vanilla 6.8.12 | 6.8.12 | 27 pass | pass |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 27 pass | pass |
| Vanilla 7.0.14 | 7.0.14 | 27 pass | pass |
| Mainline 7.3 | 7.3.0 | 27 pass | pass |

Each frozen 2d5ae45 normal guest also passes 22 serial library, 24 Linux,
five review, 65 ordinary binary, three privileged binary and 29 process cases.
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

The [directory-owner record](phase6/pid-directory-owner-20261101/README.md)
checks readable foreign-owned directories, allowing the ownership guard to
run. Three GNU/musl repetitions and a reversed-comparison control qualify
it. The earlier five-kernel snapshot passes ordinary CLI units and three
selected filesystem cases. Coverage reaches 8,514/8,687 lines and 1,704/1,852
branches; all 4,327 production mappings remain identical. Mainline 7.4-rc1
is outside this record's live scope.

The [PID-file refusal record](phase6/pidfile-inspection-errors-20261101/README.md)
adds creation EIO, uninspectable cleanup and metadata-error propagation.
Ten native/instrumented and three musl repetitions now include ordinary CLI
units; five controls fail. Corrected fixtures cover the musl legacy metadata
syscall. The CLI-only guest profile passes all 65 ordinary tests on each of
the completed matrix's five kernels, with five privileged cases ignored.
Marker checks reject every missing result. Coverage reaches 8,510/8,687
lines and 1,703/1,852 branches; all 4,327 production mappings remain identical.
The complete thirteen-profile matrix retains its separate frozen source.

The [custom-resolver default record](phase6/resolver-default-capacity-20261101/README.md)
polls active custom-resolver watches during the existing four 300-watch
histories. The default hook must open no false worker-pressure episodes;
all history cleanup assertions remain. Ten native/instrumented and three
musl model runs, common checks and a failing pressure control pass.
Coverage reaches 8,503/8,687 lines and 1,702/1,852 branches; all 4,327
production mappings remain identical. No new live scope is claimed.

The [deletion, completion and parser record](phase6/deletion-and-parser-20261101/README.md)
adds confirmed-absence reporting, session recovery after L2TP loss, stale
incarnation/deadline completions, foreign address families and the disabled
host helper's no-store withdrawal answer. Ten native/instrumented and three
musl model runs, common checks and six failing controls qualify the final
formatted tests. Coverage reaches 8,500/8,687 lines and 1,702/1,852 branches;
all 4,327 production mappings remain identical. The record distinguishes
controlled helper/fake inputs from live manager and kernel observations.

The [lifetime boundary record](phase6/lifetime-completion-20261101/README.md)
adds unusable/unrelated multicast payloads and a controlled absence reply
after registration release. Ten native/instrumented and three musl model
runs, common checks and three failing controls pass. Coverage reaches
8,487/8,687 lines and 1,699/1,852 branches; all 4,327 production mappings
remain unchanged. These are synthetic cases; no malformed live broadcast
or natural concurrent release through LinuxKernel is claimed.

The [removed-device MAC record](phase6/removed-device-mac-20261101/README.md)
qualifies deferred MAC changes after a device departs. Three reconciliations
finish without a write; one warning identifies the session and skipped
operation. Ten native/instrumented and three musl model runs, common checks
and two deliberately broken controls qualify the test. Coverage reaches
8,484/8,687 lines and 1,697/1,852 branches; all 4,327 production mappings
remain unchanged. This adds fake-policy evidence only.

The [error boundaries](phase6/error-boundaries-20261101/README.md) add
closed-queue admission, either subscription-initializer failure, partial
reader cleanup, reload-spawn EAGAIN and six synthetic socket-error inputs.
Ten native/instrumented and three musl model runs, serial profiles, common
checks and nine failing controls pass. GNU live passes 50 serial library,
24 Linux, five review, three privileged binary, 29 process and 27 normal
cases. All prior 4,319 mappings remain unchanged; eight service caller
instantiations are added. Coverage reaches 8,482/8,687 lines and 1,696/1,852
branches, with complete line/branch coverage of socket.rs. Synthetic errors
establish no natural invalid kernel response. Live scope is Ubuntu 6.8.0-147.

The preceding [reconciler record guards](phase6/reconciler-record-guards-20261101/README.md)
add four cases for already-satisfied names, the direct missing-name helper
boundary, failed child cleanup and unmatched adopted-parent retirement.
Ten native/instrumented and three musl model runs, common checks and five
independent failing controls pass. All 4,319 mappings remain identical.
Coverage reaches 8,474/8,687 lines and 1,695/1,852 branches. These cases add
no per-target live qualification or production change.

The preceding [service queue record](phase6/service-queue-guards-20261101/README.md)
adds stale/current reload, returned admission-slot and background-error
ordering assertions. Ten native/instrumented and three musl model runs,
common gates and three failure controls qualify the final source. Both
generation outcomes run in the same fake-worker instantiation. The report
reaches 8,464/8,687 lines and 1,693/1,852 branches. All prior 4,311 mappings
remain unchanged; eight service instantiations are added by the test callers.
No production code changes or new live manager/kernel scopes are claimed.

The preceding [netlink I/O record](phase6/netlink-io-faults-20261101/README.md) adds
receive/poll failures, interruption, buffer fallback and three accepted real
buffer-force guests. Seven profiles per accepted guest are merged; a reduced-
buffer control fails. Three GNU/musl external Linux repetitions and their
capability-retention controls pass/fail as expected. Serial startup profiles
are also collected. The report reaches 8,462/8,687 lines and 1,692/1,852
branches. All 4,311 production mappings remain identical. Rejected wording,
source-link and marker-prefix attempts are retained and not counted as
qualification. The specification and production code are unchanged.

The preceding [reply correction](phase6/netlink-reply-state-20261101/README.md) records
the malformed-status witnesses, eight passing cases, eight rejected controls
and all local GNU/musl qualifications. Its fresh collector reports
8,456/8,687 lines and 1,687/1,852 branches. No older profiles are merged.
Production changes alter the denominators: 4,243 mappings remain identical,
56 change, 21 disappear and 12 are added, all within request.rs. No production
exclusion, mismatch or saturated region is present. Before/after source
patches agree. The earlier packages below retain their original measurements
and execution scopes.

The [adapter completion](phase6/host-adapter-completion-20261101/README.md)
adds a WouldBlock read fault and requires one tunable-correction warning.
Ten native/instrumented binary repetitions, three musl runs, three GNU/musl
container repetitions, namespace checks and common gates pass. Each live
ordinary log verifies all seven barrier faults. The read-retry control
fails its Rust assertion; the muted-warning control passes Rust but fails
the required output count. An incomplete preliminary command is retained
and not counted. All 4,320 mappings remain identical. caps.rs, fdstore.rs
and tunable.rs each have complete line/branch coverage. The overall report
reaches 8,435/8,671 lines and 1,680/1,850 branches: 236 lines and 170 branches
remain. Live scope is Ubuntu 6.8.0-147; the fb0620d matrix runs separately.

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
