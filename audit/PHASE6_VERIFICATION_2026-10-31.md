# Phase 6 verification, 2026-10-31

Phase 6 is not complete. This record extends
[the October 30 record](PHASE6_VERIFICATION_2026-10-30.md).
Strict CI map flags were enabled after the ten-run qualification recorded
below; the updated strict workflow also passed. The maintainer approved the K26/K34
kernel distinction on 2026-10-31, and the correction is applied. The
previously approved evidence-map and H11 MAC decisions remain in force.

| Gate/package | Current evidence | Remaining work |
|---|---|---|
| P1 source link | Strict local and CI passes: 43 facts, 37 production-cited and six classified; no uncited functions. Ten CI repetitions passed | Maintain strict enforcement as sources change |
| P1 rule map | Strict local and CI passes: 343 total / 333 active / 333 cited / zero missing | Declaration traceability does not establish clause coverage |
| P2 scenarios | All 26 normal scenarios pass in each of ten Ubuntu CI guests; H16 has passing required-kernel records | Relevant-event CPU cost, full resource/history proof and remaining clauses; investigate the separate vanilla 7.0.14 capture failure |
| P3 matrix | Four normal profiles pass in the full refresh; the vanilla 7.0.14 fixture failure is corrected and its targeted full normal/clock rerun passes | Final consistent-source five-target driver result; complete P2/delegated proof |
| P4 coverage | Approved production scope: merged GNU report 92.72% lines / 80.03% branches, including closed handles, lifetime/startup/process failures, live adoption, real user manager and full Incus case; no production exclusions | 610 missing lines / 351 branches; add meaningful cases and remaining profiles to reach 100% |
| P5 Incus | Current unmodified musl full case passes, including manager race/ordered policy/store/re-exec; instrumented GNU full case exports seven daemon profiles | Repeat if relevant source changes; retain documented MAC limitations |
| P6 root sandbox | Current unmodified musl full root-systemd case passes on Ubuntu 6.8.0-147, without drop-ins | Repeat after relevant source changes; other distribution userspaces remain untested |
| P7 docs/CI | Ten seeded CI repetitions and the updated strict workflow pass on their first attempts; regular CI retains one full live guest | Complete verification and coverage enforcement remain open |

Current P1/ordinary/warning checks are in
[deadline-index-20261031](phase6/deadline-index-20261031/README.md). Lifetime
indexing evidence is in
[lifetime-index-20261031](phase6/lifetime-index-20261031/README.md). Earlier
H17 scale/storage evidence is in
[H17-20261031](phase6/H17-20261031/README.md). Clock evidence is in
[H16-20261031](phase6/H16-20261031/README.md). H15/report-fix evidence is in
[H15-20261031](phase6/H15-20261031/README.md). Earlier readiness-fix logs are in
[ready-signal-race-20261031](phase6/ready-signal-race-20261031/README.md).
The record names exact commands, features, kernel releases, counts and
scope. Test durations are retained; host allocation details and elapsed
build durations are omitted.

## Required kernels and P3

The published candidates resolved on the run date are:

| Target | Version | Executed evidence |
|---|---|---|
| Ubuntu 24.04 | 6.8.0-147.147 / 6.8.0-147-generic | Fresh implemented profile and H20 passed; empty-VRF errno 99 |
| Vanilla equivalent | 6.8.12 | Fresh implemented profile and H20 passed after approved distinction; errno 101 |
| Ubuntu 26.04 | 7.0.0-42.42 / 7.0.0-42-generic | Fresh implemented profile and H20 passed, KHO disabled for cold boot; errno 99 |
| Vanilla equivalent | 7.0.14 | Fresh implemented profile and H20 passed; errno 99 |
| Mainline | 7.3 / guest release 7.3.0 | Fresh implemented profile and H20 passed; errno 99; namespace-local deletion notifications |
| Extra mainline boots | ipv6.disable=1 and CONFIG_IPV6=n | One H4/T4 case passed in each scoped boot |

The first required driver correctly returned MATRIX_RESULT=1. Published
target versions were identical at its beginning/end. Its records are in
[matrix-20261031T062607Z-3496031](phase6/matrix-20261031T062607Z-3496031/command.log).
The fixed harness subsequently proved the omitted release-pocket fetch
and built-in nlmon path. The driver and run-by-run scope are documented
in [P3_MATRIX_DRIVER_2026-10-31.md](phase6/P3_MATRIX_DRIVER_2026-10-31.md).
The optional broader vanilla range was not run.

### Approved K26/K34 kernel distinction

Vanilla 6.8.12 returns **ENETUNREACH (101)** when connecting to an IPv6
peer through an empty VRF without a usable source or route. Ubuntu's
patched 6.8 kernel and the other verified newer kernels return
**EADDRNOTAVAIL (99)**. The versioned source comparison shows differing
L3-domain-aware source-selection paths.

The maintainer approved documenting that distinction on 2026-10-31.
The reviewed [patch](phase6/kernel-contract-20261031/proposed.patch) is
applied to K26/K34, T16 and the shared conformance case; only those two
precise refusals are accepted and the actual errno is recorded. Both
already receive the same transient handling, so no production behavior
changes. The decision was required by Phase 6's “Never weaken a rule to
make a gate pass” instruction and is now resolved.
[Source comparison, original failure and fresh checks](phase6/kernel-contract-20261031/README.md).

### Guest boot-memory diagnosis

The first Ubuntu 26.04 fixed-code guest panicked while unpacking its
initramfs, before tests executed. Controlled boots traced the reservation
to default-enabled kexec handover (KHO) scratch memory. Enabling KHO with
fixed scratch sizes reproduces the OOM; disabling it with the same sizes
and layout setting boots successfully. Three further KHO-off boots pass
with address randomization enabled. Exact cause of the original physical
layout difference is not claimed.

The helper now adds `kho=off` only when the supplied stock config enables
KHO by default, preserving the stock image/modules/config and 2 GiB
memory. This cold-boot profile never tests kernel kexec; daemon execve
restart is independent. [All eight diagnostic boots, source and
reproducer](phase6/boot-memory-20261031/README.md) are retained, including
the expected failed control. Those probes are not conformance passes.

The fresh consistent-source matrix is
[matrix-20261031T071523Z-3533819](phase6/matrix-20261031T071523Z-3533819/command.log).
[Required-kernel behavior](../docs/kernel-behavior.md) documents every
required target, active K fact, observed difference and proof limitation.
The driver returned MATRIX_RESULT=0 with all normal and scoped result
markers zero, unchanged target versions and unchanged tested source
state. All five normal profiles used identical executable identities.
P2 completeness and the other phase gates remain separate.

## Readiness/signal race fixed

The Ubuntu 26.04 H8 case saw readiness, sent SIGHUP immediately, and
never received reload completion. The daemon enabled signal acceptance
after announcing readiness; the collector could discard that signal
under its pre-readiness rule. Signal acceptance now precedes the external
announcement after successful convergence.

[The fix record](phase6/ready-signal-race-20261031/README.md) contains:
26 passing host process cases; the passing host H8 case; passing ordinary
all-feature tests, formatting and warning-denied Clippy; strict source
link success and honest strict rule-map failure; and a fixed-code Ubuntu
26.04 guest with 26 process cases and all 18 scenarios passing, including
fragmentation and the 100,000-route tables. This changes no specification.

An [exploratory scale probe](phase6/scale-probe-20261031/README.md) also
passed 300-to-one reload cycles. Descriptors returned from 314 to 15.
Its limits are explicit: it is not yet the H17/G23 Rust scenario or a
proof of all resource/history bounds.

## H15 degradation and host-defect reporting

[H15's record](phase6/H15-20261031/README.md) adds four live capability/netlink
scenarios and a stock-kernel guest with the Ethernet driver genuinely
unavailable until explicitly loaded inside that guest. The final source
passes all 22 host scenarios and the one scoped guest case. It also passes
ordinary tests, Clippy and strict source links. Strict rule-map citations
improve from 263 to 271, leaving 62 uncited active rules.

The cases found and fixed warning-level reports for missing pseudowire
support and refused resolver initialization, a missing errno name in
propagated startup I/O errors, and suppression of an error after a preceding
transient warning. Repeated retries stay quiet; one severity promotion is
allowed per episode. Fake tests retain transient allocation severity and
exercise mixed-error recovery; live cases prove real kernel refusals.

These report corrections postdate the five-target matrix above, which
retains its original 18-case scope. The expanded suite/current binary still
needs a complete latest-target run. No full Phase 6 gate is closed merely
by adding a test citation.

## H16 clocks/pause and DHCPv6 low-port range

[H16's record](phase6/H16-20261031/README.md) proves one-second retries
and thirty-second wire DNS refreshes across forward/backward wall-clock
steps and a QMP-confirmed three-second pause. It passes on all five required
kernels, with three mainline repetitions. Post-resume address/name events,
route-only retry recovery, stable sessions, bidirectional frames and cleanup
are asserted. QMP pause is a suspend stand-in; physical S3 is not claimed.
The matrix driver now includes this scoped profile on every target.

The strengthened H15 capability case also proves real DHCPv6 traffic from
UDP port 546 without CAP_NET_BIND_SERVICE when the namespace's
unprivileged range starts at zero. The final 22-case host regression,
ordinary tests, Clippy and strict source links pass; strict rule-map coverage
is now 273 cited / 60 missing. Full H17 and the other remaining gates
remain open.

## H17 live scale and retained storage

[The H17 package](phase6/H17-20261031/README.md) adds fresh 300-entry
readiness, exact live object counts, frames both ways through all 300
sessions, three 300-to-one reload cycles and descriptor checks. An unchanged
300-entry reload issues 600 requests; 200 unrelated link events issue zero.
The extended nlmon observer counts both rtnetlink and generic netlink and
passes live positive controls with no loss. RSS envelopes are finite
regression guards, not complete allocation proofs.

Direct regressions found and fixed socket and registration maps retaining
hundreds of slots for one survivor. Geometric shrinking now bounds retained
capacity by current records plus a constant; generation loss discards the
registration allocation. Failed before logs remain beside passing results.
A process-test startup race is fixed by awaiting kernel-open failure after
signal installation before sending SIGTERM. No production signal behavior
changed. The original failure and subsequent repetitions are retained.

The full host profile now passes 23 scenarios. The corrected mainline
normal guest also passes all 23 scenarios, 11 live library cases,
16 kernel cases, five review cases, 38 ordinary binary cases plus three
privileged cases, and 26 process cases. Its original failure was the
scale fixture's ten-second observation timeout during session creation,
not a kernel refusal; the scoped observation waits now allow sixty seconds
per readiness/reload/shutdown. Actual fresh 300-entry readiness is 38.43
seconds for both daemons in TCG. The original failure remains recorded.
At the H17 snapshot, M16/G12's CPU-cost proof remained open because the
lifetime subscriber scanned registrations on RTM_DELLINK. The following
package addresses that part. Discovery/store/history bounds and other remaining clauses
also retain their separate obligations. Rule citations improve to 275,
leaving 58 uncited active rules; strict CI remains off.

## Indexed lifetime deletion handling

[The indexed-lifetime package](phase6/lifetime-index-20261031/README.md)
replaces the registration scan with an ordered map keyed by interface
index and incarnation. Tests preserve old/new incarnations under index
reuse, exact release/disarm, foreign-event rejection and generation loss.
The same 20,000-event workload with 20,000 current registrations takes
12.3 seconds before and 42.7 milliseconds after, in the recorded native
debug profile; timing is diagnostic rather than a new SLA.

Ordinary tests, Clippy, strict source links, 32 live library/kernel/review
cases and all 23 host scenarios pass. The registration HashMap-specific
capacity assertion is replaced by record retirement/generation assertions
for the ordered map; the socket-storage allocation regression remains.
The earlier mainline and five-target results predate this implementation
change, so the final full matrix still needs refreshing. Runtime deadline
selection still scans all tunnel timers after events; complete G12/M16
event cost and the other phase gates remain open. The first empty-loop
live harness invocation is retained as a harness error, not counted.

## Indexed deadlines and conflict cancellation

[The deadline-index package](phase6/deadline-index-20261031/README.md)
replaces per-event timer scans with ordered indexes. Replacing or
cancelling an owner's deadline removes the previous entry; due iteration
visits only due owners. A 10,000-mutation model checks exact minima,
contents, due sets and bounded cardinality. Fixed retry times survive
unrelated traffic and are cancelled on success/removal.

The selector's 20,000-query/20,000-record native workload falls from
29.17 seconds to 8.84 milliseconds in the recorded debug profile; this is
diagnostic evidence, not a new SLA. A regression also found existing
conflict counters/slow retries retained after configuration removal.
Removal, identity replacement and shutdown now discard obsolete conflict
state; removal/shutdown cases preserve the foreign tunnel.

All 23 host scenarios, 26 privileged process cases, ordinary tests, Clippy,
four strict source-link checks and ten TEST_SEED=1..10 rule runs pass.
Each rule run passes 74 tests; its 32-seed planner ranges overlap. Mainline
7.3.0 also passes the scoped H16 clock/pause case with current deadlines
and all result markers zero. The full current-source/latest-target matrix
still needs its final run. Relevant-event cache maintenance and the rest
of the G12/M16/resource proof remain open; no global gate is closed.

## Incremental event cache and fake-suite isolation

[The event-cache package](phase6/event-cache-20261031/README.md) replaces
global device/address-cache maintenance with changed-dependency updates,
an indexed reverse member map and addresses grouped by device. It removes
stale addresses when a complete monitor-resync snapshot no longer contains
them and excludes unbound siblings of a bound VRF member. Previously,
10,000 unrelated sibling notices accumulated 10,001 cached master records.
The regressions also check VRF binding removal/member moves, seed failure
and recovery, and empty-configuration cleanup without changing foreign links.

For 500 unchanged bound-link events, diagnostic native debug times change
from 2.02/40.69/126.24 milliseconds at 1/100/300 independent bindings to
1.36/1.43/1.46 milliseconds. No kernel operation is issued. A separate
member-move workload reconnects exactly one affected tunnel per event;
its whole fake-backend elapsed time is not a constant-cost assertion.
Full reconciliation/resync and newly discovered address dumps retain
their documented global work. Complete G12/M16/G23 proof remains open.

All 23 host scenarios pass on Ubuntu 6.8.0-147-generic. Shared CI checks,
the five focused cache cases and four strict source-link cases pass.
Repeated rules initially expose an intermittent re-creation failure.
A controlled fork probe demonstrates cross-test fake-socket reference
retention. The logging fixture now captures its own thread without a
subprocess; an extra assertion excludes another thread's report. Ten
seeded 74-case rule runs subsequently pass. The exact scheduling of the
original failure was not captured; failed and inconclusive diagnostic
runs remain archived. Strict rule-map coverage remains 275/333, with 58
uncited active rules. Final matrix, coverage and manager refreshes are
still open; no global strict flag is enabled.

## R6/R9: filter refusal and process descriptor limits

[The R6/R9 package](phase6/R6-R9-20261031/README.md) adds live child-only
SO_ATTACH_FILTER refusal and real EMFILE at a descriptor limit of 32.
The unfiltered monitor preserves traffic and session identity across
unrelated churn and address loss/recovery. Its warning now includes
EPERM. Under EMFILE, existing traffic works, missing entries withhold
readiness, and raising the child's soft limit permits all 40 tunnels
without a reload. No host networking or process limit is changed.

The first live test reproduces error-level reports for transient tunnel
creation failures. Tunnel and session creation now share the existing
support/privilege-versus-transient classification. Expanded fake cases
also expose a silent EAGAIN mistaken for the internal tunable wait;
the silent arm now requires an actual pending handshake. All 16 error/
creation-kind combinations and the original episode-promotion cases pass.

The focused host run passes six cases and the first full host run passes
all 25 scenarios. A fresh final-source run also passes all 25 in 161.26
seconds after the EPERM-display follow-up. Shared CI,
four strict source-link cases and ten seeded 74-case rule runs pass.
The strict rule map improves to 278 cited of 333 active rules, leaving 55
uncited. Initial fixture/compiler failures and real reporting failures
remain separate in the record. These additional cases have not run on
the other required targets or in Incus. No global gate is closed.

## Library requirements and recoverable runtime errors

[The library package](phase6/library-requirements-20261031/README.md)
tests absent runtime, capability and logging, a caller-dropped source event,
overlapping owners and active/retiring socket cleanup. It reproduces and fixes
two defects: dropping a runtime leaked owned sockets when its kernel backend
outlived it, and polling a timed event wait without Tokio panicked. Drop now
closes those sockets without ordered deletion; the timed wait yields a
non-exhaustive `ControlEvent::Failed` and forwarding it returns the error.
Synchronous startup and event preparation retain their useful ownership/thread
contracts; channel-only futures remain usable outside Tokio.

The common CI gate and four strict source-link cases pass. Each of ten seeded
runs passes 92 ordinary library cases (11 live cases ignored), 74 rule cases
and 25 service cases. The privileged musl run on `6.8.0-147-generic` passes
19 kernel cases and 26 process cases. The full host run passes 25 scenarios
in 161.19 seconds. Separate logs retain the two demonstrated product failures
and the two initial live-fixture mistakes. The strict rule map remains red:
343 total / 333 active / 289 cited / 44 missing. The new citations cover
A2, A21, G9, G14, R22 and R37–R42; they do not close every clause of those
rules or the final matrix, manager and coverage refreshes.

## Operator, peer and manager requirement assertions

[The operator package](phase6/operator-requirements-20261031/README.md)
adds 23 requirement citations to observed behavior, strengthening invalid UTF-8
handling, temporary-name collisions, wrong-ID/cookie frame rejection and the
empty-filesystem container case. It changes no production behavior. Foreign
temporary-name occupants remain unchanged, and the daemon operates with both
`/proc` and `/sys` hidden. Other citations point to existing configuration,
recovery, identity, manager and process assertions; they do not by themselves
prove every clause.

Shared CI passes, as do ten seeded runs of 92 ordinary library cases
(11 live ignored), 74 rules and 25 service cases. The corrected privileged
musl profile passes 19 kernel, 26 process and 41 binary unit cases. Its one
real-manager case is explicitly filtered and passes separately in a collected
user systemd service with the template's address-family filter and descriptor
store. The initial incorrectly combined profile remains a recorded fixture
failure, not a passing run or a product defect. The strict rule map remains red
at 312 cited of 333 active rules, 21 uncited. Final kernel/manager refreshes,
coverage, resource/event-cost proof and strict CI are still open.
The full host suite also passes all 25 scenarios in 164.59 seconds, including
the strengthened empty-`/proc`/`/sys` case.

## Final host-requirement citations: R35 and R45

[The host-requirement package](phase6/host-requirements-20261031/README.md)
overflows a four-notice fake monitor with 1,000 foreign link/address cycles,
then loses a relevant source change behind the full queue. One loss/resync
recovers the final source with exactly one disconnect/rebind/connect, unchanged
socket/session identity, readiness and no pending timer. Its first expected
trace omitted the required rebind and is retained as a fixture failure.

The new guest-only `no-vrf` profile passes on `6.8.0-147-generic` and
`7.0.0-42-generic`. Both positively refuse VRF creation with the driver absent
and autoload disabled, then carry IPv4/IPv6 frames bound to ordinary `vrf0`
devices. Bind-name loss/restoration reconnects without session replacement.
Each scoped run requires all three guest result markers; neither is a full
normal-matrix result or a CONFIG_NET_VRF=n build. The host is untouched.

All 75 rule cases pass under each of ten seeds; common CI and four
source-link cases pass in the lenient shared-script run. Strict rule-map status is 314 cited / 333 active,
19 uncited. Every active R rule now has declaration traceability, with full
clause proof still open. Coverage, final normal matrix/manager profiles,
event/resource/history proof and strict CI remain incomplete.

## O4: identifiers in configuration diagnostics

[The observability package](phase6/observability-20261031/README.md)
reproduces missing valid IDs for left-out entries. Diagnostics previously
looked them up in accepted configuration, where omitted entries have no record;
sessions also lacked their tunnel ID and unknown-key reports lacked context.
Conversion now retains valid numeric identifiers in `Problem`, shared by
check/startup/reload output and strict conversion errors. Invalid or absent
IDs are omitted; cookies remain redacted. A nine-input process case and exact
creation-report labels assert O4. Existing exact-message expectations are
updated to include IDs, with the intermediate failures retained separately.

Common CI and four source-link cases pass. Shared-script map runs were lenient.
Each of ten seeds passes
92 ordinary library cases (11 live ignored), 75 rules, 25 service cases and
nine ordinary process cases (18 live ignored). The privileged musl process
suite passes all 27 cases on `6.8.0-147-generic`; the full host suite passes
all 25 scenarios in 163.38 seconds. The strict map remains red at 315 cited /
333 active, 18 missing. No global gate is closed.

The separate requested CodeQL exclusion is committed in `f42e841`/`bcd283b`.
The advanced Rust/Actions workflow preserves the extended suite and excludes
only `rust/cleartext-logging`; its actual GitHub run passes and uploads results,
with the configuration/filter visible in the log and no open alerts for that
query after analysis. Default setup is disabled so it cannot override the
custom workflow. The unavailable organization-property alternative changed
no organization setting. This does not weaken cookie-redaction assertions.

## Architecture, restart and host-visible identity assertions

[The architecture package](phase6/architecture-20261031/README.md)
strengthens the planner's configuration/object comparisons after every seeded
transition, verifies no second creation after a staging-address failure, checks
register/create/address/publication order, and checks exact PID formatting and
fixture directory contents across exec/shutdown. H6 requires the session to be
the only additional device at readiness; its baseline permits devices already
present in the namespace. Existing resolver, identity-loss, reconnect and
restart assertions now carry relevant architecture/event/observability tags.
Module-map/source-boundary checks remain explicitly supplementary to behavior.
No production behavior or dependency changes.

Ten seeds each pass 92 ordinary library cases (11 live ignored), 75 rule cases
and 25 service cases; the planner ranges overlap. The live musl run on
`6.8.0-147-generic` passes all 19 kernel and 27 process cases. The full host
suite passes 25 scenarios in 163.50 seconds. These executions precede only a
test-only H6 iterator cleanup required by warning-denied Clippy; the original
lint failure is retained separately. The corrected common CI passes, and the
final focused H6 run passes in 4.45 seconds. The strict map is 330 cited / 333 active,
three missing: G15, G16, G20. Current coverage, final normal matrix and manager
profiles, complete clause/event-cost/resource/history proof and strict CI
remain open.

## Final promise declarations and complete local traceability

[The conditional-promise package](phase6/conditional-promises-20261031/README.md)
supplies G15/G16/G20 declarations and a live G15–G20 scenario. It measures
readiness after creation while DNS, binding and routes are unavailable;
requires all three eligible objects; measures literal-peer connection; keeps
all session indexes through identical reload, rename and peer change; carries
real frames; checks the kernel's source/peer dump; and requires ordered
session-before-tunnel cleanup, exit status 0 and actual object absence.
The process conflict case now enforces the ten-second readiness bound.
Existing parent/PID and runtime cleanup-window tests add complementary tags.

The explicit two-flag strict command passes three rule-map and four source-link
cases: 343 total / 333 active / 333 cited / zero missing; 43 active K facts,
37 production citations, six classified facts and no uncited Linux functions.
Ten seeded runs each pass 92 ordinary library cases (11 live ignored), one
fake-conformance case, 75 rules and 25 service cases; the ranges overlap.
Common CI passes, and three consecutive full local host runs pass all 26 cases
in 164.21, 163.32 and 161.90 seconds, with no intervening source change or flake.
Each retains its required controller result marker.
The live musl process suite passes all 27 cases on `6.8.0-147-generic`;
the measured conflict-readiness delay is 9.017 seconds, within ten seconds.

Audit wording is corrected where the host-requirement, observability and
architecture packages called their shared-script source-link runs strict.
The shared script does not set strict flags: those invocations reported
counts leniently. Separate explicit strict logs are distinct evidence. The
current explicit strict run above closes local declaration traceability,
not every clause or the phase. The plan requires ten repetitions of each
suite in CI, so three local container runs do not authorize claiming that
stronger requirement complete. Strict CI enforcement remains off; final
kernel/manager profiles, coverage and complete resource/event/history proof
remain open.

## Bounded CI qualification

[The CI qualification package](phase6/ci-qualification-20261031/README.md)
adds ten seeded fake/live matrix jobs. The live jobs boot fresh stock Ubuntu
guests and run the same scenario binary as the container suite, plus kernel
and process cases. Every job and long step has an explicit timeout; QEMU
retains its separate 900-second limit. At most two repetitions run at once,
fail-fast is disabled, and failed jobs retain their logs. The ordinary build
job now has a 30-minute limit. Strict flags remain off until all required
CI repetitions pass. No CI qualification pass is claimed by this package's
local image/common-gate checks.

The review-image helper downloads package indexes and archives with host
curl. Package resolution and installation stay in networkless Docker;
Alpine's signature checks remain enabled. The local image build and package
presence check pass. Common CI gates pass. The package records commands,
source identity and the pending external-run requirement.

## CI artifact-parser correction

[The artifact-path package](phase6/artifact-paths-20261031/README.md) records
the first qualification failure: forced Cargo color prevented executable-path
parsing, and a searchable directory passed the old executable-only guard.
QEMU, Docker and Incus runners now request plain output for parsed Cargo
commands and require regular executable files. The remaining broken-revision
jobs were cancelled; this attempt is not ten-run qualification evidence.
The forced-color Docker and QEMU clock-profile regressions and common gates
pass. Injected empty Cargo output is rejected by all three runners before
test execution; the Incus negative check stubs availability and does not
claim a live Incus pass.

A full Ubuntu 24.04 normal guest, on the current Rust source before only
the runner correction, passes 11 live library, 19 kernel, five review,
38 ordinary binary, three explicit permission, 27 process and 26 scenario
cases. Nested child results are not added to the counts. All required
guest markers are zero. This refreshes one required normal profile;
it does not establish the full latest matrix.

## Coverage and exit state

[The first merged coverage record](phase6/coverage-20261031/README.md) combines
ordinary native, fake, privileged GNU container, real user-systemd and
unprivileged Incus buffer profiles. It reports 9,101/9,998 lines and
1,374/1,784 branches. Source snapshot: 8fd9ae8, before the later readiness
fix. Test helpers in src/ have not been silently suppressed. No coverage
exclusion is claimed; this report does not pass the gate.

[The current-source coverage refresh](phase6/coverage-current-20261031/README.md)
uses Rust source `0f5292e` and combines native/fake, all 26 host scenarios,
the live kernel/process suites, the real user manager and the full
unprivileged Incus manager scenario. All executed suites pass. The result
is 9,586/10,390 lines (92.26%) and 1,460/1,868 branches (78.16%), with no
exclusions. It leaves 804 lines and 408 branches, including reachable error
paths, inline-test compound assertions and missing boot/root-sandbox
profiles. The coverage-only Incus drop-in preserves the existing writable
runtime directory for profile export. Escaped systemd percent specifiers
and an explicit multi-process profile check retain seven daemon profiles.
The initial filename-expansion defect and its diagnostic report are kept
separately; the final merge uses only the corrected Incus collection.

The unmodified musl Incus gate also passes through
`CARGO_TERM_COLOR=always tests/docker/run.sh incus`: its buffer case requires
`FORCE_RESULT=EPERM`, the full system-manager scenario passes in 17.19 seconds,
and `INCUS_RESULT=0` follows successful container deletion. Its record is
[incus-20261031T134611Z-3957335](phase6/incus-20261031T134611Z-3957335/scenario.log).
The concurrent H11 MAC write gets EBUSY; both ordered cases assign a persistent
MAC. This remains the approved combined contract.

Commits use commit.sh, signatures and sign-offs; completed packages are
synced through sync.sh. No global strict-CI success is claimed.
Completed profiles clean up their transient user services and containers.
The separate current required-kernel matrix refresh is still running;
its final result is not claimed here. Earlier records retain their scoped
outcomes.

## Completed CI qualification and strict map enforcement

[The retained CI qualification](phase6/strict-gates-20261031/README.md)
records all ten seeded fake/live passes from run 41205847108, attempt 1,
source `0f5292e`. Every guest ran all 26 normal scenarios and the full live
kernel/process suites on Ubuntu `6.8.0-147-generic`. Seeds, revisions,
result markers and suite counts were checked against the extracted artifacts.
The common script now enables both strict map flags and passes locally.
Regular CI retains one full fake/live guest with the same bounded timeouts;
the new strict workflow still needs its own successful run. This closes the
initial ten-run prerequisite, not complete clause coverage or Phase 6.

The separate current kernel matrix found an H8 scenario assertion failure
on vanilla 7.0.14: total requests differ by one generic-netlink request,
while both captures contain exactly the two deliberate fixture route queries.
That failure is retained and under investigation. The successful Ubuntu CI
qualification does not establish a passing five-kernel matrix.

## Current matrix and root-systemd refresh

[The current required matrix](phase6/matrix-20261031T133318Z-3943822/README.md)
finishes with `MATRIX_RESULT=1`: four normal profiles pass all 26 scenarios;
vanilla 7.0.14 passes 25 and fails the H8 aggregate request-count assertion.
All five targets pass their kernel/process cases, H20 fragmentation and
H17 300-tunnel cases. Four current clock profiles pass; vanilla 7.0.14's
clock boot is skipped after its normal-profile failure. Both mainline H4
boots and the stock Ubuntu 7.0 missing-Ethernet-driver recovery case pass.
Initial/final published versions match and both source patches are empty.
The earlier metadata TLS failure ran no tests and is recorded separately.

[The current P6 root-systemd profile](phase6/root-systemd-current-20261031/README.md)
passes its full one-case suite in 26.30 seconds on Ubuntu 6.8.0-147. The
actual supplied unit has no drop-ins; private mounts, protected root and
tunables, the writable exception, exact capabilities, autoload/readiness,
manager store/re-exec and cleanup assertions pass. This is uninstrumented
musl evidence, separate from the coverage-only manager drop-in profile.

## Strict workflow execution confirmed

CI run 41211013318, revision `26fe9ba`, attempt 1, passes both jobs.
The build log confirms all 333 active rules cited and all 43 source facts
accounted for, with no uncited Linux functions. Its single normal guest
passes all 26 scenarios and the live kernel/process suites. Retained
metadata and normalized logs are in the qualification record's `enforced-ci`
directory. This establishes both P1 traceability gates in CI; other Phase 6
requirements remain open. The later H8 fixture change has a separate CI run.

## Vanilla 7.0.14 after the H8 correction

[The targeted rerun](phase6/vanilla7014-refresh-20261031/README.md) passes
all 26 normal scenarios in 449.00 seconds, all kernel/process cases and
the separate 64.05-second clock/pause profile. Three earlier focused H8
repetitions already passed. The fixture now compares drained startup/reload
work before scheduler-dependent tunnel cleanup, while still prohibiting
extra route queries through shutdown. The failed matrix remains failed;
a final consistent-source five-target run is still required. CI run
41212014031 at the H8-fix revision `fb41979` also passes both jobs.

## Approved production-code coverage scope

The maintainer approved production-code coverage, excluding test-only
bodies/helpers from instrumentation while still executing every test.
[The decision and original evidence](phase6/coverage-test-code-20261031/README.md)
retain the example of a zero-count panic arm in a passing inline test.
The plan and coverage definitions now state that scope explicitly.
Nightly-only attributes identify 45 test modules and one test-only helper;
no production code is excluded. Stable checks still execute the same tests.

[The fresh merged production baseline](phase6/coverage-production-20261031/README.md)
is 90.68% lines (7,596/8,377) and 78.16% branches (1,374/1,758), leaving
781 lines and 384 branches. It includes all native suites, 11 live library,
19 kernel and five review cases, privileged binary probes, all 27 process
cases, all 26 normal scenarios, the real user manager and the full Incus
manager scenario. Incus exports seven daemon profiles and is deleted.
The source patches match and profiles from the earlier instrumentation
scope are not merged. The previous 92.26% line figure included inline test
code; its denominator is different. The production threshold remains 100%.

The coverage CI step now pins nightly-2026-10-28 and cargo-llvm-cov 0.9.1,
with branch-aware LCOV. Ordinary checks and shipped builds stay on stable.
[CI run 41214508623](https://github.com/menhera-org/rs-l2tpd/actions/runs/41214508623)
passes both jobs on its first attempt at `2afe727`; retained metadata and
coverage commands are in the baseline record. The native badge report
remains distinct from the merged live-profile gate.

[Startup resource-failure checks](phase6/coverage-startup-20261031/README.md)
cover 24 more production lines, bringing the merged report to 90.96%
(7,620/8,377) with unchanged branch coverage. Runtime/service thread
creation and service engine construction return their precise I/O errors
and both inherited descriptors remain usable. An initializer panic also
returns ownership to the caller. The common checks and ten seeded fake
repetitions pass after moving subprocess faults into a separate test
executable; the initial isolation failure remains recorded. Production
implementation is unchanged, so the baseline live profiles remain valid.
There are still 757 missing production lines and 384 missing branches.

The subsequent [adoption and recovery checks](phase6/coverage-boundary-20261031/README.md)
raise coverage to 91.83% lines and 78.56% branches, leaving 684 lines and
377 branches. All 17 shared conformance cases pass on the fake and live
Ubuntu kernel. Six startup faults and three new policy cases verify actual
error recovery; an existing staged-deletion test now uses the fake's correct
fault key. Common checks and ten seeded fake repetitions pass. The production
implementation remains unchanged; these new live cases still need the final
required-kernel matrix.

[File, handover and notification failures](phase6/coverage-process-20261031/README.md)
raise coverage to 92.23% lines and 79.41% branches, leaving 651 lines and
362 branches. Common checks and ten seeded library/binary/fake repetitions
pass after correcting a listener-close assumption in the new test. Production
code remains unchanged and previous privileged profiles remain applicable.
The startup package's [CI run 41217025839](https://github.com/menhera-org/rs-l2tpd/actions/runs/41217025839)
also passes both jobs on its first attempt at `3f9d32a`.

[Closed-handle and lifetime checks](phase6/coverage-closed-20261031/README.md)
raise coverage to 92.72% lines and 80.03% branches, leaving 610 lines and
351 branches. Final common checks and ten seeded repetitions pass. The
17 shared fake cases pass under four capability/deletion combinations;
the same 17 cases pass in the focused live Ubuntu wrapper. Production code
remains unchanged. The adoption package's CI run `41217588917` passes both
jobs on its first attempt at `f7db02e`; job metadata is retained in this record.
