# Phase 6 verification, 2026-10-31

Phase 6 is not complete. This record extends
[the October 30 record](PHASE6_VERIFICATION_2026-10-30.md).
No strict CI flag has been enabled. The maintainer approved the K26/K34
kernel distinction on 2026-10-31, and the correction is applied. The
previously approved evidence-map and H11 MAC decisions remain in force.

| Gate/package | Current evidence | Remaining work |
|---|---|---|
| P1 source link | Fresh strict run: four tests pass; 43 facts, 37 production-cited and six classified; no uncited functions | Enable in CI only with required determinism and remaining phase proof |
| P1 rule map | Fresh strict run fails: 343 total / 333 active / 275 cited / 58 missing | Genuine assertions/citations for the remaining rules; strict flag stays off |
| P2 scenarios | 23-case host subset passes, including the 300-tunnel H17 case; H16 passes on all five required kernels; scoped missing-Ethernet-driver guest also passes | Relevant-event cache cost, full resource/history proof, remaining clauses, manager/promise cases and final repetitions |
| P3 matrix | Pre-H15 required driver returns MATRIX_RESULT=0: five 18-scenario profiles plus both H4 boots; H15 adds a scoped stock-kernel driver-availability boot; H16 adds a passing clock profile on every required target; fresh mainline normal profile passes all 23 scenarios and current conformance | Complete P2/delegated proof and rerun all latest targets with the expanded suite and current report fixes; partial profiles do not close the whole gate |
| P4 coverage | First merged GNU report: 91.03% lines / 77.02% branches, source snapshot before the readiness fix | The previous source snapshot has 897 missing lines / 410 branches; recollect current-source profiles after readiness/H15 fixes; no exclusions introduced |
| P5 Incus | October 30 full case passed, including manager race/ordered policy/store/re-exec; fresh GNU buffer case proves EPERM and exports coverage | Final-code full-case refresh as part of phase exit |
| P6 root sandbox | October 30 full real-root-systemd sandbox case passed, without drop-ins | Final phase validation; no new sandbox claim from the coverage-only user-manager case |
| P7 docs/CI | Documentation updated to the actual partial runners and new records | Full verification, determinism/coverage jobs, strict CI and CI execution remain open |

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

All 75 rule cases pass under each of ten seeds; common CI and four strict
source-link cases pass. Strict rule-map status is 314 cited / 333 active,
19 uncited. Every active R rule now has declaration traceability, with full
clause proof still open. Coverage, final normal matrix/manager profiles,
event/resource/history proof and strict CI remain incomplete.

## Coverage and exit state

[The merged coverage record](phase6/coverage-20261031/README.md) combines
ordinary native, fake, privileged GNU container, real user-systemd and
unprivileged Incus buffer profiles. It reports 9,101/9,998 lines and
1,374/1,784 branches. Source snapshot: 8fd9ae8, before the later readiness
fix. Test helpers in src/ have not been silently suppressed. No coverage
exclusion is claimed; this report does not pass the gate.

Commits use commit.sh, signatures and sign-offs; completed packages are
synced through sync.sh. No global strict-CI success is claimed.
All test guests, transient user services and probe
containers have exited or been deleted. The worktree's latest status
pages point here; earlier records retain their original scoped outcomes.
