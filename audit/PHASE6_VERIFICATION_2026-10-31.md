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
| P2 scenarios | 23-case host subset passes, including the 300-tunnel H17 case; H16 passes on all five required kernels; scoped missing-Ethernet-driver guest also passes | Deadline-selection event cost, full resource/history proof, remaining clauses, manager/promise cases and final repetitions |
| P3 matrix | Pre-H15 required driver returns MATRIX_RESULT=0: five 18-scenario profiles plus both H4 boots; H15 adds a scoped stock-kernel driver-availability boot; H16 adds a passing clock profile on every required target; fresh mainline normal profile passes all 23 scenarios and current conformance | Complete P2/delegated proof and rerun all latest targets with the expanded suite and current report fixes; partial profiles do not close the whole gate |
| P4 coverage | First merged GNU report: 91.03% lines / 77.02% branches, source snapshot before the readiness fix | The previous source snapshot has 897 missing lines / 410 branches; recollect current-source profiles after readiness/H15 fixes; no exclusions introduced |
| P5 Incus | October 30 full case passed, including manager race/ordered policy/store/re-exec; fresh GNU buffer case proves EPERM and exports coverage | Final-code full-case refresh as part of phase exit |
| P6 root sandbox | October 30 full real-root-systemd sandbox case passed, without drop-ins | Final phase validation; no new sandbox claim from the coverage-only user-manager case |
| P7 docs/CI | Documentation updated to the actual partial runners and new records | Full verification, determinism/coverage jobs, strict CI and CI execution remain open |

Current P1/ordinary/warning checks are in
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

## Coverage and exit state

[The merged coverage record](phase6/coverage-20261031/README.md) combines
ordinary native, fake, privileged GNU container, real user-systemd and
unprivileged Incus buffer profiles. It reports 9,101/9,998 lines and
1,374/1,784 branches. Source snapshot: 8fd9ae8, before the later readiness
fix. Test helpers in src/ have not been silently suppressed. No coverage
exclusion is claimed; this report does not pass the gate.

Commits use commit.sh, signatures and sign-offs. No push or strict-CI
success is claimed. All test guests, transient user services and probe
containers have exited or been deleted. The worktree's latest status
pages point here; earlier records retain their original scoped outcomes.
