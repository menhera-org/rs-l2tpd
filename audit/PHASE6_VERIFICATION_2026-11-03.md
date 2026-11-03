# Phase 6 verification, November 3

## Final result

Phase 6 is complete on signed commit
`9e6aae63ec43166941a14fed8883547ead7dc4f0`.
[CI run 41607623091](https://github.com/menhera-org/rs-l2tpd/actions/runs/41607623091)
passes Build and check, Live conformance, and Production coverage (100%).
[CodeQL run 41607623178](https://github.com/menhera-org/rs-l2tpd/actions/runs/41607623178)
also passes. The downloaded
[coverage artifact](phase6/ci-coverage-9e6aae6-20261103/README.md) reports
**8,486/8,486 merged production source lines and 1,852/1,852 condition
outcomes**. Raw LLVM reports 8,699/8,751 lines (99.41%) and 1,819/1,852
outcomes (98.22%); no production exclusion was added.

The [required matrix](phase6/matrix-20261103T090121Z-983779/README.md)
passes all thirteen profiles on that source. The five normal kernels each
pass all 27 scenarios and 37 process cases; all five clock/pause profiles,
both IPv6-absent profiles and missing-driver recovery pass. Initial and final
publication selections agree and both source patches are empty.

The [final host record](phase6/final-hosts-9e6aae6-20261103/README.md)
contains three consecutive complete musl scenario/unprivileged-Incus pairs
and the supplied root-systemd unit. All pass with empty initial/final source
patches. The [clause assessment](phase6/clause-assessment-20261103/README.md)
checks the assertions and required-suite execution behind all 333 active rule
citations and all 43 kernel facts. It treats lexical traceability as a map,
not as semantic proof.

The assessment found an S8 ownership race. Signed `f744335` contains the
ordering fix; `9e6aae6` adds the missing failure-path coverage. CI, the full
matrix, Incus repetitions and root-unit qualification were all repeated after
that production change. The initial ten-seed CI qualification passed before
strict gates were enabled. Earlier failed collectors and parallel-QEMU clock
experiments remain failures in the chronological record below; no passing run
is used to erase or explain them.

Desired Debian/RHEL-family userspaces and intermediate vanilla kernels were
not run. They are explicitly non-gating targets. No required Phase 6 case was
skipped in the final records.

| Package | Final evidence | Result |
|---|---|---|
| P1 | Strict rule/source commands in `phase6/clause-assessment-20261103/commands.txt`; 333 active rules and 43 classified kernel facts | pass |
| P2 | 27 scenarios in every normal matrix profile and each of three final musl repetitions | pass |
| P3 | `tests/docker/run.sh matrix required`; five normal, five clock and three boot/recovery profiles | pass |
| P4 | Required Production coverage (100%) CI job; 8,486 lines and 1,852 outcomes | pass |
| P5 | Three `tests/docker/run.sh incus` executions, unprivileged and unskipped | pass |
| P6 | Supplied unit in the retained root-systemd QEMU guest | pass |
| P7 | This record and the status, testing, kernel-behavior and index pages | pass |

## Chronological evidence and retained failures

The final clause audit after signed `f771c24` reproduced an S8 ownership
failure: a foreign device registered under an armed creation name, moved
away, and its index was returned as `Proved` after the real L2TP session
registered under that name. The
[creation-capture record](phase6/creation-capture-ordering-20261103/README.md)
retains the failure. The working fix orders capture completion through the
lifetime socket and refuses multiple distinct registrations. It passes all
31 ignored live library cases, all 24 Linux integration cases and ten forced
interleavings. The original five-second uncertain-creation deadline also
passes. Signed `f744335` contains the fix and passes the complete
[required matrix](phase6/matrix-20261103T074746Z-889916/README.md): five normal
suites, five clock/pause profiles, both IPv6-absent boots and missing-driver
recovery. Its source patches are empty and publication selections agree.

Signed `f771c24` has a failed
[CI run 41595151274](https://github.com/menhera-org/rs-l2tpd/actions/runs/41595151274).
Live conformance and the 100% production-coverage job pass; the build job
fails because ANSI bytes from `CARGO_TERM_COLOR=always` enter the
source-work executable path. The working change adds `--color never` to
that parsed command. Signed `f744335` fixes the parser command. Its build and
live jobs pass in
[CI run 41598593512](https://github.com/menhera-org/rs-l2tpd/actions/runs/41598593512),
and CodeQL passes. Its production-coverage job fails at **8,477/8,485 lines
and 1,848/1,854 outcomes** on the new lifetime capture paths. The current
working tests cover those new paths in fresh focused measurement, but
current-source CI coverage, Incus and root-unit qualification remain pending.

Signed `e29c6f3` is synced. All three jobs pass in
[CI run 41582370103](https://github.com/menhera-org/rs-l2tpd/actions/runs/41582370103),
as does [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41582370032).
The [downloaded production artifact](phase6/ci-coverage-20261103/README.md)
reports **8,444/8,444 source lines and 1,838/1,838 condition outcomes**,
with a successful mandatory gate. All 51 source fingerprints match the
independent local rehearsal. Raw LLVM remains 99.40% lines and 98.20%
outcomes in CI; no production exclusion is added.

The [required matrix on e29c6f3](phase6/matrix-20261103T051118Z-682716/README.md)
passes all thirteen profiles, with empty source patches and unchanged
initial/final publication selections. Each normal target passes all 27
scenarios and 37 process cases. All clocks, both IPv6-absent boots and
missing-driver recovery pass. This does not erase earlier failed parallel
clock experiments or establish their cause.

The [allocation/cost integration](phase6/resource-cost-integration-20261103/README.md)
passes the final common checks. The expanded allocation fixture passes
ten GNU and ten musl repetitions, with 18 startup and 18 resync measurements
per repetition. The integrated work runner passes all 240 cases. Its new
parser passes four tests on both libcs. Fault controls reject temporary
full inventories, a configuration-wide scan, disabled peak accounting and
forgotten deallocation; all mutations are restored.

The [fresh host checks](phase6/final-hosts-20261103/README.md) pass three
complete musl scenario/Incus pairs and the unmodified root systemd profile.
Production src/ is unchanged from e29c6f3; the compiled shipped-musl daemon
is byte-identical to the tested binary. Actual CI qualification of the
new checks and the final clause assessment remain open. The first
production-coverage job is a pass, not ten CI executions of this revision.

The following collector entries retain their historical failures and
subsequent local closure.

The [fresh source collector](phase6/source-coverage-20261103/README.md)
reports 8,444/8,444 lines and 1,836/1,838 outcomes, checker exit 1.
The [two-witness collection](phase6/final-source-coverage-20261103/README.md)
covers those outcomes but still misses the unsent-store shutdown line and
the restart shutdown guard: 8,443/8,444 lines and 1,837/1,838 outcomes,
checker exit 1. Both failures are retained.

The [extended witness batch](phase6/final-condition-witnesses-20261103/README.md)
passes 19 shutdown tests ten times per libc and the full common checks.
Four fault controls reject their intended behavior changes. Ten fresh
instrumented ordinary collections pass. The [closure collector](phase6/closure-coverage-20261103/README.md)
now passes **8,444/8,444 production source lines and 1,838/1,838 condition
outcomes**, checker exit **0**. Raw LLVM retains **8,657/8,709 lines
(99.40%) and 1,804/1,838 outcomes (98.15%)**. No production exclusion is added.
A full instrumented guest and three real-daemon CLI restarts per libc pass;
only GNU profiles enter the coverage measurement. The new separate 100%
workflow job's [fresh local rehearsal](phase6/coverage-ci-rehearsal-20261103/README.md)
reproduces both 100% totals, checker exit 0. The first GitHub execution and
current-source full kernel matrix subsequently pass, as recorded above.
The final clause assessment remains separate.


Signed c0a1b3b passes [both CI jobs](https://github.com/menhera-org/rs-l2tpd/actions/runs/41572274408)
and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41572274403).


The [outcome-boundary batch](phase6/outcome-boundaries-20261103/README.md)
now passes the full common checks. Ten ordinary native suites, three
musl collections and separately run reload/shutdown witnesses pass.
Six restored behavior controls fail their intended assertions. Its
subprocess test runs serially; the earlier parallel fake-socket failure
and the surviving inventory mutation remain in the record.

The [coverage input follow-up](phase6/coverage-line-inventory-20261103/README.md)
passes ten checker tests on both libcs, Rust 1.89 checks, compiler-generated
calibration and four restored input-validation controls. A task-helper
name collision is reproduced and corrected; concurrent GNU/musl resource
fixtures pass. Fresh production coverage for this changed source is pending.

The [full required matrix](phase6/matrix-20261103T021525Z-400861/README.md)
passes all thirteen profiles on signed `db7c1d2`, with unchanged initial/
final targets and empty source patches. The five normal profiles each pass
all 27 scenarios and 37 process cases. This precedes the new readiness/
resync changes and does not settle the retained parallel clock failures.

## Preceding defensive-boundary batch

The [defensive-boundary batch](phase6/defensive-boundaries-20261103/README.md)
passes the mandatory common checks, repeated GNU/musl live collections,
GNU Incus, manager/task limits and the unmodified root system-unit profile.
Seven restored controls fail their intended assertions.

The maintainer approved [merged-source measurement](phase6/coverage-metric-20261103/README.md).
Its checker passes eight tests on GNU and musl, Rust 1.89 checks and a
compiler-generated calibration with missing-arm and repeated-guard controls.
It reports **8,441/8,441 merged source lines and 1,834/1,840 condition
outcomes**, exits **1**, and leaves **six outcomes missing**. The raw LLVM
summary remains **8,655/8,707 lines (99.40%) and 1,800/1,840 outcomes
(97.83%)**. The record retains both reports and compressed full exports.
The source/mapping inventory was captured after collection, not before it.

The 100% production CI gate, complete clause/history/resource/event-cost
proof and retained clock/emulator failures remain open. This batch does
not establish Phase 6 completion or replace the earlier full kernel matrix.

Signed base `6735dd6` passes
[both CI jobs](https://github.com/menhera-org/rs-l2tpd/actions/runs/41558686756)
and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41558686721).

## Preceding remaining-path batch


Phase 6 remains open. The [remaining-path batch](phase6/remaining-paths-20261103/README.md)
adds three covered lines and seven branch outcomes. The raw report is
**8,648/8,705 lines (99.35%) and 1,799/1,840 outcomes (97.77%)**.
It leaves **57 lines and 41 outcomes**, with no production exclusions.
All 4,389 production-source function mappings match the preceding
collector; process-test locations and six test mappings change.

Signed base `f0b666f` passes [both CI jobs](https://github.com/menhera-org/rs-l2tpd/actions/runs/41549176297)
and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41549176350).
The [November 2 record](PHASE6_VERIFICATION_2026-11-02.md) retains the
earlier full matrix, Incus, root sandbox, maintainer decisions and failed
clock/emulator experiments.

| Package | Current evidence | Remaining work |
|---|---|---|
| P1 | Common CI checks pass strict declarations for 333 active rules and classified evidence for 43 kernel facts | Declaration traceability does not establish every clause |
| P2 | Three instrumented GNU repetitions pass 57 live library cases; three stable repetitions per libc pass 29. Each collection passes all 37 process cases and ordinary library/binary cases; ten final model suites pass | Complete clause/history/resource/event-cost proof |
| P3 | Five focused required-kernel profiles pass; three instrumented Ubuntu 7.0 inventory repetitions pass and reject a faulty ID guard; publication selection is unchanged | Preserve earlier full normal/boot/clock scope; resolve or bound retained clock/emulator failures |
| P4 | Raw 99.35% lines / 97.77% outcomes; no production exclusions | 57 lines and 41 outcomes; enforce the final 100% gate in CI |
| P5 | Previous GNU/musl unprivileged Incus evidence remains | No fresh Incus run in this batch |
| P6 | Previous unmodified root-unit and manager/task-limit evidence remains; new focused guests also run signal task-limit cases | No fresh root-unit run in this batch; other distribution userspaces remain untested |
| P7 | Status, per-kernel behavior and evidence updated; common checks pass | Complete proof and coverage enforcement |

The new cases check successful inherited-socket withdrawal during failed
startup, a capget error that still permits empty readiness, quiet
lifetime timeouts, direct versus parent bindings on member removal,
duplicate source removal on an unrelated device and reload from a
zoned literal to an unanswered hostname. The latter three pass ten
complete instrumented library repetitions and three ordinary library
repetitions per stable libc. All five focused kernel profiles pass these
models, the reader modes and both process cases. Seven restored fault
controls fail their intended assertions.

An instrumented GNU guest now executes the newer kernel's wrong-tunnel
session-reply path. Ubuntu 7.0.0-42 returns the existing session from the
other tunnel; the adapter rejects its ID pair. All three repetitions
pass, export profiles and agree with the five stable witnesses from
November 2. These focused profiles do not replace a full matrix.

The [coverage investigation](phase6/remaining-paths-20261103/coverage-measurement.md)
reproduces LLVM summary aggregation across complementary function
instantiations. The merged source view and raw summary answer different
questions. This record retains the raw P4 metric and makes no 100% claim.

The November 3 publication recheck retains Ubuntu 6.8.0-147.147,
vanilla 6.8.12, Ubuntu 7.0.0-42.42, vanilla 7.0.14 and mainline 7.4-rc1.
The [kernel behavior page](../docs/kernel-behavior.md) distinguishes
observations from source evidence and userspace limits.
