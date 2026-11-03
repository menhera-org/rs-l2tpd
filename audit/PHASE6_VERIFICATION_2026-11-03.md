# Phase 6 verification, November 3

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
