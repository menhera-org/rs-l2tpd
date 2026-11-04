# Current verification

The qualified production source is signed commit
[`c599b1f`](https://github.com/menhera-org/rs-l2tpd/commit/c599b1f9c2343a3ffe6be315a6d77c4b68106744).
It refactors private startup, restart-probe, session-swap and service-worker
control flow without changing behavior or the public API. Production
specifications, assertions, gate definitions and coverage exclusions are
unchanged. Current gating tools live outside this evidence directory.

## Gates

| Check | Result | Evidence |
|---|---|---|
| Common CI gates, GNU/musl, Clippy/rustfmt/docs | Pass | [local log](phase6/qlty-refactor-20261104/ci-gates.log), [CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41755915522) |
| Strict traceability | 333 active rules, 43 K facts, no uncited Linux functions | Same common gate log |
| Merged production coverage | 8,582/8,582 lines; 1,844/1,844 condition outcomes | [merged report](phase6/qlty-refactor-20261104/merged-source-coverage.log), [CI result](phase6/qlty-refactor-20261104/ci-result.log) |
| Determinism | Ten native seeds pass; three musl scenario/Incus pairs pass | [command/result summary](phase6/qlty-refactor-20261104/verification.log) |
| Required kernels | All thirteen profiles pass | [matrix](phase6/matrix-20261104T013533Z-1275329/README.md) |
| Unprivileged Incus | Three executed passes, each container deleted | Same command/result summary and linked run directories |
| Unmodified root-systemd unit | Pass on Ubuntu 6.8.0-147 with Ubuntu 24.04 userspace | [guest](phase6/qlty-refactor-20261104/root-systemd/run.log) |
| Optional distribution matrix | Complete: Rocky 9/10 normal/clock pass; Debian 12 normal/clock fail |  [profile statuses](phase6/optional-kernels-20261104/profiles.log) |
| Security analysis | Pass | [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41755915465) |

Raw local LLVM totals remain separate: **99.45% lines and 98.26% outcomes**.
The full compressed export and source/mapping inventory are retained beside
the merged report. Test-only bodies/helpers are not instrumented; all required
tests execute. Production exclusion list: **none**. Coverage calibration and
its negative controls pass; thread/fork refusal profiles pass.

## Commands and source identity

```sh
qlty smells .
./test-ci-gates.sh
sh tools/coverage/calibrate.sh RECORD
TEST_SEED=SEED cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh tools/coverage/run-guest.sh NATIVE_LOG KERNEL_ROOT RECORD PROFILES
tests/docker/thread-limits.sh IMAGE INSTRUMENTED_DAEMON RECORD PROFILES
tests/docker/run.sh scenarios
tests/docker/run.sh incus
tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD
tests/docker/run.sh matrix required
```

The [refactor record](phase6/qlty-refactor-20261104/verification.log) identifies
seed 1–10, the three scenario/Incus pairs, GNU guest and root-unit commands.
The refactor and required matrix began on `7ed0e6e` plus the recorded patch;
that production/test patch equals the committed `c599b1f` change. Initial and
final patches agree. The optional runner starts from clean `c599b1f` after
its commit and sync. Documentation edits do not change those execution inputs.

Qlty's service-worker complexity falls from 80 to 24. The former startup
(68), swap planner (44) and probe (39) no longer trigger high function
complexity. Lower-complexity production routines and explicit test matrices
remain; no analyzer configuration or gate was relaxed.

## Scope and history

Required kernels are Ubuntu `6.8.0-147-generic`/`7.0.0-42-generic`, vanilla
`6.8.12`/`7.0.14` and mainline `7.4.0-rc1`. Normal guests each pass 27 scenarios
and 37 process cases; the five H16 profiles, both IPv6-absent boots and
missing-driver recovery are separate. Publication selections are unchanged.
The optional stock kernels are Debian `6.1.0-54-amd64`, Rocky 9
`5.14.0-687.61.1.el9_8.x86_64` and Rocky 10 `6.12.0-211.72.1.el10_2.x86_64`.
They do not qualify distribution userspace or a complete source/backport audit.

Debian's normal run passes 31 private live cases and 21 Linux cases, but
three Linux cases fail older unchanged-MAC/UP-device rename assumptions.
Later suites are not reached. Its clock controller passes, but the scenario
fails renaming the UP underlay. No assertion was weakened and no production
behavior was changed to make the optional result pass.

The CI/host matrix does not independently exercise every source-only or
delegated assertion. [Kernel evidence](../docs/kernel-evidence.md) preserves
those classifications; [kernel behavior](../docs/kernel-behavior.md) states
manager, fragmentation, deletion and cold-boot limits. Semantic clause
assessment, initial ten-run CI qualification, source comparisons and failed
historical attempts remain available at the
[archived commit](https://github.com/menhera-org/rs-l2tpd/tree/c599b1f9c2343a3ffe6be315a6d77c4b68106744/audit).
Historical files were checked in that Git tree before removal. Current
records retain compact results and artifact identities; kernel.org HTML
indexes are fetched/parsed as needed and are not committed.
