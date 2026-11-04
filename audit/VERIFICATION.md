# Verification status

Production source is signed [`c599b1f`](https://github.com/menhera-org/rs-l2tpd/commit/c599b1f9c2343a3ffe6be315a6d77c4b68106744).
The refactor preserves behavior and public APIs. The full execution evidence
is archived in signed [`129a4e1`](https://github.com/menhera-org/rs-l2tpd/tree/129a4e1fb02da9fab01ef61730853c2129ee9e5a/audit/phase6).
Current gating code lives in `tests/`, `tools/` and the repository root;
this directory keeps summaries and immutable pointers.

| Gate | Result | Evidence |
|---|---|---|
| Common CI gates, GNU/musl, formatting, Clippy and docs | Pass | [CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41755915522), [maintenance checks](https://github.com/menhera-org/rs-l2tpd/blob/129a4e1fb02da9fab01ef61730853c2129ee9e5a/audit/phase6/qlty-refactor-20261104/maintenance-checks.log) |
| Strict maps | 333 active rules, 43 kernel facts, no uncited Linux functions | Same common gates |
| Production coverage | 8,582/8,582 merged lines; 1,844/1,844 condition outcomes | [Coverage record](https://github.com/menhera-org/rs-l2tpd/blob/129a4e1fb02da9fab01ef61730853c2129ee9e5a/audit/phase6/qlty-refactor-20261104/merged-source-coverage.log) |
| Required kernel matrix | All 13 profiles pass; unchanged source and publication selections | [Matrix summary and logs](https://github.com/menhera-org/rs-l2tpd/tree/129a4e1fb02da9fab01ef61730853c2129ee9e5a/audit/phase6/matrix-20261104T013533Z-1275329) |
| Scenario/Incus qualification | Three consecutive musl pairs pass; containers deleted | [Commands and results](https://github.com/menhera-org/rs-l2tpd/blob/129a4e1fb02da9fab01ef61730853c2129ee9e5a/audit/phase6/qlty-refactor-20261104/verification.log) |
| Unmodified root-systemd unit | Pass on Ubuntu 6.8.0-147 with Ubuntu 24.04 userspace | Same execution record |
| Security analysis | Pass | [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41755915465) |

The required set is Ubuntu `6.8.0-147-generic`/`7.0.0-42-generic`,
vanilla `6.8.12`/`7.0.14` and mainline `7.4.0-rc1`. Each normal guest
passes 27 scenarios and 37 process cases. Five clock/pause profiles,
both IPv6-absent boots and missing-driver recovery pass separately.

| Optional stock kernel | Normal | Clock/pause |
|---|---|---|
| Debian 13 `6.12.115+deb13.1-amd64` (6.12.115-2) | Fail: H17 capture; 26/27 scenarios, 37 process cases pass | Pass |
| Rocky 9 `5.14.0-687.61.1.el9_8.x86_64` | Pass: 27 scenarios, 37 process cases | Pass |
| Rocky 10 `6.12.0-211.72.1.el10_2.x86_64` | Pass: 27 scenarios, 37 process cases | Pass |

Signed `3dee493` replaces Debian 12 with Debian 13 in the optional tooling;
production behavior, executable hashes and guest assertions are unchanged.
All six new profiles ran after it was synced, with empty initial/final source
patches. The aggregate optional result is **failure**: Debian 13's full normal
run fails an intermittent nlmon capture check. A scoped H17 rerun and 40
notification-only rounds pass without reproducing it; Debian 13 remains
unqualified. [Commands, package identities, full results and diagnostic scope](https://github.com/menhera-org/rs-l2tpd/blob/8766a43c2099a9ff71ae7ee1e30866c61777fbb4/audit/optional-kernels/README.md)
are retained separately. Debian 12 is outside the support target, with
[best-effort degradation](../docs/kernel-behavior.md#best-effort-behavior-on-debian-12).
Its failed qualification and the earlier Rocky results remain in the
[archived optional record](https://github.com/menhera-org/rs-l2tpd/tree/129a4e1fb02da9fab01ef61730853c2129ee9e5a/audit/phase6/optional-kernels-20261104).

Raw local LLVM metrics remain separate: 99.45% lines and 98.26% outcomes.
Production exclusions: **none**. Test-only instrumentation exclusions are
unchanged; required tests still execute. Ten native seeds, coverage
calibration/negative controls and thread/fork refusal profiles pass.

Qlty's service-worker complexity falls from 80 to 24; the former startup
(68), swap planner (44) and probe (39) no longer trigger high function
complexity. Lower-complexity routines and explicit test matrices remain.
The maintenance checks verify temporary HTML parsing, unchanged coverage
runtime layers/configuration, all 23 `#!/bin/sh` headers and documentation links.
The current tree passes `./test-ci-gates.sh` and local Markdown link checks.
The production refactor also has a fresh `qlty smells .` record.

Kernel-only guests do not qualify distribution userspace, SELinux or packages.
Source-only and delegated assertions retain their
[evidence classifications](../docs/kernel-evidence.md);
[kernel behavior](../docs/kernel-behavior.md) states the limits.
Earlier clause assessments, determinism qualification, source comparisons
and failed attempts remain in [`c599b1f` history](https://github.com/menhera-org/rs-l2tpd/tree/c599b1f9c2343a3ffe6be315a6d77c4b68106744/audit).
Every removed historical/evidence file was verified in Git before removal.
Fetched kernel.org HTML is not committed.
