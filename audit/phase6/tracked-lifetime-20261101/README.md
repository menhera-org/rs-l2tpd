# Tracked lifetime state and reused indices

The fake's tracked-registration generation duplicated its namespace generation.
Entries receive the current generation at creation, and the only generation
change clears the entire tracking map. An entry can therefore never retain
an older generation. The redundant field and comparison are removed; the
caller's registration generation is still checked.

A new fake test covers synchronous and queued session deletion after a
foreign device reuses the departed session's index. The foreign device must
survive both session deletion and later tunnel cleanup. Ending the lifetime
generation invalidates the old registration permanently; a new session gets
a fresh generation/incarnation and remains provable until its own removal.
The existing Linux index-reuse case now waits for complete tunnel cleanup
and checks the surviving foreign device and both registration outcomes. It
reuses the shared eventual-check helper, now visible to its parent test module.
No daemon, Linux-adapter or dependency behavior changes.

## Verification

`revision` plus `source.patch` reconstructs the tested implementation and
fixtures. All-feature builds use the pinned nightly only for coverage;
shipping musl artifacts stay on stable.

| Execution | Result |
|---|---|
| GNU and musl index-reuse live case | Three fresh networkless containers per ABI pass |
| Ten seeded ordinary suites | 127 library, 51 binary, 68 shared fake plus five fake-only, 81 rules and 30 service cases pass, with startup faults |
| Common checks | Pass, including strict rule/source maps, Clippy, musl process/startup cases and documentation |
| ARM64, RISC-V64 and PowerPC64LE musl | All-target/all-feature compile checks pass; no live architecture claim |
| Fresh instrumented live collection, Ubuntu 6.8.0-147-generic | 14 library, 20 Linux, five review, three privileged binary and 28 process cases pass |
| Fresh instrumented normal suite | 26 scenarios pass in 161.25 seconds |
| Real user manager | Descriptor-store processing and address-family filter pass |
| Instrumented unprivileged Incus | Full case passes in 19.78 seconds; seven daemon profiles exported |
| Unmodified musl root-systemd guest, Ubuntu 6.8.0-147-generic | Sandbox/store/restart/cleanup case passes in 28.04 seconds, ROOT_SYSTEMD_RESULT=0 |

A fresh coverage directory contains only this production implementation's
profiles. Coverage is **95.05% lines** (8,098/8,520) and **85.07% branches**
(1,538/1,808), leaving **422 lines and 270 branches**. The fake has 100%
lines (828/828) and 95.59% branches (130/136). No production exclusions,
profile mismatches or saturated inferred regions. Cargo build durations and
host user-manager resource accounting are omitted from retained logs.

The individual Incus pass does not resolve H11's staged-MAC decision or
prove its determinism. G23's contract choice, the upstream nix release,
final five-target qualification, full clause/resource/event-cost proof and
100% production coverage remain open. The preceding documentation source
passes both CI jobs in run 41255001978, about seventeen minutes overall;
that is separate from this new fake implementation's pending CI.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
# GNU/musl Linux executable, three fresh networkless containers per ABI:
# --ignored --exact a_reused_index_and_creation_name_never_revive_an_old_registration --nocapture
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-lifetime-state-20261101"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/tracked-lifetime-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/process-errors-20261031/run-live.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
# Root guest command and image/module artifacts: root-systemd/command.log and artifacts.log.
```
