# Advisory session-deletion verification (E27)

The preceding daemon cancels a verification task when the current session's
registration still proves ownership. A deletion announcement can arrive before
the kernel removes that session, so the daemon can stop checking too early.

The correction retains one task until absence or a different incarnation is
confirmed. Removing or changing the configured session identity cancels its
task even if failed cleanup retains the old record. Late notices cannot
recreate that obsolete task. A name-only configuration change preserves it.
Existing task storage and the accepted-identity helper are reused; there is no
new dependency or public API.

## Source and witnesses

`revision` identifies `4881c32d6f166c7c36a58d95dfa741777286f787`;
`source.patch` reconstructs the production and test changes.

The delayed-work model delivers a deletion announcement, withholds kernel
work for three daemon ticks, and requires continued verification without
mutation. After kernel work completes, verification recreates the session
and clears the old task. The preceding implementation fails this witness.

The live regression replays a genuine kernel deletion notice after recreation.
The preceding code fails its first verification tick on Ubuntu
6.8.0-147-generic. The corrected daemon retains the replacement's index, MAC
and UP state through two ticks and keeps verification pending. This tests
stale-notice handling on a live kernel; it does not force delayed kernel work.

Five shared rule cases also cover query errors, completed resync, refused MAC
work, and failed publication through both monitor and L2TP notification paths.
The configuration case checks identity removal/change with failed cleanup,
an untouched query-error fence, and preservation across an entry rename.

## Qualification

Ten stable ordinary suites pass: 235 library cases (17 serial cases ignored),
10 fake cases, 94 external rules and 35 service cases. The library and external
rule declaration lists match exactly. Ten instrumented library repetitions
and three full musl model suites also pass. After the final test-only rename
assertion, ten focused ordinary, ten focused instrumented and three focused
musl repetitions pass. Final common checks and ARM64, RISC-V64 and PowerPC64LE
musl all-target checks pass.

Three stable musl live runs pass all 24 Linux cases in 5.57, 5.60 and 5.63 s.
The first final-source musl normal suite passes all 27 cases in 162.11 s;
`musl-scenarios-1-record` identifies its complete record.
The GNU live collection passes 17 serial library, 24 Linux, five review,
three privileged binary, 29 process and 27 normal scenario cases.
The GNU normal scenarios finish in 158.14 s. Shared-kernel live work is
serialized to preserve the unrelated-event capture's strict zero-query check.

Eight deliberately faulty controls fail: ignored resync query errors,
accepted verification errors, lost monitor and recreation deadlines, premature
cancellation, obsolete-identity retention, retired-announcement acceptance and
using the tunnel identity key for session pruning. Each patch and failure is
retained; controls run outside the profile collector and are restored afterward.

The first fixtures assumed a source address and readiness they had not
established. Their failures remain in `initial-fixture-expectations.log`.
The initial monitor-only missing-deadline control passed because its outer
path already armed the timer; adding the L2TP path exposes the fault.
The initial remove-tunnel configuration fixture also removed child records;
the corrected witness keeps the tunnel and fails session cleanup instead.
These initial results are historical evidence, not acceptance.

## Fresh profiles and remaining proof

The fresh collector is
`target/phase6-coverage-e27-queued-deletion-20261101`, using
nightly-2026-10-28, cargo-llvm-cov 0.9.1 and all features.
Profiles from preceding production implementations are not merged.
`before-retirement/` preserves the narrower correction and its source patch;
those raw profiles were quarantined and the collector cleaned before the
final correction was rebuilt.

The instrumented GNU Incus case passes in 17.20 s and exports seven daemon
profiles. Three stable musl Incus cases pass in 29.47, 24.78 and 24.53 s.
All containers are deleted. Two further musl normal suites pass all 27 cases
in 166.26 and 163.51 s. Their complete records are
`../scenarios-20261101T115814Z-2050684/` and
`../scenarios-20261101T120131Z-2063373/`; the Incus records are
`../incus-20261101T120430Z-2073438/`,
`../incus-20261101T120519Z-2082162/` and
`../incus-20261101T120552Z-2087273/`.

The unmodified root-systemd case passes in 30.93 s on Ubuntu 24.04 /
6.8.0-147-generic. The real user-manager case and three GNU task-limit
runs pass and supply fresh profiles. The first merged report, including
the test-only serial startup harness, is retained in
`../shared-startup-harness-20261101/`: 96.86% lines / 89.68% branches,
leaving 272 lines and 191 branches. No preceding implementation's profiles
or failed-run profiles are merged.

The required matrix now passes all thirteen profiles on frozen production
commit `11bef84`, recorded in
`../matrix-20261101T115808Z-2050597/`. The later iphost correction needs
separate released-dependency qualification.
Complete clause/history/resource proof and 100% coverage remain open.

```sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service
# Repeat seeds 2 through 10; repeat the musl model suite three times.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-e27-queued-deletion-20261101"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/event-verification-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
# Repeat the instrumented library suite ten times.
sh audit/phase6/process-errors-20261031/run-live.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
tests/docker/run.sh incus
tests/docker/run.sh scenarios
tests/docker/run.sh matrix required
```
