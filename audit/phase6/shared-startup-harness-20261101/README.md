# Serial startup fault cases in the library coverage harness

The instrumented library reuses the three startup subprocess declarations.
They test descriptor refusals, resolver-thread refusals, and service
thread/runtime refusals while preserving inherited descriptor names and
ownership. The ordinary external startup target still runs all three cases.
Shipping logic, dependencies and public APIs are unchanged.

`revision` identifies production commit `11bef84`; `source.patch`
reconstructs the test-only change. The production correction's live,
Incus, root-systemd, real-manager and task-limit results remain in
`../event-verification-20261101/`. Its required matrix is running in a
separate frozen checkout.

## Isolation and controls

Launching children can retain concurrent fake socket descriptors between
fork and exec. The initial parallel shared runs fail other fake cleanup
assertions; both logs are retained. The added library module therefore
exists only in the instrumented build, and its cases use the serial ignored
profile. Instrumented external copies are ignored; the serial library run
executes the same declarations. Ordinary external copies remain enabled.

Child selection derives the module prefix and retains exact matching.
The final `bare-name-control.patch` applies after `source.patch` and fails
all three serial cases: each parent rejects a child that selected no test.
The earlier serial attempt omitted ignored-test selection in its children;
the corrected command includes it. Its failure and the initial focused
result remain historical evidence.

All failed instrumented attempts and the final control have their raw
profiles quarantined outside the collector. Accepted profiles come only
from passing runs. No assertion, exclusion or production rule was weakened.

## Qualification and coverage

Ten final seeded ordinary runs pass 235 library cases (17 ignored), ten
fake cases, 94 rules, 35 service cases and all three external startup cases.
Ten instrumented repetitions pass the ordinary library suite and all three
serial startup cases. A final restored-source serial run also passes.
Three full musl library/startup runs and three final focused musl startup
runs pass. Final common checks pass strict maps, feature builds, GNU/musl
ordinary tests, Clippy and rustdoc. The common run follows the control's
restoration.

The fresh E27 collector uses nightly-2026-10-28, cargo-llvm-cov 0.9.1,
all features and branch reporting. Merged coverage is **96.86% lines**
(8,391/8,663) and **89.68% branches** (1,659/1,850), leaving **272 lines
and 191 branches**. There are no production exclusions, profile mismatches
or saturated regions. Test-only bodies stay excluded while their tests run.

The interim E27 catalog had 3,958 function names; the current catalog has
4,287. All 3,949 common names retain identical source regions and filenames.
Nine of those now expose branch records. Nine preceding names disappear
and 338 are added as the library harness instantiates the startup paths.
Line and branch denominators stay at 8,663 and 1,850. The retained mapping,
execution and summary files expose these differences; this is not a claim
that every generic-instance mapping is identical.

Complete clause/history/resource proof and the 100% gate remain open.
Kernel-matrix completion is still required for production commit 11bef84.
The test harness does not establish kernel behavior by itself.

```sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --test startup
# Repeat three times; final focused startup runs also repeat three times.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-e27-queued-deletion-20261101"
TEST_SEED=1 cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --lib --test startup --branch --no-report
TEST_SEED=1 cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --lib --branch --no-report -- --ignored startup_tests:: --nocapture --test-threads=1
# Repeat both instrumented commands for seeds 2 through 10.
./test-ci-gates.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
