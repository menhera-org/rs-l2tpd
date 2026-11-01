# Dropping a resolver adapter with current jobs

The new regression starts two adapters with three distinct literal-address
lookups. Dropping the first must release its owner, jobs and scheduling entries,
preserve the second owner's job, and allow the second adapter to receive its
answer. Dropping the survivor must empty the shared state; completed obsolete
calls must return their worker permits.

The test runs in a fresh subprocess so unrelated tests cannot change the global
worker state. Literal addresses provide deterministic local answers without a
DNS peer. The parent enforces a ten-second process deadline; answer/permit polls
share a three-second deadline. Stderr must contain no LLVM profile errors.

`revision` identifies the base; `source.patch` adds only the regression.
`foreign-jobs-control.patch` wrongly clears other owners' jobs during owner
cleanup, and fails the new test. The positive comparison
`without-adapter-destructor.patch` removes the adapter's explicit destructor
and still passes: the worker owner's destructor already performs cleanup.
Neither production patch is applied.

Ten seeded library/fake/rule/service suites, ten instrumented repetitions,
three musl library runs and common checks pass. The ordinary library suite
has 141 passing cases and 14 live cases skipped by that command. Both
production files used by the controls are restored exactly.

```sh
PROPTEST_RNG_SEED=N cargo test --locked --all-features \
  --lib --test kernel-fake --test rules --test service
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib
CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-vrf-inventory-state-20261101" \
cargo +nightly-2026-10-28 llvm-cov --locked --all-features \
  --target x86_64-unknown-linux-gnu --branch --no-report --lib \
  -- dropping_an_adapter_cancels_only_its_jobs_and_preserves_other_answers --nocapture
./test-ci-gates.sh
```

Compatible profiles cover **8,338/8,660 lines (96.28%)** and **1,631/1,848
branches (88.26%)**, leaving **322 lines and 217 branches**. All production
function mappings match the preceding collection, with no profile mismatches,
saturated regions or production exclusions. Test-only bodies remain excluded
while their tests execute.

Production code and live-kernel fixtures are unchanged. The frozen required
matrix continues; full clause proof and the 100% coverage gate remain open.
