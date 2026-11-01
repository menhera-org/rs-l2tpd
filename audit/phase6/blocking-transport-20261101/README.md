# Blocking-service transport errors

Two private transport cases now exercise closed/full command queues and an
abandoned reply. All four public command methods return the original queue
error. A worker that receives a convergence command and drops its sender
causes the original receive error to reach the caller. These cases use
explicit channels, without creating kernel objects.

`revision` identifies `31b431d`; `source.patch` adds only tests after the
production functions. Shipping logic and public APIs are unchanged.
Each `*-control-from-base.patch` applies independently to `revision`:
replacing either original message fails only its corresponding case.
Both controls are restored before qualification and never enter the collector.

Ten seeded library/fake/rule/service/startup runs pass, as do ten instrumented
library repetitions, three full musl library suites and final common checks.
The ordinary library now passes 237 cases with 17 ignored; the instrumented
library has the same 237 ordinary cases and 20 serial ignored cases.
Strict maps, feature builds, GNU/musl ordinary tests, Clippy and rustdoc pass.

Merged coverage is **96.96% lines** (8,400/8,663) and **89.84% branches**
(1,662/1,850), leaving **263 lines and 188 branches**. The fresh E27 collector
retains its passing live, Incus, real-manager and task-limit profiles.
There are no production exclusions, profile mismatches or saturated regions.

All 4,281 common production function mappings are identical. The compiler
emits fourteen new names and removes five preceding names as the command
methods are instantiated by these tests; the complete catalog lists them.
Production line and branch denominators remain unchanged.

This is transport-unit evidence, not a forced failure of an actual service
thread. Existing live constructor and cleanup results retain their scope.
The required matrix remains frozen at 11bef84 and is still running.
Complete clause/history/resource proof and 100% coverage remain open.

```sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib
# Repeat three times.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-e27-queued-deletion-20261101"
TEST_SEED=1 cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --lib --branch --no-report
# Repeat seeds 2 through 10.
./test-ci-gates.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
