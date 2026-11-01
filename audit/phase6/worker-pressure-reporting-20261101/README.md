# Resolver worker pressure and recovery

The existing report-count test now exercises two worker-pressure episodes.
Each emits one warning while waiting and one information message on recovery.
Repeated polls emit neither warning nor recovery duplicates. The current
lookup, connected IPv6 peer and tunnel socket survive; no kernel mutation is
issued and readiness stays true. The shared Answers fixture exposes pressure
only for a currently watched lookup; an unknown identifier remains false.

`revision` identifies `d413108`; `source.patch` contains only test changes.
Shipping logic, public APIs and the 94 shared rule declarations are unchanged.
Both missing-pressure and missing-recovery controls fail the extended case.
Their production patches are restored before qualification and never run in
the profile collector.

The initial fixture supplied an IPv4 answer to an explicitly IPv6 tunnel.
Its disconnected result was correct; the retained failure is not acceptance.
The corrected fixture uses an IPv6 source and peer and verifies the actual
connection before applying worker pressure.

Ten seeded ordinary library/fake/rule/service/startup suites pass, as do ten
instrumented library repetitions and three full musl library/rule suites.
Ordinary counts remain 235 library cases (17 ignored), ten fake cases,
94 rules, 35 service cases and three startup cases. The instrumented library
has 20 serial ignored cases. Final common checks pass strict maps, feature
builds, GNU/musl ordinary tests, Clippy and rustdoc.

Merged production coverage is **96.92% lines** (8,396/8,663) and
**89.73% branches** (1,660/1,850), leaving **267 lines and 190 branches**.
The fresh E27 collector retains its passing live, Incus, real-manager and
task-limit profiles. There are no production exclusions, profile mismatches
or saturated regions.

All 4,286 common production function mappings are identical. One preceding
mapping disappears: Answers no longer instantiates Resolve's default waiting
method because its test implementation now supplies that method. Production
line and branch denominators remain unchanged; the mapping record names it.

The frozen 11bef84 required matrix is still running. This model fixture does
not establish actual worker saturation or per-kernel behavior; earlier
worker-admission tests retain their own scope. Complete clause/history/
resource proof and 100% coverage remain open.

```sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --test rules
# Repeat three times.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-e27-queued-deletion-20261101"
TEST_SEED=1 cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --lib --branch --no-report
# Repeat seeds 2 through 10.
./test-ci-gates.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
