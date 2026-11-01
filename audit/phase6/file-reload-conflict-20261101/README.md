# File reload refusal and recovery

A valid previous configuration has tunnel identifiers one and two. A new
file gives the first entry an invalid identifier and the second identifier
one. Startup can omit the invalid entry, but reload must retain its previous
value; that conflicts with the valid new entry, so the whole reload is
refused. The test distinguishes this semantic refusal from file errors,
checks ERROR/WARN diagnostics, then repairs the conflict. The next reload
keeps the complete previous first entry, including its peer, and accepts the
second entry's new identifier.

The isolated control reports the refused reload as successful. The regression
fails. `negative-control.patch` includes that control and test against
`revision`; `source.patch` contains only the shipping test. No production
code, dependencies, specifications or guest fixtures change. The initial
fixture omitted required peer addresses from its strict baseline and failed
before reaching reload; `first-focused.log` retains that diagnostic. The
corrected fixture supplies valid peers before final qualification.

Ten seeded ordinary suites, three musl binary suites and common strict
checks, Clippy, feature builds and rustdoc pass. There are 58 ordinary binary
cases; the other counts remain 133 library, 68 shared fake plus six
fake-only, 88 rules, 30 service and three startup cases. The collection
kernel is 6.8.0-147-generic. Cargo build durations are omitted.

Production function, region and branch mappings match exactly. Compatible
native profiles add four covered lines. Coverage is **96.00% lines**
(8,247/8,591) and **87.81% branches** (1,607/1,830), leaving 344 lines and
223 branches. No production exclusions, profile mismatches or saturated
inferred regions are recorded. Test-only helpers stay excluded while all
their tests execute.

The frozen `ce6a70a` matrix and the later thread-resource CI check are
separate qualifications. The event-inventory-cost investigation, complete
clause/resource proof and the 100% report remain open.

```sh
cargo test --locked --all-features --bin rs-l2tpd retained_entry_conflicts_refuse_reload_and_recovery_preserves_the_retained_value -- --nocapture
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd
# Repeat three times.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-libc-signals-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report --bin rs-l2tpd
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
# In an isolated copy of revision:
git --no-pager apply negative-control.patch
cargo test --locked --all-features --bin rs-l2tpd retained_entry_conflicts_refuse_reload_and_recovery_preserves_the_retained_value -- --nocapture
# Expected: refusal assertion fails.
```
