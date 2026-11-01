# Bound-member inventory recovery

A tunnel bound to an ordinary device may need its master relationship even
when the master itself is not configured. The new model test creates the
bound member before its parent, with 1, 100 or 10,000 unrelated siblings.
It covers VRF and ordinary masters.

Initial reconciliation and monitor-loss recovery must retain only the bound
member's addresses and master relationship, recognize a VRF parent, and
preserve the socket, binding and selected source. Sibling addresses and
membership records must stay absent. Removing the final dependency releases
all 32 tracked cache/index/queue counts and every deadline.

The isolated negative control removes parent retention from the second
streaming link pass. It fails the expected VRF-parent assertion. The
candidate passes. `negative-control.patch` applies to the final test source;
it is not applied to the shipping implementation.

## Verification

`revision` plus `source.patch` reconstructs the new test. Production code,
dependencies, kernel adapters, specifications and fixtures are unchanged.
The test is in an existing test-only module excluded from instrumentation;
it still executes. The collection host reports `6.8.0-147-generic`.

Ten seeded suites pass: 132 ordinary library cases, 51 binary cases,
68 shared fake cases plus six fake-only cases, 87 rules, 30 service cases
and startup faults. Three musl library/rule suites and the mandatory common
strict checks, feature builds, Clippy and rustdoc pass.

Production function, region and branch mappings match the preceding
streamed-inventory collection exactly. The new native profiles merge with
that implementation's live/process/normal/manager/Incus profiles. Coverage
is **95.51% lines** (8,193/8,578) and **86.34% branches** (1,580/1,830):
385 lines and 250 branches remain. Three additional branch outcomes are
covered. No production exclusions, profile mismatches or saturated inferred
regions. Cargo build durations are omitted from retained logs.

The required five-target matrix is running on frozen production/fixtures
`012764f`; this test-only addition does not change those sources. Final
matrix results, the compatible nix release, complete clause/resource/event
cost proof and 100% coverage remain open. These retained-state assertions
do not measure peak allocator bytes.

```sh
cargo test --locked --all-features --lib bound_member_resync_retains_its_parent_without_sibling_state -- --nocapture
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --test rules
# Repeat three times.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-streamed-inventories-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --json --output-path /tmp/phase6-member-coverage.json
# Negative control, only in an isolated copy with the final unit test:
git --no-pager apply negative-control.patch
cargo test --locked --all-features --lib bound_member_resync_retains_its_parent_without_sibling_state -- --nocapture
# Expected: failed VRF-parent assertion.
```
