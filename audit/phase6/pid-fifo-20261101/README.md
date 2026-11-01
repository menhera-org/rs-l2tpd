# Non-regular pre-created PID file

The existing directory-fallback fixture now includes a FIFO. It holds a
nonblocking reader, refuses only O_CREAT opens, then asks the daemon to use
the pre-created inode. Publication must refuse it as an unsafe PID file
before truncation or writing. Its type and inode remain unchanged.

The isolated control omits the regular-file validation. The case then
reaches truncation and reports EINVAL instead of the required unsafe-file
refusal; the regression fails. The control remains unapplied.

A baseline instrumented binary also checks the existing raw-filter fixture's
profile output. Its `PidFile::publish` function count is one and its profile
contains executed fallback counters. An initially considered profiling-helper
change is unnecessary and is removed before final checks. That standalone
baseline probe is not merged into coverage; `baseline-artifact.log` identifies
its source and binary, and `baseline-profile.log` retains its counters.

## Verification

`revision` plus `source.patch` reconstructs the FIFO fixture. Production
logic, profiling helpers, dependencies, specifications, Linux adapters and
guest fixtures are unchanged. Test-only instrumentation exclusions remain
in force while the tests execute. The collection host is
`6.8.0-147-generic`.

The focused fixture, ten seeded ordinary suites, three musl binary suites
and common strict checks, feature builds, Clippy and rustdoc pass. Counts
remain 133 ordinary library, 54 binary, 68 shared fake plus six fake-only,
88 rules, 30 service cases and startup faults. Cargo build durations are
omitted from retained logs.

Production function, region and branch mappings match exactly. Compatible
native profiles add one covered line and two branch outcomes. Coverage is
**95.73% lines** (8,212/8,578) and **87.49% branches** (1,601/1,830),
leaving 366 lines and 229 branches. No production exclusions, profile
mismatches or saturated inferred regions.

The preceding PID-authority source passes both jobs in
[CI run 41269025130](https://github.com/menhera-org/rs-l2tpd/actions/runs/41269025130).
The current test source's CI/final required-kernel qualification, compatible
nix release, full clause/resource/event-cost proof and 100% report remain
open.

```sh
cargo test --locked --all-features --bin rs-l2tpd sticky_warning_and_unwritable_directory_fallbacks -- --nocapture
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd
# Repeat three times.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-streamed-inventories-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --json --output-path /tmp/phase6-pid-fifo-coverage.json
# Separate baseline probe, using the copied binary identified by baseline-artifact.log:
LLVM_PROFILE_FILE=/tmp/phase6-pid-fifo-baseline-%p.profraw PHASE5_PID_CASE=eperm /tmp/phase6-pid-fifo-baseline --exact pidfile::edge_tests::pid_edge_child --nocapture
# llvm-profdata from nightly-2026-10-28:
llvm-profdata show --counts --function=publish /tmp/phase6-pid-fifo-baseline-1323356.profraw
# Only in an isolated copy with the final test:
git --no-pager apply negative-control.patch
cargo test --locked --all-features --bin rs-l2tpd sticky_warning_and_unwritable_directory_fallbacks -- --nocapture
# Expected: FIFO refusal diagnostic mismatch.
```
