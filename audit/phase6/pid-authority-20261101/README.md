# PID-file removal authority

A new direct case rejects device and inode mismatches even when the other
field matches. Directory and symlink hints use their actual metadata:
matching numbers must still confer no removal authority. Every rejected hint
leaves the existing file contents and path intact. The original valid proof
still permits cleanup.

The re-exec fixture now passes five encoded states through `restart::entry`:
inspection failure, wrong device, wrong inode, directory and symlink.
Each keeps re-exec processing enabled, discards only PID-file removal
authority and preserves the original file. Each runs in an isolated
self-spawned test process.

The isolated control removes the regular-file check from `PidFile::matches`.
Both the direct and re-exec cases fail. `negative-control.patch` applies to
the candidate; it remains unapplied to shipping code. These are invalid
handover-hint and file-type checks, not a claim of deterministic reproduction
of an inode-replacement race.

## Verification

`revision` plus `source.patch` reconstructs the test changes. Production
logic, dependencies, specifications, Linux adapters and guest fixtures are
unchanged. Existing test-only instrumentation exclusions remain in force;
the tests still execute. The collection host reports `6.8.0-147-generic`.

Focused cases, ten seeded ordinary suites, three musl binary repetitions and
mandatory common strict checks, feature builds, Clippy and rustdoc pass.
The seeded counts are 133 ordinary library, 52 binary, 68 shared fake plus
six fake-only, 88 rules, 30 service cases and startup faults. Cargo build
durations are omitted from retained logs.

Production function, region and branch mappings match exactly. Compatible
native profiles add one covered line and four branch outcomes to the
broader streamed-inventory collection. Coverage is **95.63% lines**
(8,203/8,578) and **87.05% branches** (1,593/1,830), leaving 375 lines
and 237 branches. No production exclusions, profile mismatches or saturated
inferred regions.

The preceding member-recovery and discovery-retry commits pass
[CI run 41267596137](https://github.com/menhera-org/rs-l2tpd/actions/runs/41267596137)
and [CI run 41268176750](https://github.com/menhera-org/rs-l2tpd/actions/runs/41268176750),
respectively, without timeout. The current source's CI, final five-target
qualification, compatible nix release, complete clause/resource/event-cost
proof and 100% report remain open.

```sh
cargo test --locked --all-features --bin rs-l2tpd incorrect_inode_hints_and_nonregular_paths_never_authorize_removal -- --nocapture
cargo test --locked --all-features --bin rs-l2tpd pid_
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd
# Repeat three times.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-streamed-inventories-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --json --output-path /tmp/phase6-pid-authority-coverage.json
# Only in an isolated copy with the final tests:
git --no-pager apply negative-control.patch
cargo test --locked --all-features --bin rs-l2tpd incorrect_inode_hints_and_nonregular_paths_never_authorize_removal -- --nocapture
cargo test --locked --all-features --bin rs-l2tpd pid_metadata_mismatches_and_inspection_errors_discard_only_removal_authority -- --nocapture
# Both must fail their authority assertion.
```
