# PID publication and removal faults

Eight isolated child-process cases refuse the syscalls used for directory
creation, directory-mode correction, truncation, sync, rename, unlink and
entropy acquisition. The directory-creation pair returns either EIO or
EEXIST: when the subsequent open still finds no directory, the daemon must
return ENOENT from that open. This models the reported creation race and
its missing final object; it does not reproduce concurrent mkdir calls.

The other filesystem faults return their original EIO. The entropy case
first confirms the dependency receives EIO, then requires the PID
publication error to retain its exact diagnostic. Every failed publication
preserves the existing file and removes temporary names. Refused unlink
returns an error and leaves the file intact. Each fixture's parent owns
and cleans its directory after the child exits.

An isolated negative control omits temporary-name cleanup. The truncation
case fails with `temporary PID file remains`. The control patch is not
applied to shipping code.

## Entropy fixture corrections

The first fixture used EPERM and unexpectedly published successfully.
[Getrandom 0.3.4 deliberately selects its file fallback on Linux EPERM](https://github.com/rust-random/getrandom/blob/v0.3.4/src/backends/linux_android_with_fallback.rs#L45-L55).
The final fault is EIO, which does not select that fallback. The second
fixture assumed the dependency used std's error spelling; this build
reports `OS Error: 5`. The final test verifies the raw upstream errno and
compares the propagated diagnostic with that upstream error. Both original
diagnostics are retained, along with the source identity in
`entropy-source.json`. Neither failure requires a production change.

## Verification

`revision` plus `source.patch` reconstructs the final tests. Shipping logic,
Linux adapters, dependencies, specifications and guest fixtures are unchanged.
The new module uses the existing syscall-fault helper and test-only
instrumentation exclusion. The tests still execute; `kernel` records the
collection host's release, `6.8.0-147-generic`.

Ten seeded suites pass: 133 ordinary library, 54 binary, 68 shared fake plus
six fake-only, 88 rules, 30 service cases and startup faults. Three musl
binary suites and common strict checks, feature builds, Clippy and rustdoc
pass. ARM64, RISC-V64 and PowerPC64LE musl all-target/all-feature compile
checks pass; they are not live architecture tests. Rename refusal includes
the target's available syscall spellings. Cargo build durations and registry
progress are omitted from retained logs.

Production function, region and branch mappings match exactly. Compatible
native profiles add eight covered lines and six branch outcomes. Coverage
is **95.72% lines** (8,211/8,578) and **87.38% branches** (1,599/1,830),
leaving 367 lines and 231 branches. No production exclusions, profile
mismatches or saturated inferred regions.

The current test source's CI and required-kernel qualification, compatible
nix release, complete clause/resource/event-cost proof and 100% report
remain open. The frozen matrix still qualifies its recorded source and
fixtures separately.

```sh
cargo test --locked --all-features --bin rs-l2tpd publication_and_removal_faults_preserve_existing_files_and_clear_temporary_names -- --nocapture
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd
# Repeat three times.
cargo check --locked --all-features --all-targets --target aarch64-unknown-linux-musl
cargo check --locked --all-features --all-targets --target riscv64gc-unknown-linux-musl
cargo check --locked --all-features --all-targets --target powerpc64le-unknown-linux-musl
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-streamed-inventories-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --json --output-path /tmp/phase6-pid-faults-coverage.json
# Only in an isolated copy with the final tests:
git --no-pager apply negative-control.patch
cargo test --locked --all-features --bin rs-l2tpd publication_and_removal_faults_preserve_existing_files_and_clear_temporary_names -- --nocapture
# Expected: retained temporary PID file after failed truncation.
```
