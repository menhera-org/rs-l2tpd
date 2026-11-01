# Installer failures preserve files and allow recovery

Three cases exercise the installer's best-effort steps under a temporary
prefix: a missing source executable, a directory at the unit-file path,
and a regular file where the configuration directory belongs. Each must
report overall failure, preserve the existing conflicting object, and
still complete the independent steps. The missing-source case preserves
the installed binary's contents and inode. Removing each obstruction and
retrying must install the expected binary, unit and sample configuration.
No host installation path or system manager is touched.

The isolated control falsely reports failed steps as successful. The new
regression fails at its missing-source assertion. `negative-control.patch`
reconstructs that control against `revision`; it remains unapplied.
`source.patch` reconstructs the shipping test. Production code, dependencies,
specifications and guest fixtures are unchanged. The test is appended after
all production definitions to preserve their coverage coordinates.

Ten seeded ordinary suites, three musl binary suites and common strict
checks, Clippy, feature builds and rustdoc pass. The ordinary binary count
is now 57; other ordinary counts remain 133 library, 68 shared fake plus
six fake-only, 88 rules, 30 service and three startup cases. The collection
kernel is 6.8.0-147-generic. Cargo build durations are omitted.

Production function, region and branch mappings match exactly. Compatible
native binary profiles add five covered lines and three branch outcomes.
Coverage is **95.89% lines** (8,238/8,591) and **87.81% branches**
(1,607/1,830), leaving 353 lines and 223 branches. There are no production
exclusions, profile mismatches or saturated inferred regions. Test-only
helpers remain excluded while their tests execute.

The frozen libc-signal implementation `ce6a70a` is running its required
matrix and CI. Final qualification, complete clause/resource/event-cost
proof and the 100% report remain open.

```sh
cargo test --locked --all-features --bin rs-l2tpd failed_install_steps_preserve_existing_files_and_attempt_the_remaining_steps -- --nocapture
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd
# Repeat three times.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-libc-signals-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report --bin rs-l2tpd
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
# Isolated control, against revision:
git --no-pager apply negative-control.patch
cargo test --locked --all-features --bin rs-l2tpd failed_install_steps_preserve_existing_files_and_attempt_the_remaining_steps -- --nocapture
# Expected: failure at the overall-result assertion.
```
