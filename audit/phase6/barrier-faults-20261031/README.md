# Descriptor-store barrier failures

Six subprocess cases refuse pipe creation, sending, polling and reading,
including persistent EINTR from poll and read. Hard failures preserve EMFILE
or EIO; interrupted operations still end at the absolute deadline. Every
case returns to its starting count of local descriptors. Read cases receive
the transferred barrier descriptor and close it, making the production read
path ready without a fabricated response.

The test uses the existing syscall-fault helper and a Unix-datagram manager
fixture. Each child owns its filter. A shared listener reference keeps
manager-thread exit from changing the descriptor count being compared.
The initial scratch build exposed an array/slice annotation error; the
corrected scratch and final native cases pass. Shipping code and dependencies
are unchanged.

## Verification

`revision` plus `source.patch` reconstructs the final source. Ten seeded
ordinary suites pass, including all 51 ordinary binary cases and all six
new fault paths per repetition. Library/fake/rules/service/startup counts
remain 127, 68 shared plus four fake-only, 81, 29 and eleven fault paths.
Three musl repetitions pass. Common checks, Clippy and ARM64/RISC-V64/
PowerPC64LE musl all-target builds pass; only x86_64 is executed live.

The new native profiles retain the preceding
[compatible production collection](../inheritance-validation-20261031/README.md).
The production function, region and branch maps match exactly. Final native
profiles execute the six fault cases; only excluded test code changes.
Merged coverage is **95.00% lines** (8,102/8,528) and **84.86% branches**
(1,536/1,810), leaving **426 lines and 274 branches**. There are no production
exclusions, profile mismatches or saturated inferred regions.

Prior live/process/scenario/manager profiles retain their recorded scope.
These Unix fixture results do not substitute for a real systemd manager.
The [required matrix](../matrix-20261031T213935Z-567802/README.md) passes its
earlier fixture set on all five targets. H11/P5, final consistent-source
qualification, complete clause/resource/event-cost proof and 100% coverage
remain open. Logs omit Cargo build durations.

```sh
cargo test --locked --all-features --bin rs-l2tpd failed_barrier_operations -- --nocapture
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd --no-run
# Run the printed musl binary's focused case three times.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-process-errors-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
