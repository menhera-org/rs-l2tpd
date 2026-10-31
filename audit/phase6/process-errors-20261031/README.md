# Daemon setup and final cleanup errors

Six daemon cases deny stream inspection, changing directory, executable-path
discovery, pipe creation, the first fork and session creation. Each requires
the original errno, exit status 1 within five seconds and an untouched PID-file
sentinel. An independent socket denial keeps a missed fault from reaching
kernel setup; the fork case also guards the next stage with a different errno.
The exec hooks prepare filters in the parent and issue only raw syscalls in
the child. These cases run inside disposable containers or guests.

Both service APIs now have a final cleanup-query case. It waits for the empty
configuration snapshot, advances fake time beyond the retirement deadline,
then refuses the tunnel query. Both return EIO, close local descriptors and
leave eventual kernel deletion to the simulated external lifetime. Session
deletion precedes local socket closure. The earlier draft expected a transient
query error to escape immediately; that expectation was wrong because cleanup
retries before its deadline. Its failed log is retained separately.

The test-only fault helper now exposes its prepared exec hook. Coverage runs
use a distinct profile prefix for each container invocation, so reused
container PIDs cannot overwrite profiles after the helper disables LLVM's
merge pool. There is no shipping-code or dependency change.

## Verification

`revision` plus `source.patch` identifies the tested source. Common checks,
Clippy and ten seeds pass: 126 ordinary library cases, 68 shared fake cases
plus four fake-only cases, 81 rules, 29 service cases and eleven startup,
resolver and descriptor fault paths. ARM64, RISC-V64 and PowerPC64LE musl
all-target builds pass; these are compile checks, not live architecture runs.

| All-feature profile on Ubuntu 6.8.0-147-generic | Result |
|---|---|
| GNU live | 14 library, 19 kernel, five review and three privileged binary cases pass |
| Full process suite | 28 pass |
| Normal scenarios | 26 pass in 159.74 seconds |
| Focused daemon failures | Three GNU and three musl repetitions pass |
| Real user manager | FD-store barrier and address-family checks pass |
| Instrumented unprivileged Incus | Full case passes in 18.41 seconds; seven daemon profiles exported |

Fresh nightly-2026-10-28 / cargo-llvm-cov 0.9.1 coverage is **94.81% lines**
(8,085/8,528) and **84.36% branches** (1,527/1,810). **443 lines and 283
branches remain**. No production path is excluded, no inferred region is
saturated and no profile mismatch is reported. The instrumented process
runs verify failures independently of counters lost across successful exec.
The normal helper's single-threaded pre-`_exit` flush remains unchanged.

Both jobs passed for the preceding monitor source in
[CI run 41247879444](https://github.com/menhera-org/rs-l2tpd/actions/runs/41247879444),
about ten minutes overall. Logs omit Cargo build durations and manager
resource accounting.

The Incus pass does not resolve the
[staged-MAC failure](../staged-mac-override-20261031/README.md).
Unmodified P5 remains pending that decision. The preceding unmodified
[P6 run](../io-faults-20261031/README.md) still applies to unchanged shipping
code. The running required matrix uses that production source and an earlier
fixture set; final consistent-source qualification, complete clause and
resource proof, H11/P5 and 100% coverage remain open.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
cargo check --locked --all-features --all-targets --target aarch64-unknown-linux-musl
# Also riscv64gc-unknown-linux-musl and powerpc64le-unknown-linux-musl.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-process-errors-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/process-errors-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/process-errors-20261031/run-live.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
