# Subscription failures and reactor recovery

New socket-backed assertions cover monitor-open refusal, reactor registration
refusal, receive overflow, other receive errors and reactor shutdown. Overflow
reports loss while retaining the socket; other receive errors discard it.
Registration failure reports loss, waits until its retry deadline and makes
only one reopen attempt. A feed registered on a stopped runtime reports loss
before registering on the next runtime. Malformed/unrelated decoded messages
remain unusable notices.

A lifetime-reader case injects poll/receive errors and refuses subsequent
socket opens. The generation ends, pending state is released, an old proof is
lost and dropping the reader completes within three seconds. It does not
establish every failed-reopen scheduling path; uncovered paths remain in P4.
The fault fixtures fork only in the serial isolated live runner, avoiding
the previously demonstrated inheritance of concurrent fake descriptors.

An ARM64 test-build check exposed two fixture assumptions: legacy dup2 and
poll syscalls are absent there. Duplication filters now cover dup3 and legacy
dup2 where available; the reader filter includes ppoll. All-target/all-feature
musl checks pass for ARM64, RISC-V64 and PowerPC64LE. These are build checks,
not live runs on those architectures. Daemon behavior and dependencies are
unchanged. The first source-link draft rejected three unnecessary logger
methods; they were removed, and the strict check passes without new citations
for unrelated logging code.

## Verification and profiles

`revision` plus `source.patch` reconstruct the final source. Common checks and
all ten final seeds pass: 126 ordinary library cases, 68 shared fake cases
plus four fake-only cases, 81 rules, 28 service cases and eleven startup/
resolver/descriptor faults. Binary tests pass 50 ordinary cases, with four
privileged/manager cases executed separately. The two new forking fault
declarations are explicitly ignored by ordinary runs and executed live.

| All-feature profile on Ubuntu 6.8.0-147-generic | Result |
|---|---|
| GNU live | 14 library, 19 kernel, five review and three privileged binary cases pass |
| Full process suite | 27 pass |
| Normal scenarios | 26 pass in 159.09 seconds |
| Final fault fixtures | Three GNU and three musl repetitions pass, including open refusal |
| Real user manager | FD-store barrier and address-family assertions pass |
| Instrumented unprivileged Incus | Full case passes in 9.07 seconds; seven daemon profiles exported |

GNU coverage uses nightly-2026-10-28 and cargo-llvm-cov 0.9.1. Only test code
changes during this collection: the production function/region/branch
mappings match before and after those corrections (`mapping-check.log`).
Full live/scenario/Incus profiles precede the final fixture corrections;
fresh native and focused GNU/musl runs execute the final fixtures. No profile
from a different production implementation is merged. The extra helper module
is test-only, with its unsafe allowance confined to fault installation.

Fresh coverage is **94.72% lines** (8,078/8,528) and **84.20% branches**
(1,524/1,810), leaving **450 lines and 286 branches**. Fifty-two test-only
modules and one helper exclude instrumentation while tests execute. No
production path is excluded; there are no mismatches or saturated inferred
regions. LLVM reports all 18 monitor branches covered, but only 92/94 of that
file's lines. `monitor-lines.txt` is a diagnostic source view, not a replacement
for the reported totals.

Incus observes concurrent udev EBUSY and twice-stable ordered persistent
assignment. Its individual pass does not resolve the
[staged-MAC failure](../staged-mac-override-20261031/README.md); unmodified P5
is not rerun pending that decision. The preceding unmodified
[P6 profile](../io-faults-20261031/README.md) remains applicable because all
changes are test-only. The isolated matrix uses the preceding production
source and earlier fixture set; final consistent-source qualification remains
open, along with H11/P5, complete clause/resource/event-cost proof and 100%
coverage.

Both jobs pass for the preceding I/O source in
[CI run 41245243701](https://github.com/menhera-org/rs-l2tpd/actions/runs/41245243701),
about fifteen minutes overall. Logs omit Cargo build durations and manager
resource accounting. Final executions are `native-complete.log`,
`gnu-faults-complete-*.log`, `musl-faults-complete-*.log` and
`seed-final-*.log`; earlier focused runs retain their narrower scope.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
cargo check --locked --all-features --all-targets --target aarch64-unknown-linux-musl
# Also riscv64gc-unknown-linux-musl and powerpc64le-unknown-linux-musl.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-monitor-faults-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/monitor-faults-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/coverage-simplify-20261031/run-live-normal.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
