# Indexed descriptor retirement and host requests

Stale withdrawal acknowledgements previously scanned every retirement and
advanced unrelated work. A baseline regression consumes a second injected
lookup error from an unrelated tunnel. The corrected implementation queries
only the acknowledged retirement and leaves that second error untouched.
The baseline is `de8ac73`, whose production Store code is unchanged through
the recorded parent revision; only the two regression cases were appended.

Current indexes map withdrawal tokens to names/deadlines, count retirement
aliases per tunnel identifier and select due work. Timeout, refusal, duplicate
and late acknowledgements retain their existing bounded cleanup behavior.
Full reconciliation and shutdown explicitly reschedule pending work. Completed
retirements release every index entry. Named host requests use ordered entries
and a name index, preserving FIFO order and closing replaced Store descriptors.
This removes the repeated queue scans in a batch of withdrawals. Public
signatures and dependencies are unchanged.

Five test cases cover these paths. Repeated histories grow from one to 300
retirements twice and shrink to one, retain an unrelated anchor, and verify
exact token, deadline and identifier counts after cleanup. Two aliases sharing
an identifier block it until both finish. A thousand queued replacements keep
only current entries; descriptor ownership and shutdown cancellation are
asserted. The existing whole-reconciler history check now includes 32
collections. These cases establish this batch's scope, not the entire resource
or event-cost requirement.

For 500 stale acknowledgements with 20,000 unrelated retirements, the baseline
records 809.49 ms and the indexed run 0.386 ms. Timing is supporting evidence;
the targeted-query assertion and index-size assertions enforce the behavior.

## Verification

All features are enabled. `revision` and `source.patch` identify the tested
source. Common checks pass formatting, ShellCheck, Clippy, feature builds,
strict traceability, musl process/startup tests and warning-denied docs. Ten
seeds each pass 122 ordinary library cases, 68 shared fake conformance cases,
80 rules, 28 service cases and eight startup/resolver fault paths. Native
binary tests pass 45 ordinary cases; four privileged/manager cases execute
separately. The initial focused command filtered the other targets to zero;
`full-queued.log` and the final seed logs execute their suites.

Fresh GNU profiles use nightly-2026-10-28, cargo-llvm-cov 0.9.1 and ordinary
per-process profiles with the existing single-threaded `_exit` flush.

| Profile on Ubuntu 6.8.0-147-generic | Result |
|---|---|
| GNU native/live | Ordinary cases, 12 live library, 19 kernel, five review and three privileged binary probes pass |
| Full process suite | 27 pass |
| Normal scenarios | 26 pass in 158.83 seconds |
| Real user manager | FD-store barrier and address-family restrictions pass |
| Instrumented unprivileged Incus | Full case passes in 18.75 seconds; seven daemon profiles exported |
| Unmodified musl root systemd | Supplied-unit case passes in 28.78 seconds, without drop-ins |

The Incus case observes concurrent udev EBUSY and twice-stable ordered
persistent assignment. This individual pass does not resolve the
[separate staged-MAC failure](../staged-mac-override-20261031/README.md).
The unmodified P5 case is not rerun pending that contract decision. The root
record in `root-systemd/` contains the exact guest command and kernel config.

Fresh coverage is **93.48% lines** (7,970/8,526) and **81.54% branches**
(1,471/1,804), leaving **556 lines and 333 branches**. Fifty-one test-only
modules and one helper exclude instrumentation while tests execute. No
production path is excluded, no profile-mismatch warning occurs and the JSON
has zero saturated inferred regions. Earlier-source profiles are not merged.

The parent source passes both jobs on the first attempt in
[CI run 41240599787](https://github.com/menhera-org/rs-l2tpd/actions/runs/41240599787),
about nine minutes overall. H11/P5, remaining clauses, full resource/event-cost
proof, 100% coverage and the final consistent-source matrix remain open.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-store-final-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/store-cost-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/coverage-simplify-20261031/run-live-normal.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```

Logs omit Cargo build durations and user-manager resource accounting.
