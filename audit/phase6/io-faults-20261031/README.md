# File and descriptor error paths

New child-only fault cases check standard-stream setup, configuration I/O and
descriptor ownership. They return the original error, retain inherited
descriptors when duplication fails, release partial fake sockets, preserve
successfully read documents, and refuse reloads after a file problem. The
peerless target now constructs its disconnected state directly; its one-use
conversion helper and impossible alternate arm are removed. No dependency or
public signature changes.

Four stream cases cover a failed descriptor probe, a failed null-device open,
and successful/refused duplication after a descriptor-reuse race. Three
descriptor cases cover inherited duplication, partial socket duplication and
socket metadata failure. The original inherited descriptor remains readable
and closes on shutdown; exact descriptor counts check partial cleanup. Four
file cases cover directory enumeration, read, open and metadata failures.
Fixture directories belong to the unfiltered parent, which cleans them up.

## Profiling denied operations

Before installing a fault filter, the test helper opens the current expanded
profile filename and gives its FILE to LLVM's
[profile writer](https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/profile/InstrProfiling.h).
The filename and FILE remain alive until the child exits. An expanded filename
disables pattern-based merging for this per-process file. Exit writes can then
record the tested path even when open or metadata syscalls are denied.
Stable builds omit this profiling setup. Shipping code is unaffected.

The standalone `profile-denial.rs` control denies opens and metadata, observes
EACCES for both, and retains complete profile counts for both operations.
Its separate report is in `profile-denial.log`; those profiles are not merged
into daemon coverage. Real child faults also produce no LLVM profile error.

Two fixture failures are retained. The first common run reaches musl, whose
legacy open syscall escaped the initial openat-only filter. The helper now
denies both spellings on architectures that provide them. The first GNU
collection hits ETXTBSY when another parallel test's fork briefly inherits a
probe script's writable descriptor. The probe fixture now runs in its own
child before creating scripts. Production probe behavior is unchanged.
`initial-collection/` retains the failed collection and its independent
passing P6 run; none of its profiles enter the final report. Earlier draft
descriptor cases omitted a required family, then attempted metadata-dependent
directory enumeration after denying metadata. The final fixture sets the
family and opens its enumeration before the filter.

## Verification

All features are enabled. `revision` plus `source.patch` identify the final
source. Common checks and all ten seeds pass: 125 ordinary library cases,
68 shared fake conformance invocations plus four fake-only cases, 81 rules,
28 service cases and eleven startup/resolver/descriptor fault paths per seed.
Native and musl binary checks pass 50 ordinary cases, with four privileged/
manager cases executed separately. Clippy, formatting, ShellCheck, feature
builds, strict maps and warning-denied docs pass. Final logs are
`common-final.log`, `common-precommit.log` and `seed-*.log`.

Fresh GNU profiles use nightly-2026-10-28, cargo-llvm-cov 0.9.1, ordinary
per-process files and the existing single-threaded `_exit` flush.

| Profile on Ubuntu 6.8.0-147-generic | Result |
|---|---|
| GNU native/live | Ordinary suites, 12 live library, 19 kernel, five review and three privileged binary probes pass |
| Full process suite | 27 pass in 17.52 seconds |
| Normal scenarios | 26 pass in 163.29 seconds |
| Real user manager | FD-store processing barrier and address-family assertions pass |
| Instrumented unprivileged Incus | Full case passes in 19.69 seconds; seven daemon profiles exported |
| Unmodified musl root systemd | Supplied-unit case passes in 27.16 seconds, without drop-ins |

Incus observes concurrent udev EBUSY and twice-stable ordered persistent
assignment. This individual pass does not resolve the
[staged-MAC failure](../staged-mac-override-20261031/README.md). Unmodified P5 is
not rerun pending that decision.

Fresh coverage is **94.50% lines** (8,059/8,528) and **83.87% branches**
(1,518/1,810), leaving **469 lines and 292 branches**. Fifty-one test-only
modules and one helper exclude instrumentation while tests execute. No
production path is excluded; there are no profile mismatches or saturated
inferred regions. Earlier-source and failed-collection profiles are not merged.

Both jobs pass for the preceding fake-handle source in
[CI run 41242867879](https://github.com/menhera-org/rs-l2tpd/actions/runs/41242867879).
A required-kernel matrix is running in an isolated checkout of this final
source, allowing independent later coverage work. Its result is still pending.
H11/P5, remaining clauses, full resource/event-cost proof and 100% coverage
remain open. Logs omit Cargo build durations and user-manager accounting.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-io-faults-final-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/io-faults-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/coverage-simplify-20261031/run-live-normal.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
