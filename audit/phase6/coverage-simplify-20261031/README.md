# Smaller validation and service control paths

This batch removes a redundant cookie-length check, the const-only BPF endian
helper, a repeated service dispatch predicate and an unreachable service panic
arm. The existing rename target map now carries its verified registration,
avoiding another impossible state branch. No dependency or public signature
changes. Cookie diagnostics remain exact and redact the supplied value; BPF
constants retain the same byte-order conversion and K10 source citation.

New assertions cover malformed/Unicode cookie diagnostics, disabled host
integration with local socket ownership and AF_INET fallback, capget refusal
with the original EPERM and warning, and disabled/escaped logger records.
The existing child-only syscall refusal helper is shared by startup and binary
tests; it does not alter host limits or capabilities. All service readiness,
shutdown, callback panic and admission cases continue to run.

Common checks and all ten final seeds pass: 117 ordinary library cases,
68 fake conformance cases, 80 rules, 28 service cases and eight startup/resolver
faults per seed. Native binary checks pass 45 ordinary cases, with four live/
manager cases explicitly ignored and executed separately. Formatting,
ShellCheck, Clippy, feature builds, musl process/startup, strict maps and
warning-denied docs pass. `common-exit-only.log`, `common-precommit.log` and
`seed-exit-only-*.log` identify the final method and source; earlier collections
are supplementary.

## Recording nonreturning paths

Ordinary exit-based profiling misses the intermediate daemon child's `_exit`.
A `coverage_nightly`-only flush precedes that call, before daemon threads exist.
It calls LLVM's documented
[profile writer](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html#using-the-profiling-runtime-without-static-initializers).
Shipping builds compile out both the helper and call. No production path is
excluded from instrumentation.

Two investigated alternatives are **not merged into the final report**:

- LLVM continuous mapping retains the isolated fork/exec probe's counters,
  but the full daemon collection has seven saturated inferred regions after
  shared fork counters. `continuous-experiment/` retains that collection.
- Flushing before exec retains isolated probe data, but sampling active reader
  threads yields two saturated inferred regions. `exec-dump-experiment/`
  retains that collection. Those exec flush calls are removed.

`continuous.rs`, `manual-flush.rs` and their rendered reports retain the probes.
The final collection uses ordinary per-process `%p`/`%m` files and only the
single-threaded `_exit` flush. `summary.json` records **zero saturated regions**;
no profile-mismatch warning occurs. A successful exec can still discard its
predecessor's last counters. Process assertions separately prove exec behavior;
uncaptured counters do not count as covered. The final helpers are
`run-live-normal.sh` and `run-incus-normal.sh`; the continuous helpers remain
experiment artifacts.

## Fresh final profiles

| Profile | Result |
|---|---|
| GNU native and live | Ordinary cases, 12 live library, 19 kernel, five review and three privileged binary probes pass |
| Full process suite | 27 pass in 17.69 seconds |
| Normal scenarios | 26 pass in 159.34 seconds |
| Real user manager | FD-store barrier and address-family assertions pass |
| Instrumented unprivileged Incus | Full case passes in 20.32 seconds; seven daemon profiles exported |
| Unmodified musl root systemd | Separate supplied-unit case passes in 28.90 seconds with no drop-ins |
| Unmodified musl Incus | **Fails** staged configured-MAC assertion; retained separately |

All use Ubuntu `6.8.0-147-generic` and all features. Coverage uses GNU with
nightly-2026-10-28 and cargo-llvm-cov 0.9.1. Root and unmodified Incus use stable
musl binaries. The final root run precedes removal of coverage-only exec calls;
those calls are absent from the musl build in either source. Its machine-code
behavior is unchanged by that instrumentation-only removal. The earlier root
run is retained separately as `root-systemd-first/`.

Both instrumented Incus cases observe concurrent udev EBUSY and twice-stable
ordered persistent assignment. The root guest's concurrent creation gets the
persistent address. These individual passes do not close the staged-MAC failure:
[the H11 record](../staged-mac-override-20261031/README.md) reproduces it on the
preceding committed daemon and retains a tested policy control and an
**unapplied** docs/test proposal. P5 determinism remains unresolved.

Fresh final coverage is **93.45% of production lines** (7,922/8,477) and
**81.23% of branches** (1,454/1,790), leaving **555 lines and 336 branches**.
Fifty test-only modules and one helper exclude instrumentation while tests
execute; there are no production exclusions. Earlier-source and experimental
profiles are not merged. The complete clause/resource/event-cost proof,
100% coverage, H11 decision and final consistent-source five-target matrix
remain open.

The preceding rename/recreation source `de8ac73` passes both jobs on the first
attempt in [CI run 41237384642](https://github.com/menhera-org/rs-l2tpd/actions/runs/41237384642),
completing in about eight minutes overall. Job metadata is retained in `ci/`.

`revision` plus `source.patch` and `syscall_fault.rs` reconstruct final code;
copy the helper into `tests/tools/` after applying the patch. Logs omit Cargo
build durations and user-manager CPU/memory accounting.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-simplify-exit-final-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/coverage-simplify-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh "$PHASE6_COVERAGE_RECORD/run-live-normal.sh"
sh "$PHASE6_COVERAGE_RECORD/run-incus-normal.sh"
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```

The real-manager command follows the preceding lookup record, with unit
`phase6-simplify-exit-manager-20261031` and this collection's instrumented binary.
