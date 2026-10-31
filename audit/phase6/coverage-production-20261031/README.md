# Production-scope coverage baseline

The maintainer approved excluding test-only bodies/helpers from coverage
instrumentation on 2026-10-31. All required tests still execute. The gate
remains 100% lines and branches of production `src/` code.

The fresh merged report covers **90.68% of lines** (7,596/8,377) and
**78.16% of branches** (1,374/1,758). There are **781 missing lines and
384 missing branches**, with **no production exclusions**. The earlier
92.26%/78.16% report included inline test code and has a different
denominator. Neither report satisfies the 100% gate.

| Run | Result | Evidence |
|---|---|---|
| Native all-feature suites | Pass; 92 ordinary library cases, 38 ordinary binary cases, fake/rule/service/process suites and parser checks; live cases remain explicitly ignored here | [native.log](native.log) |
| Live GNU library/kernel/review/binary probes | Pass: 11 live library, 19 kernel, five review and three privileged binary permission cases | [live.log](live.log) |
| Full live process suite | All 27 pass | [live.log](live.log) |
| Normal scenarios | All 26 pass in 159.70 seconds | [live.log](live.log) |
| Real user manager | Actual FD-store/processing/address-family case passes | [manager.log](manager.log) |
| Unprivileged Incus | Buffer FORCE returns EPERM; full manager/udev/networkd/store/re-exec case passes in 17.90 seconds; seven daemon profiles exported; container deleted | [incus.log](incus.log), [incus-scenario.log](incus-scenario.log), [incus-cleanup.log](incus-cleanup.log) |

The Incus concurrent MAC write receives EBUSY and retains the kernel-random
address. Both separately ordered creations receive the same persistent MAC.
The approved manager limitations remain unchanged.

Coverage uses cargo-llvm-cov 0.9.1, pinned nightly-2026-10-28 and the GNU
target. `coverage_nightly` enables `coverage(off)` only on 45 test-only
modules and one test-only report helper. The fake-kernel feature remains
production code for this gate. Stable builds ignore these attributes and
continue running the same tests. [scope-checks.log](scope-checks.log) verifies
that the service and signal test bodies have no counted source regions;
their passing execution remains in the native log. Generic production
instantiations can contain test callback names in their symbols; their
production source regions remain counted.

`revision` plus `source.patch` identify the tested tree. The final source
patch matches exactly. The collection uses a fresh target/profile directory,
so the earlier instrumentation scope is not merged into this report.
[merged.log](merged.log) lists missing lines; [counts.log](counts.log) retains
the totals. Cargo build durations are omitted. Only test execution times
are retained.

From the repository root:

```sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-production-final-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/coverage-production-20261031"
cargo +nightly llvm-cov --color never --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/coverage-current-20261031/run-live.sh
sh audit/phase6/coverage-current-20261031/run-incus.sh
cargo +nightly llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```

The helpers reuse the prepared networkless GNU review image and baseline
peer described in the earlier coverage record; their environment overrides
select this record and profile directory. The real-manager command is
recorded separately in manager.log. The Incus transport retains the existing
runtime directory and sets a coverage-only profile environment; it does not
replace the unmodified musl P5 or root-systemd P6 gate.

CI now installs the pinned nightly for its coverage step, pins cargo-llvm-cov
0.9.1 and generates branch-aware LCOV with this production scope. Stable
checks run first. The new CI configuration still needs its own passing run;
its native-only badge report does not substitute for merged live coverage.
