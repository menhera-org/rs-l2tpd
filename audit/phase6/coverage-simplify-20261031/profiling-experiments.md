# Profiling controls

Both experiments use all features, GNU target and nightly-2026-10-28 with
cargo-llvm-cov 0.9.1 on Ubuntu `6.8.0-147-generic`. Their source revision and
patch are retained in their respective folders; the shared syscall helper
is unchanged. Their reports are diagnostic and excluded from final totals.

Continuous collection:

```sh
export RUSTFLAGS='-C llvm-args=-runtime-counter-relocation'
export LLVM_PROFILE_FILE_NAME='rs-l2tpd-%p-%m%c.profraw'
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-simplify-final-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/coverage-simplify-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh "$PHASE6_COVERAGE_RECORD/run-live.sh"
sh "$PHASE6_COVERAGE_RECORD/run-incus.sh"
```

The initial root record paths were used during execution; the logs are now
under `continuous-experiment/`. The full report contains seven saturated
inferred regions, despite successful isolated fork/exec controls.

The next source adds profile writes before `_exit` and exec. It uses ordinary
per-process files and no counter relocation:

```sh
unset RUSTFLAGS LLVM_PROFILE_FILE_NAME
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-simplify-normal-final-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh "$PHASE6_COVERAGE_RECORD/run-live-normal.sh"
sh "$PHASE6_COVERAGE_RECORD/run-incus-normal.sh"
```

Its logs are now under `exec-dump-experiment/`. Two saturated inferred regions
occur in the active lifetime reader. The final source removes exec dumping
and retains only the intermediate child's single-threaded `_exit` write.
The final fresh target is `phase6-coverage-simplify-exit-final-20261031` and
contains no saturated regions.

The standalone controls compile `continuous.rs` with
`-C instrument-coverage -C llvm-args=-runtime-counter-relocation`; ordinary
and `%c` profile names demonstrate lost/retained child and exec counters.
`manual-flush.rs` compiles with only `-C instrument-coverage` and explicitly
writes before the nonreturning operation. Rendered probe reports retain
the exact source for each run; later probe extensions do not rewrite those
historical report contents. A full-daemon check, rather than the small probe,
determines which method is retained.
