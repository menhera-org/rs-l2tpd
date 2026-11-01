# Public service constructors against the live kernel

The new live case opens both public service constructors, using the real
Linux backend in an isolated network namespace. Each API must create its
configured peerless IPv6 tunnel, return readiness twice, transfer its host
receiver only once, reject a capacity change after convergence, and remove
its tunnel before shutdown completes. An independent kernel query checks
existence and removal.

The Tokio lifecycle has a ten-second timeout. The blocking lifecycle runs
on another thread with a ten-second reply deadline; it joins only after
that thread reports completion. Each lifecycle disables global tunable
writes and uses local descriptor ownership, with no host reply required.

## Control and qualification

`revision` identifies the base; `source.patch` adds only this live test.
`ignored-config-control.patch` makes the blocking constructor discard the
configuration. The new case fails because tunnel 11 was never created.
The production file is restored exactly.

The first fixture omitted the explicit family required for a peerless
tunnel. Configuration validation refuses it before either API runs
(`first-live.log`). Its profiles are quarantined outside the collected
directory. The corrected focused case passes.

Three instrumented GNU and three stable musl runs pass all **24 Linux
cases**, including the new lifecycle. Every run uses a disposable privileged
Docker container with `--network none`, a read-only checkout and
`--ignored --nocapture --test-threads=1`. GNU uses
`rs-l2tpd-coverage:phase6` and a writable profile mount; musl uses
`rs-l2tpd-audit-vm:local`. Logs record the kernel and counts. Common checks
pass strict maps, warning checks, feature builds, ordinary GNU/musl tests
and rustdoc. ARM64, RISC-V64 and PowerPC64LE musl all-target checks pass;
these are compile checks, not live execution on those architectures.

```sh
CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-vrf-inventory-state-20261101" \
cargo +nightly-2026-10-28 llvm-cov --locked --all-features \
  --target x86_64-unknown-linux-gnu --branch --no-report --test kernel-linux
cargo test --locked --all-features --target x86_64-unknown-linux-musl \
  --test kernel-linux --no-run
./test-ci-gates.sh
```

## Coverage scope

All 3,937 preceding production function mappings remain unchanged. The new
callback types add nine generic instantiations, for 3,946 mappings. There
are no profile mismatches, saturated regions or production exclusions.
Test-only bodies remain excluded while their tests execute.

The raw Linux-worker counter for the repeated-convergence return at
`src/service.rs:439` rises from zero to eight: two API lifecycles in each
of four completed GNU cases. The extracted counters are retained.
The aggregate report remains **8,338/8,660 lines (96.28%)** and
**1,631/1,848 branches (88.26%)**, leaving **322 lines and 217 branches**.

Current upstream LLVM merges each generic group's
[summaries](https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/tools/llvm-cov/CoverageSummaryInfo.cpp)
with [maximum coverage counts](https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/tools/llvm-cov/CoverageSummaryInfo.h),
rather than a union of covered paths. That matches the observed unchanged
summary despite the new positive counter. Those links describe upstream
main; the local exported counters establish this pinned toolchain's result.
The gate and its reported totals are unchanged.

The frozen required matrix predates this test-only addition. No new Incus,
root-systemd or complete matrix result is claimed by this package.
Phase 6's complete-clause and 100% coverage gates remain open.
