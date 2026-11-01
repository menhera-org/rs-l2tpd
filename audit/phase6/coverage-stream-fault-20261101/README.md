# Coverage-safe standard-stream refusal

The daemon setup fixture denied every `fcntl` call to force its standard-stream
check to return EIO. That also prevented LLVM from writing the executed daemon's
profile. The test passed, but its coverage evidence was incomplete.

The fixture now denies only `fcntl(0, F_GETFD)`, the daemon's first stream
probe. The original EIO, exit status 1, untouched PID sentinel and refusal
before kernel startup remain required. All eight setup cases now drain stderr
and reject LLVM profile errors. The stderr drain shares the parent's fixed five-second termination deadline.
The shared helper keeps its existing raw-syscall
installation path; only the new filter examines arguments.

## Checks and control

`revision` identifies the production base. `source.patch` changes test code only.
`broad-control.patch` applies after it and restores the broad streams fault.
The instrumented control fails with the expected LLVM profile-write EIO
(`broad-control.log`, exit 101). Its profiles remain outside the collected
profile directory.

The new subprocess check requires EIO for stdin's descriptor-flags probe,
successful descriptor-flags reads on stdout and an opened file, successful
status-flags reads on stdin and the file, a successful status-flags write, and
EBADF for a nonexistent descriptor. It also rejects a profile-write error.
Actual instrumented daemon runs exercise the profile writer after the fault.

Three instrumented GNU runs and three stable musl runs pass all eight setup
cases. The lifetime-reader and monitor refusal cases also pass three times
on each C library, exercising the shared installer after extraction. Each musl run also passes the descriptor-operation check. Ten seeded
library, binary, process, fake, rule and service suites pass. Common checks
pass Clippy, feature builds, GNU/musl ordinary tests, strict traceability and
rustdoc. ARM64, RISC-V64 and PowerPC64LE musl all-target checks pass; these are
compile checks, not live execution on those architectures.

The first seed command used an invalid Cargo target name and ran no tests.
`initial-seed-driver-refusal.log` retains that refusal; the corrected command
uses `--test kernel-fake`. An overbroad deadline edit also caused a compiler
refusal in an unrelated fixture; that edit was restored before final builds
and repetitions (`initial-timeout-edit-refusal.log`).

## Collection

The command family is:

```sh
CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-vrf-inventory-state-20261101" \
cargo +nightly-2026-10-28 llvm-cov --locked --all-features \
  --target x86_64-unknown-linux-gnu --branch --no-report --test process \
  -- --test-threads=1 --nocapture
cargo test --locked --all-features --target x86_64-unknown-linux-musl \
  --test process --no-run
./test-ci-gates.sh
```

The GNU process executable from `native.log` runs in
`rs-l2tpd-coverage:phase6`; the musl executable runs in
`rs-l2tpd-audit-vm:local`. Both use disposable Docker containers with
`--privileged --network none`, a read-only checkout and the exact filter
`--ignored --exact daemon_setup_failures_return_the_original_error_before_kernel_startup --nocapture --test-threads=1`.
GNU additionally mounts a writable profile directory and sets
`LLVM_PROFILE_FILE=.../streams-N-%p-%m.profraw`. All three completed runs'
profiles are merged into the existing compatible collection. Each log records
the running kernel and all eight `DAEMON_FAULT_CHECKED` markers.

The fresh report covers **8,320/8,660 lines (96.07%)** and **1,628/1,848
branches (88.10%)**, leaving **340 lines and 220 branches**. All 3,937
production function mappings match the preceding report; no saturated regions,
profile mismatches or production exclusions appear. Test-only bodies remain
excluded from instrumentation while their tests run.

The five-target matrix is still running from the frozen production base and
preceding test fixtures. This package does not claim a new kernel-matrix result
or complete clause coverage. Both GitHub jobs for production base 2051827 pass in
[run 41286660781](https://github.com/menhera-org/rs-l2tpd/actions/runs/41286660781).
Phase 6's 100% coverage gate remains open.
