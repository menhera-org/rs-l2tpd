# Descriptor inheritance and cleanup fallback

The new binary test runs eleven isolated subprocess cases:

- A valid named descriptor retains ownership, receives close-on-exec, and
  carries the advertised store capacity and notify address.
- Invalid, negative and excessive counts return their precise refusal.
- Missing, extra and control-containing names are refused. The announced
  descriptor is closed, along with an unannounced descriptor.
- An announced but absent descriptor returns the cleanup refusal.
- A foreign LISTEN_PID makes its malformed count irrelevant; unannounced
  descriptors close and malformed capacity becomes zero.
- Refused close_range falls back to closing through the hard descriptor limit.
  A descriptor above the reduced soft limit must close.
- Failure to obtain that limit preserves the original EIO and returns before
  descriptor cleanup or environment consumption can be claimed.

Each child has a five-second deadline. Environment changes, descriptor
replacement and lowered resource limits stay in that disposable subprocess.
The fault filter preserves file operations so LLVM can write its profile
after inheritance. Every child must exit successfully without a profile error.

Three production controls fail: using the soft limit, omitting name
validation and clearing close-on-exec. Their minimal patches apply cleanly
after exact restoration. Shipping behavior is unchanged.

Ten ordinary and ten instrumented repetitions pass all eleven cases.
Three full musl binary suites pass 59 ordinary cases; four privileged/manager
cases remain in their separately recorded profiles. ARM64, RISC-V64 and
PowerPC64LE all-target checks and final common checks pass.

`revision` identifies the base and `source.patch` adds only the test module.

```sh
cargo test --locked --all-features --bin rs-l2tpd -- fdstore::inheritance_tests --nocapture
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd
CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-vrf-inventory-state-20261101" \
cargo +nightly-2026-10-28 llvm-cov --locked --all-features \
  --target x86_64-unknown-linux-gnu --branch --no-report \
  --bin rs-l2tpd -- fdstore::inheritance_tests --nocapture
./test-ci-gates.sh
```

Compatible profiles cover **8,372/8,660 lines (96.67%)** and
**1,650/1,848 branches (89.29%)**, leaving **288 lines and 198 branches**.
The 3,952 function names and all source-region shapes are unchanged.
Two previously unexecuted binary-test instances (inherit and close_from)
now have 110 and 80 calls and expose nine branch records; their preceding
JSON entries had zero calls and empty branch arrays. The other 3,950
mappings are identical. Both denominators are unchanged, with no profile
mismatches, saturated regions or production exclusions.

These are real descriptor/syscall checks on the recorded kernel. They add
no L2TP scenario, QEMU, Incus or root-systemd result. Complete clause/history
proof and 100% coverage remain open.
