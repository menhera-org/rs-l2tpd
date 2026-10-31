# Unregistered socket ownership and ordered proof failures

An unregistered, bound socket cannot be adopted as a kernel tunnel. Its
connection identifier also stays reserved while an external descriptor holds
it. The fake violated both conditions: it invented a registered tunnel on
adoption and removed the socket metadata after local close. The shared
identifier case now checks both families before its existing registered-tunnel
assertions. The unchanged Linux backend passes the expanded case on Ubuntu
`6.8.0-147-generic`.

`baseline-adoption.log` records the original fake accepting the unregistered
socket. After adding only the adoption guard, `intermediate-bind.log` records
premature identifier reuse. The final fake requires a registered tunnel for
adoption, retains an unregistered socket while external references exist, and
reclaims its metadata on a later tick. The existing external-reference frame
and registered-tunnel tests remain unchanged.

The reference rule follows the bind table and final close in Linux 6.8.12
`net/l2tp/l2tp_ip.c`, `l2tp_ip_bind` and `l2tp_ip_close`, and their IPv6
equivalents. The backend's adoption path separately requires an existing
generic-netlink tunnel record (K19/K37). No shipping Linux-backend, binary or
service behavior changes in this package.

## Additional assertions

Three native socket-backed lifetime tests cover found, removed, forgotten,
absent and failed completions, generation loss during a lookup, an unanswered
five-second lookup, and a refused send. Controlled completion states test the
proof state machine; they are not claimed as actual rtnetlink replies. The
refused-send case uses the kernel's absent NETLINK_USERSOCK endpoint at port
zero, whose ECONNREFUSED result is checked before testing proof cleanup.
Both timeout and refusal must release all pending answers and old proofs.

Three binary tests exercise executable search through missing, directory and
nonexecutable candidates, relative paths and a missing executable, then
compatible, failed, oversized and silent adoption probes. The silent probe
must time out; each probe completes within ten seconds. A new rules case
retires an inherited descriptor with the wrong tunnel or peer identifier by
its exact store name before publishing the correct replacement. Two further
fake scope assertions check IPv6-only mapped refusal and an unplugged binding.

The scratch lifetime/restart logs precede integration and retain their original
scope. `kernel-focused.log` filters the rules target to zero; the dedicated
mismatch case and final full seed/common runs execute it.

## Verification

All features are enabled. `revision` plus `source.patch` identify the tested
source. Common checks and all ten seeds pass: 125 ordinary library cases,
68 shared fake conformance invocations plus four fake-only cases, 81 rules,
28 service cases and eight startup/resolver faults per seed. Native binary
checks pass 48 ordinary cases; four privileged/manager cases run separately.
Formatting, ShellCheck, Clippy, feature builds, strict maps, musl process/
startup checks and warning-denied docs pass.

Fresh GNU profiles use nightly-2026-10-28, cargo-llvm-cov 0.9.1, ordinary
per-process files and the existing single-threaded `_exit` flush.

| Profile on Ubuntu 6.8.0-147-generic | Result |
|---|---|
| Native/live GNU | Ordinary suites, 12 live library, 19 kernel, five review and three privileged binary probes pass |
| Full process suite | 27 pass |
| Normal scenarios | 26 pass in 158.64 seconds |
| Real user manager | FD-store barrier and address-family assertions pass |
| Instrumented unprivileged Incus | Full case passes in 9.07 seconds; seven daemon profiles exported |

Incus observes concurrent udev EBUSY and twice-stable ordered persistent
assignment. This individual pass does not close the
[staged-MAC issue](../staged-mac-override-20261031/README.md); unmodified P5 is
not rerun pending that decision. The preceding unmodified musl
[P6 record](../store-cost-20261031/README.md) remains applicable because
this package changes only fake production code and test bodies.

Fresh coverage is **94.34% lines** (8,051/8,534) and **83.48% branches**
(1,511/1,810), leaving **483 lines and 299 branches**. Fifty-one test-only
modules and one helper exclude instrumentation while all tests execute.
There are no production exclusions, profile mismatches or saturated inferred
regions. Earlier-source profiles are not merged.

Both jobs also pass for the preceding Store source in
[CI run 41242087168](https://github.com/menhera-org/rs-l2tpd/actions/runs/41242087168).
H11/P5, remaining clauses, full resource/event-cost proof, 100% coverage and
the final consistent-source five-target matrix remain open.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-ownership-proof-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/ownership-proof-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/coverage-simplify-20261031/run-live-normal.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```

Logs omit Cargo build durations and user-manager resource accounting.
