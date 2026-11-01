# Tunnel application status and coalesced retries

This implementation was superseded before commit by the final cleanup/rebind
fix in the parent record. Its results qualify only `source.patch` in this
directory. The full diagnostic GNU rerun passes 26 scenarios in 159.71 seconds;
the original timing and packet failures remain unresolved. None of these
profiles is merged with the final production implementation.

`Runtime::reconcile` could report success after a required disconnect or
binding failed. The reconciler ignored each tunnel's application result.
This could also report reload completion while a requested socket change
remained unapplied (L9, M2, M3). A refused peer connection is different:
T1 permits the applied tunnel to remain disconnected while E13 retries it.

The reconciler now includes required socket operations in its application
result without making peer availability a readiness or application gate.
An unspecified source still requires disconnection; a failure of that
cleanup is reported and retried, preserving the recorded binding until
cleanup succeeds. No public signature or dependency changes.

A failed socket operation can arm both the full-reconcile retry and the
per-tunnel retry. When both expired together, one tick attempted the same
connection twice. The tick now removes expired tunnel deadlines before
choosing either the full reconcile or the individual tunnel retries.
Future deadlines remain intact; failed attempts arm their next deadline
once.

## Regressions

- Tunnel setup failures at device lookup, bind and registration close the
  provisional socket and preserve sibling progress. A one-second retry
  creates the missing tunnel and session.
- Required disconnect/bind failures during peer and peerless transitions
  return false, stop the failed transition and preserve the sibling,
  session ownership and socket lifetime through recovery.
- The public runtime reports unapplied required operations while reporting
  an applied disconnected state for a refused peer. Readiness and the
  accepted configuration remain independent.
- An unspecified-source connect followed by failed cleanup remains
  unapplied until recovery. The fake's `fail_after` fixture targets that
  second disconnect; its own test checks one-shot failure and binding state.
- Simultaneous reconcile/peer deadlines perform one connection attempt per
  tunnel and preserve the next absolute deadline.

`baseline-test.patch` adds the rule regressions to `revision` without the
fix. Both isolated controls fail: application unexpectedly returns true,
and one tick makes two connect attempts. `pre-fix-clear-source.log` retains
the intermediate cleanup-status failure before that error was propagated.

## Source and execution scope

`revision` plus `source.patch` reconstructs the final source and fixtures.
`pre-diagnostic-source.patch` identifies the same production implementation
before the scale assertion gained packet-command output. Its three musl
normal runs are retained as `scenarios-1` through `scenarios-3`.
`pre-coalescing-source.patch` and `pre-coalescing-production.log` identify
the earlier implementation; its three normal runs are separate and do not
qualify the final timer change.

The final implementation passes ten seeded ordinary suites: 129 library,
51 binary, 68 shared fake cases plus six fake-only cases, 87 rules, 30
service cases and the startup fault cases. Three musl library/fake/rule
runs pass. Common checks, including strict rule/source maps, Clippy,
musl process/startup cases and documentation, pass. ARM64, RISC-V64 and
PowerPC64LE musl checks pass; those are compile checks only.

Fresh instrumented GNU live collection on Ubuntu 6.8.0-147-generic passes
14 library, 20 Linux, five review, three privileged binary and 28 process
cases. Real user-manager descriptor-store processing and the address-family
filter pass. The unprivileged Incus case passes in 17.36 seconds, exporting
seven daemon profiles. The unmodified stable musl root-systemd case passes
in 31.29 seconds, with `ROOT_SYSTEMD_RESULT=0`.

The three final stable musl normal runs pass all 26 scenarios in 171.53,
180.07 and 158.27 seconds respectively. Check `scenarios-*/run.log` for the
retained results and individual scale measurements.

## Retained GNU failures

The first instrumented GNU normal suite fails two of 26 scenarios, retained
in `live.log`. The route-to-connect observation is 1.000167510 seconds,
168 microseconds beyond its strict one-second assertion. The timestamp is
captured by the test's daemon-log reader. This observation includes timer
scheduling and log-reader scheduling; it does not isolate either delay.
The 300-session case fails the single packet command for session 197,
side 0; its original assertion omitted stdout and stderr. No cause is
claimed for that packet failure.

The scale assertion now retains the complete packet-command output on
failure. Focused instrumented reruns pass both cases, in 4.42 and 66.70
seconds respectively. Passing reruns do not explain or erase the failures;
timing/packet determinism remains open. No deadline, packet assertion or
normative rule was relaxed.

The baseline commit passes both jobs in
[CI run 41258308613](https://github.com/menhera-org/rs-l2tpd/actions/runs/41258308613),
about fifteen minutes overall, without timeout. That result predates this
production change. H11's staged-MAC decision, G23's dependency-state bound,
the compatible nix release, final required-kernel qualification, complete
clause/resource proof and 100% production coverage remain open.

## Commands

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --test kernel-fake --test rules
# Repeat three times; the normal runner also executes three times.
tests/docker/run.sh scenarios
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-tunnel-status-final-20261101"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/tunnel-application-status-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/process-errors-20261031/run-live.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
# Root guest command and artifact identities: root-systemd/command.log and artifacts.log.
```
