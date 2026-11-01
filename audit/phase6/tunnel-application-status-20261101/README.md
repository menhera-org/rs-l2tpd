# Tunnel application status, cleanup binding and coalesced retries

The public runtime could report an applied configuration after a required
disconnect or binding failed. The reconciler ignored each tunnel's
application result. It now propagates those failures without making peer
availability an application or readiness gate: T1 permits an applied,
disconnected tunnel while E13 retries the peer.

A connect that selects an unspecified source must be cleared. That cleanup
also cleared the configured device binding and never restored it. The
reconnect now reuses the existing disconnect-and-bind path, preserving the
configured binding while disconnected. Failed cleanup or restoration stays
unapplied and retries; recorded binding changes follow successful kernel
operations only. No public signature or dependency changes.

Required-operation failures can arm both the full reconcile and per-tunnel
retry. One tick previously attempted the connection twice when both were
due. The tick now removes expired tunnel deadlines before choosing either
a full reconcile or individual tunnel retries. Future deadlines remain
intact; a failed attempt arms its next deadline once.

## Regressions and controls

- Initial lookup, bind and registration failures close provisional sockets,
  preserve sibling progress and recover with the same surviving ownership.
- Peer and peerless transitions stop after required disconnect/bind failure,
  report unapplied work and preserve sessions and sibling sockets.
- The public runtime checks required socket-operation failures,
  refused peer availability, unspecified-source cleanup failure, successful
  binding restoration and refused restoration. Accepted configuration and
  readiness remain independent of application status.
- Simultaneous reconcile/peer deadlines attempt each tunnel once and retain
  the next absolute deadline.
- The fake's one-shot delayed fault targets the second disconnect or bind.
  Its own regression checks operation order, binding state and cleanup.

`revision` plus `source.patch` reconstructs the final implementation and
fixtures. `baseline-test.patch` adds the rule tests to the unchanged
baseline: isolated controls fail on unexpected application success and two
connection attempts in one tick. `pre-fix-clear-source.log` retains the
intermediate ignored-cleanup-error failure.

`rebind-negative-control.patch` restores the pre-rebind cleanup on the final
source. `rebind-before.log` fails because the binding is absent instead of
its configured index. `rebind-after.log` passes the library/fake/rule suites
after the shared cleanup path is used. Test-only bodies remain excluded
from instrumentation under the approved production-code scope.

## Final verification

The final implementation passes ten seeded ordinary suites: 129 library,
51 binary, 68 shared fake cases plus six fake-only cases, 87 rules, 30
service cases and the startup fault cases. The runtime regression exercises
six fault/outcome paths. Three musl library/fake/rule runs pass. Common
checks pass, including strict rule/source maps, Clippy, musl process/startup
cases and documentation. ARM64, RISC-V64 and PowerPC64LE musl all-target/
all-feature checks pass; those are compile checks only.

The unmodified stable musl root-systemd case passes on Ubuntu
6.8.0-147-generic in 29.72 seconds, with `ROOT_SYSTEMD_RESULT=0`.

The final fresh GNU live collection passes 14 library, 20 Linux, five
review, three privileged binary and 28 process cases. Its normal suite
passes all 26 cases in 160.72 seconds, with `LIVE_COVERAGE_RESULT=0`.
The real user-manager processing/filter case passes. The retained full
unprivileged Incus case passes in 30.11 seconds and exports seven daemon
profiles; its temporary container is deleted.

The final stable musl normal run passes 25/26 cases in 170.00 seconds;
H6 fails at an observed route-to-connect delay of 1.000375371 seconds.
The planned three-run loop stops at this failure; no three-pass claim is
made. The [timing proposal](../route-retry-timing-20261101/README.md)
remains unapplied pending a maintainer decision.

Fresh production coverage is **95.46% lines** (8,142/8,529) and
**86.11% branches** (1,562/1,814), leaving **387 lines and 252 branches**.
The collection uses only this production implementation's profiles; none
of the superseded implementation's profiles is merged. There are no
production exclusions, profile mismatches or saturated inferred regions.
Test-only instrumentation exclusions retain the approved production scope.
Cargo build durations and host user-manager resource accounting are omitted.

## Earlier evidence and limitations

`pre-rebind/` retains all qualification of the superseded implementation,
including its original source patches. Its first instrumented GNU normal
run failed the route timing assertion by 168 microseconds and a single
packet command for session 197. The scale assertion now preserves packet
stdout/stderr on failure. Focused reruns and a full 26-case rerun pass;
the causes remain unresolved. No deadline, packet assertion or normative
rule was relaxed. Passing later runs do not erase those failures.

The baseline passes both jobs in
[CI run 41258308613](https://github.com/menhera-org/rs-l2tpd/actions/runs/41258308613),
about fifteen minutes overall, without timeout. That result predates this
production change. Applying the approved H11 and G23 corrections, streamed inventories,
the compatible nix release, final required-kernel qualification, complete
clause/resource proof, timing/packet determinism and 100% production coverage
remain open.

## Commands

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --test kernel-fake --test rules
# Repeat three times; the attempted normal loop stops at its first failure.
tests/docker/run.sh scenarios
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-tunnel-binding-20261101"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/tunnel-application-status-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/process-errors-20261031/run-live.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
# Root guest command and artifact identities: root-systemd/command.log and artifacts.log.
```
