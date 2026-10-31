# Resource history and retained queue storage

Two regressions reproduced storage retained after work completed. Cancelling
300 DNS jobs left capacity for 512 queue entries with one job remaining.
Completing 128 descriptor-store retirements left 129 outgoing queue slots
with one tunnel remaining. [DNS regression](worker-only/queue-regression.log)
and [outgoing regression](outgoing-regression.log) retain both failures.

The DNS queue now shrinks after cancellation and owner drop; the outgoing
queue shrinks after dequeue. Both use geometric shrinking: capacity follows
the current queue length with a small fixed allowance, rather than peak
configuration history. Ordering, admission budgets and public APIs are unchanged.

| Proof | Workload and result |
|---|---|
| Ownership and event indexes | Eight distinct configuration epochs add/remove 1, 100 or 300 tunnels and sessions. All 29 record/index/cache counts return to the same single-survivor snapshot; its interface index is preserved. |
| Resolver dependencies | Four epochs each remove 300 lookups after testing missing-device retries and device recovery. Watches, retries, name indexes and device indexes return to zero. |
| Reports | Eight epochs grow to 601 condition records, then release all removed entries' conditions while retaining the survivor's episode. |
| DNS queue and snapshots | Cancellation and owner drop release all 300 queued snapshots. Capacity stays within the geometric bound after each cancellation and is at most 16 with one remaining job. |
| Outgoing requests | After 129 stored tunnels shrink to one and all 128 withdrawals complete, only one socket remains, the outgoing queue is empty and capacity is at most 16. |

The first combined run exhausted descriptors when the new large fake
namespaces overlapped the existing scale fixture. A shared test gate now
serializes those large workloads. Their sizes and assertions remain unchanged.
[The failed common run](worker-only/before-workload-gate-ci.log) and
[failed coverage run](worker-only/before-workload-gate-coverage.log) remain
recorded. A draft resolver fixture also incorrectly required `unwatch` to
refer to an already-started lookup; the existing contract permits idempotent
stops. [That draft failure](worker-only/draft.log) is retained.

[Final common checks](ci-gates.log) and all ten seeded repetitions pass.
Each seed executes 102 ordinary library cases, 68 shared cases in one fake
wrapper, 78 rules, 27 service cases and the six-fault startup case.
[Count checks](seed-counts.log) also verify all eight ownership epochs and
four resolver epochs. The common checks include musl binary/process/startup
cases, strict maps, Clippy, formatting and warning-denied documentation.

| Fresh final profile | Result | Evidence |
|---|---|---|
| Native all-feature coverage | Pass, with live tests explicitly ignored | [native.log](native.log) |
| Live GNU library/kernel/review probes | 11 library, 19 kernel and five review cases pass, plus three privileged binary probes | [live.log](live.log) |
| Full process suite | All 27 pass | [live.log](live.log) |
| Normal scenarios | All 26 pass in 158.94 seconds | [live.log](live.log) |
| Real user manager | FD-store, processing barrier and address-family check pass | [manager.log](manager.log) |
| Instrumented unprivileged Incus | Full case passes in 13.47 seconds; seven daemon profiles exported; container deleted | [incus.log](incus.log), [scenario](incus-scenario.log), [cleanup](incus-cleanup.log) |
| Unmodified musl Incus | Full case passes in 22.38 seconds; container deleted | [P5 record](../incus-20261031T164656Z-11386/README.md) |
| Unmodified musl root-systemd | Full P6 case passes in 27.46 seconds with no drop-ins | [root record](root-systemd/README.md) |

The live kernel is Ubuntu `6.8.0-147-generic`. Both Incus profiles observe
EBUSY when udev loses the concurrent MAC-write race, preserving the kernel
address. Both ordered creations receive the same persistent address. The
approved H11 limitations remain unchanged.

Merged coverage is **92.79% of production lines** (7,782/8,387) and
**80.19% of branches** (1,413/1,762), leaving **605 lines and 349 branches**.
There are no production exclusions. The 100% gate remains open. These
container/table/capacity checks strengthen resource-history proof; complete
event-cost and clause proof remain open.

The final collection uses a fresh target/profile directory, all features,
GNU, cargo-llvm-cov 0.9.1 and pinned nightly-2026-10-28. Its 46 test-only
modules and one test-only report helper are excluded from instrumentation;
all required tests still execute. Earlier profiles, including the intermediate
worker-only collection, are not merged into this report. [Source checks](source-checks.log)
confirm matching initial/final patches and matching source for the unmodified
root-systemd run. `revision` plus `source.patch` reconstruct the tested tree.
[Merged report](merged.log) and [counts](counts.log) retain the result.
No profile-mismatch warning occurred. Cargo build durations and user-manager
resource accounting are omitted.

The [intermediate collection](worker-only/merged.log) contains only the DNS
queue fix: 92.76% lines / 80.06% branches. Its normal scenarios pass in
157.08 seconds; its unmodified root-systemd case passes in 27.25 seconds.
Its source and logs remain under `worker-only/`, and its separate
[musl Incus record](../incus-20261031T163656Z-4188917/README.md) is preserved.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat with seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-resource-queues-final-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/resource-history-20261031"
cargo +nightly llvm-cov --color never --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/coverage-current-20261031/run-live.sh
sh audit/phase6/coverage-current-20261031/run-incus.sh
cargo +nightly llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
tests/docker/run.sh incus
sh tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD
```

The real-manager command is in manager.log. The coverage-only Incus transport
preserves its runtime directory; it remains separate from the unmodified
musl P5/P6 gates. The final five-target matrix is still required. Official
archive resolution still selects Ubuntu generic meta versions
[6.8.0-147.147](kernel-resolution/noble.log) and
[7.0.0-42.42](kernel-resolution/resolute.log); the final matrix resolves again.

Both jobs passed on their first attempts for the preceding
[process CI run 41218466550](https://github.com/menhera-org/rs-l2tpd/actions/runs/41218466550)
at `df7d97b` and
[closed-handle run 41219328717](https://github.com/menhera-org/rs-l2tpd/actions/runs/41219328717)
at `0903d55`. Their [job metadata](worker-only/ci/closed-jobs.json) is retained
with the intermediate record. This package needs its own CI run after commit.
