# Shared discovery recovery and indexed DNS cancellation

When two tunnels shared an RA-only IPv6 lookup, a successful DHCPv6
discovery retry could leave their shared worker using the old RA-only
snapshot. The retry status described a newly created adapter that the
worker never used. This was a daemon bookkeeping defect; `iphost` already
provided the required discovery state and fallback.

The [baseline regression](baseline-live.log) fails after 35.20 seconds:
DHCPv6 discovery completes, but the recovered primary DNS server receives
no query. The isolated baseline is commit `ba9faeb`, overlaid with only
the new regression in [baseline-test.patch](baseline-test.patch).
The fixture temporarily occupies DHCPv6 port 546, starts two aliases,
answers through RA fallback, releases the port and answers DHCPv6 discovery.
It then requires an actual query to the recovered primary server and
two-address answers for both aliases.

Discovery retries now replace the actual shared worker snapshot when a
complete adapter becomes available. All aliases refer to that current job.
The obsolete call retains its admission charge until it returns; its result
cannot replace the new job's result. Three focused live runs pass in
[0.30](fixed-live-1.log), [0.32](fixed-live-2.log) and
[0.31 seconds](fixed-live-3.log). Their source is recorded in
[upgrade-source.patch](upgrade-source.patch); the final full live suite
also runs the regression after the remaining index changes.

Resolver specifications and host names now index shared jobs directly.
Reference counts release unused jobs and discovery adapters. A separate
lookup-incarnation index directs answers to their tunnel and is updated
on every replacement or removal. Worker owners index their own jobs;
cancellation removes a queue position directly. The ordered queue preserves
the previous rotation, including the position of newly submitted jobs.
The outgoing runtime queue retains the geometric shrinking from `ba9faeb`.

The same [cost workload](workers_cost.rs) runs against both implementations.
Each case creates unrelated jobs, then submits and cancels 500 jobs from
another owner. It asserts that every unrelated job and queue entry survives.

| Unrelated jobs | Baseline individual cancellation | Indexed individual cancellation | Baseline owner drop | Indexed owner drop |
|---|---:|---:|---:|---:|
| 1 | 1.26 ms | 1.71 ms | 1.93 ms | 1.85 ms |
| 300 | 2.66 ms | 2.38 ms | 97.37 ms | 2.49 ms |
| 20,000 | 80.93 ms | 3.25 ms | 8,375.66 ms | 3.59 ms |

[Baseline](cost-baseline.log) and [indexed](cost-indexed.log) logs retain
nanoseconds. Timings are observations, with no timing-based pass threshold.
The indexes remove scans of unrelated jobs from cancellation and owner
drop. Admission still examines the shared rotation to preserve process-wide
fairness; these measurements do not establish complete event-cost proof.

The [alias case](aliases.log) checks shared results, distinct hosts and
resolver specifications, replacement, duplicate cancellation, invalid-host
errors and complete cleanup. The worker tests check rotation, separate
budget classes, snapshot release and queue/owner index consistency.
Four resolver-history epochs remove 300 lookups each and require the new
incarnation index, existing dependency indexes and retry table to return
to zero.

[Common checks](ci-gates.log) and all ten seeded repetitions pass.
[Count checks](seed-counts.log) confirm 105 ordinary library cases,
68 fake cases, 78 rule cases, 27 service cases and six startup faults
per seed, plus eight ownership epochs and four resolver epochs.
The common checks also run musl process/startup cases, strict maps,
Clippy, formatting and warning-denied documentation.

The [preceding CI run](https://github.com/menhera-org/rs-l2tpd/actions/runs/41222708337)
passed both jobs on their first attempts at `ba9faeb`.
[Job metadata](ci/resource-history-jobs.json) is retained.

| Fresh final profile | Result | Evidence |
|---|---|---|
| Native all features | Pass; live cases explicitly ignored | [native.log](native.log) |
| Live GNU probes | 12 library, 19 kernel, five review and three privileged binary cases pass | [live.log](live.log) |
| Full process suite | 27 pass in 17.68 seconds | [live.log](live.log) |
| Normal scenarios | 26 pass in 159.63 seconds | [live.log](live.log) |
| Real user manager | FD-store barrier and address-family checks pass | [manager.log](manager.log) |
| Instrumented unprivileged Incus | Full case passes in 14.37 seconds; seven daemon profiles exported | [incus.log](incus.log), [scenario](incus-scenario.log) |
| Unmodified musl Incus | Full case passes in 18.04 seconds; container deleted | [P5 record](../incus-20261031T174712Z-70259/README.md) |
| Unmodified musl root-systemd | Full P6 case passes in 26.80 seconds with no drop-ins | [root record](root-systemd/README.md) |

All live runs use Ubuntu `6.8.0-147-generic`. Both Incus runs observe the
concurrent udev MAC write refused with EBUSY and retain the kernel address;
both ordered creations get the same persistent address. The root guest's
concurrent creation gets the persistent address. These observations retain
the approved H11 limitations.

[Merged coverage](merged.log) is **92.94% of production lines**
(7,836/8,431) and **80.83% of branches** (1,434/1,774), leaving
**595 lines and 340 branches**. No production code is excluded. This fresh
collection excludes instrumentation for 47 test-only modules and one
helper while executing their tests. Earlier profiles are not merged and
no profile-mismatch warning occurred. Cargo build durations and user-manager
resource accounting are omitted. The 100% coverage gate, complete
clause/event-cost proof and final five-target matrix remain open.

`revision` plus `source.patch` and `workers_cost.rs` reconstruct the
tested source: copy the latter into `src/reconciler/` after applying the
patch. [Source checks](source-checks.log) compare both with the final tree.
The baseline cost run adds this same test module to the archived baseline;
it changes no production code. All features are enabled. Live commands
use disposable networkless containers; profiles use GNU and pinned
nightly-2026-10-28. P5/P6 separately use the unmodified musl binary.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat with seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-resolver-cost-final-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/resolver-cost-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/coverage-current-20261031/run-live.sh
sh audit/phase6/coverage-current-20261031/run-incus.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
tests/docker/run.sh incus
sh tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD
```

The real-manager invocation uses the instrumented binary test executable
listed in `native.log` as `BINARY`:

```sh
unit=phase6-resolver-cost-manager-20261031
systemd-run --user --no-pager --wait --pipe --collect --unit="$unit" \
  --property=Type=notify --property=NotifyAccess=all \
  --property=FileDescriptorStoreMax=8 --property=NoNewPrivileges=yes \
  --property=RuntimeMaxSec=30s \
  --property='RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6' \
  --setenv="PHASE5_NOTIFY_UNIT=$unit.service" \
  --setenv="LLVM_PROFILE_FILE=$CARGO_LLVM_COV_TARGET_DIR/manager-%p-%m.profraw" \
  "$BINARY" --ignored --exact fdstore::manager_tests::actual_manager_processing_and_address_family_filter --nocapture
```
