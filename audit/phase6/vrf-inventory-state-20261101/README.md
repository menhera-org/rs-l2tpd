# VRF kind and member inventory

A reload can add a direct VRF binding after the daemon already knows that
VRF as a bound member's parent. The old cache treated its known kind as a
complete member inventory. Existing siblings were never discovered, so
their address additions did not reconnect the newly VRF-bound tunnel (E6).

The cache now records whether a known VRF's member inventory is complete.
A direct binding captures the inventory; an unbound parent's events do not
query its siblings. Removing the last direct dependency clears completion
and releases unwatched siblings. A failed inventory preserves the kind-only
state and permits recovery. The existing VRF collection stores this flag;
no dependency, public API or additional cache collection is introduced.

The ordered-event review also corrected the preceding record's proposed
stale-master finding. A new VRF inventory must preserve an already known
member's previous master until its ordered link event arrives. That history
lets E4 reconnect both affected domains. The corrected ordering test passes
on the preceding code; removing its guard fails. The earlier assertion
before the member event did not establish a bug.

## Reproduction and controls

`revision` identifies f5dabbf; `source.patch` reconstructs the final code
and tests. The preceding source passes the ordered test but fails the
known-parent inventory witness. Its actual daemon also fails the new live
scenario after 10.19 s without the required sibling-address reconnect.
The fixed daemon passes that scenario in 0.65 s, and three instrumented GNU
repetitions pass. Both sessions retain their indexes and exchange frames
before and after sibling address additions/removals. Each change reconnects
only the VRF-bound tunnel, exactly once.

`baseline-tests.patch` and `scenario.patch` apply to `revision`.
`ordering-control.patch` applies after the baseline tests and wrongly
overwrites the prior master. `classification-control.patch` applies after
`source.patch` and wrongly marks a parent-only lookup complete. Both controls
fail their regressions. The final model test additionally checks releasing
and restoring the binding, failed inventory completion, no sibling query
for an indirect parent, and IPv6 sibling-address reconnection.

## Shared-kernel interference

The first full GNU run fails H17 with eight requests in its unrelated-link
window (`initial-live.log`). It overlapped focused container shutdowns
using matching L2TP identifiers. K41 on this kernel forwards those deletion
announcements across namespaces; E27 then requires local identity checks.

The controlled diagnostic `k41-overlap.patch` applies after `source.patch`
and runs on the same Ubuntu 6.8.0-147 kernel. Different foreign identifiers
produce zero requests. Two matching session deletions produce eight
requests, including four generic-netlink requests; four produce sixteen,
including eight generic requests. The captured first request is
L2TP_CMD_SESSION_GET. All four local sessions and their frames survive.
`k41-overlap.log` records both controls. This is an all-namespace-kernel
diagnostic, not an extra portable normal scenario.

The observer now prints its first request header, bounded to twenty bytes,
and failed scale assertions include the complete counters. The zero-query
assertion stays unchanged. The serialized full GNU run passes all 27
scenarios in 159.06 s: H17 captures 400 packets and zero requests.
Failed-run profiles remain quarantined outside the coverage directory;
completed focused-run profiles are retained. Test guidance now serializes
shared-kernel workloads during these captures. Independent QEMU kernels
isolate the notification scope.

## Qualification

Ten seeded ordinary suites and ten instrumented library/fake/rule/service
seeds pass. Final common checks pass strict maps, Clippy, feature builds,
GNU/musl ordinary tests and rustdoc. Current ordinary counts are 137 library,
58 binary, 72 shared fake plus six fake-only, 88 rules, 32 service and three
startup cases. The GNU live collection also passes 14 privileged library,
23 Linux, five review, three privileged binary and 28 process cases.

Three serialized stable musl normal suites pass all 27 cases in 162.48,
159.70 and 162.57 s. Every unrelated-link capture reports zero requests.
The instrumented GNU Incus case passes in 19.85 s and exports seven daemon
profiles. Three stable musl Incus cases pass in 18.82, 9.43 and 20.28 s;
all containers are deleted. The real user-manager case passes, and the
unmodified root-systemd guest passes in 29.97 s. Three real GNU task-limit
runs pass and export compatible profiles. ARM64, RISC-V64 and PowerPC64LE
musl all-target compile checks pass. Guest and manager results retain their
Ubuntu 24.04 / 6.8.0-147 scope.

Fresh production profiles use
`target/phase6-coverage-vrf-inventory-state-20261101`; preceding
implementations' profiles are not merged. Coverage is **96.05% lines**
(8,318/8,660) and **88.04% branches** (1,627/1,848), leaving **342 lines
and 221 branches**. There are no production exclusions, profile mismatches
or saturated regions. Test-only bodies remain excluded while their tests run.
The all-fcntl streams fault still reports an LLVM profile write error;
that existing collector limitation remains P4 work and is retained in the
logs. No malformed profile is reported by the export.

The preceding filtering commit passes both jobs in GitHub run 41281584950,
including the bounded resource step. Its job results are retained separately
from this patch's qualification. This production change still
needs the full required-kernel refresh, complete clause/history proof and
100% coverage. Cargo build durations and host-manager accounting are omitted.

```sh
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-vrf-inventory-state-20261101"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/vrf-inventory-state-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/process-errors-20261031/run-live.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
tests/docker/run.sh incus
tests/docker/run.sh scenarios
# Repeat each musl container suite three times; serialize shared-kernel live work.
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
