# Default capacity reporting for custom resolvers

The existing dependency-history test now polls its custom resolver while
all 300 watches are active. That resolver implements only the three required
trait methods. The default capacity hook must not open a worker-pressure
episode for any tunnel. The same four histories still remove all watches,
lookup IDs, retry deadlines and dependency indexes.

A control changes the default hook to report waiting. The new episode
assertion fails; restoring the hook makes the focused test pass.
Ten native and instrumented model/rule/service/startup repetitions, three
musl model runs, the full native suite, common gates, Rust 1.89 and additional
ARM64/RISC-V64/PowerPC64LE musl compile checks pass.

Production code is unchanged from `revision`; the source patches agree.
Coverage reaches **8,503/8,687 lines (97.88%) and 1,702/1,852 branches
(91.90%)**, leaving 184 lines and 150 branches. All 4,327 production mappings
remain identical to the preceding deletion/completion/parser report.
No production exclusion, profile mismatch or saturated region is present.

`commands.sh` records positive commands. This is fake-kernel/custom-resolver
policy evidence; it adds no real DNS traffic, worker-budget exhaustion or
new live kernel/userspace result. Complete clause proof and the 100% gate
remain open.
