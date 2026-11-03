# Transient inventory allocation bounds

The proposed integration test passes ten GNU and ten musl repetitions,
plus warning-denied Clippy on both targets. The final fixture is now
registered in the root crate and the common musl test command.

Each repetition checks 18 combinations: ordinary or VRF parents, a
directly bound member or configured VRF, successful or refused second-scan
completion, and 1, 100 or 10,000 sibling devices. Fake host state is
allocated before measurement. The test-only allocator forwards to System
and counts live requested Rust allocation bytes. Calibration checks ordinary
and zeroed allocation, growth, shrink, release and the observed peak.

Unrelated siblings leave the measured extra peak at 1,461 bytes on
successful resync and 957 on second-scan refusal, including 10,000 siblings.
A configured VRF's related members legitimately grow the peak, reaching
1,052,869 and 703,517 bytes respectively at 10,000. These are allocator-
visible Rust bytes, not total RSS or kernel buffer use. The assertion allows
a fixed 16 KiB margin for unrelated state and a linear allowance only for
current dependencies. It also requires recovery, readiness and preservation
of the original tunnel socket and connection.

A deliberate broader parent inventory fails the peak assertion at 10,000
siblings, while the existing retained-state test still passes on the same
faulty code. Disabling peak accounting and forgetting deallocation each
fail calibration. Every mutation is restored. This detects transient
retention that a final cache-size assertion misses.

The initial model passes, but its first Clippy run rejects an unused import.
Both attempts remain recorded. The corrected source adds explicit ordinary
allocation calibration before the twenty successful repetitions. The
proposed test and manifest patch reconstruct that qualified fixture.
The expanded final fixture also measures startup inventory peaks: 18 startup
and 18 resync measurements per repetition, with ten further repetitions per
libc and Clippy passing. Unrelated startup peaks stay at 6,492 bytes for an
ordinary parent and 6,564 for a VRF parent. Related state reaches 2,993,172
bytes at 10,000 members, within its linear bound. A deliberate temporary
full inventory fails the startup bound and is restored. Final source is in
final-test.rs.txt; startup-and-resync/ retains the expanded qualification.
No production code change or dependency is needed.

This is a bounded resync workload, not proof of every allocation site or
of the complete resource promise. Existing history, worker-budget,
descriptor and live-scale checks remain separately required.
