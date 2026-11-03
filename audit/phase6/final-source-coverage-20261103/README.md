# First collection with the two condition witnesses

The signed base is c0a1b3b; the initial and final patches identify the
same two test-only source changes. The source/mapping inventory was
captured immediately after the first instrumented ordinary suite, before
adding live profiles. Profiles from the preceding collector were not imported.

The checker exits **1**: **8,443/8,444 merged source lines and
1,837/1,838 condition outcomes**. Both new condition witnesses cover their
intended outcomes. This collection misses the shutdown refusal of an
unsent descriptor-store request at runtime.rs:585 and the restart
shutdown guard's false outcome at service.rs:478. Coverage remains below
the required 100%.

One ordinary suite, the ignored GNU library/process collection, external
Linux/review/filesystem/scenario suites, actual manager/task-limit checks,
unprivileged Incus, a buffer-force guest and three newer-kernel inventory
repetitions pass. The command files, compressed full export, frozen mapping
inventory, digests and individual logs retain the scope.

A follow-up initially used an invalid cargo-llvm-cov argument placement;
tunable-focused.log records the command error. The corrected one-test
run passes but leaves the same coverage misses. That test concerns the
neighboring tunable branch; the missing line is the descriptor-store branch.
The follow-up report is retained separately and does not replace the
original exported measurement.

The [extended witnesses](../final-condition-witnesses-20261103/README.md)
cover store refusal and restart explicitly. They require a fresh collector.
