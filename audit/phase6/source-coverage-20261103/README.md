# Source coverage before the final shutdown witnesses

Signed base c0a1b3b has identical, empty initial and final source patches.
The collector reports **8,444/8,444 merged source lines and 1,836/1,838
condition outcomes**. The checker exits **1**. This is a failed coverage
gate. The raw LLVM report retains 8,655/8,709 lines and 1,801/1,838 outcomes.

Ten instrumented ordinary collections (seeds 61 through 70), three GNU
live collections, the external live suites, actual manager and task-limit
checks, unprivileged Incus, a buffer-force guest and three newer-kernel
inventory repetitions pass. The command files, full export, source/mapping
inventory and digests retain their exact scope. They do not constitute a
new full required-kernel matrix or complete clause proof.

The missing outcomes are the unbound stale device-index address-addition
case and shutdown between dequeue and dispatch of a ready reload. The
subsequent [witness batch](../final-condition-witnesses-20261103/README.md)
adds direct assertions and fault controls for both.

The extended compiler calibration instantiates repeated same-span match
guards twice. Missing arms stay missing in both generic copies; the complete
fixture passes. Its logs retain the raw and merged reports.
