# Normal guest with released iphost 0.4.2

The complete normal QEMU profile passes on Ubuntu `6.8.0-147-generic`:
`MATRIX_GUEST_RESULT=0`. It includes all 12 live library, 19 kernel and five
review probes, 43 ordinary binary cases plus privileged/child probes,
27 process cases and all 26 normal scenarios. The process suite takes
30.00 seconds; normal scenarios take 575.52 seconds. QEMU exits at roughly
661 guest uptime seconds, within its 900-second limit.

The shared partial-discovery regression that failed in CI now passes in
the full guest's library process. [run.log](run.log) retains all assertions;
[command.log](command.log) identifies the kernel and QEMU command, and
[artifacts.log](artifacts.log) identifies executables. The parent record's
`revision` and `source.patch` reconstruct the unchanged tested source.

Command: `sh tests/kernel/run-guest.sh IMAGE MODULES CONFIG normal RECORD`.
All features, target `x86_64-unknown-linux-musl`, no coverage instrumentation.
This is one required target; the final consistent-source five-target matrix
remains required.
