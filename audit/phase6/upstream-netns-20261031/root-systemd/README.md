# Root sandbox with released iphost 0.4.2

The full unmodified musl P6 case passes on Ubuntu `6.8.0-147-generic` in
25.88 seconds: `ROOT_SYSTEMD_RESULT=0`. The guest has a real systemd PID 1
in the initial user namespace; the supplied unit has no drop-ins.

[run.log](run.log) retains sandbox, capabilities, module autoload,
network-online, tunable, descriptor-store, re-exec and cleanup assertions.
[command.log](command.log) identifies QEMU, the kernel and interoperability
baseline; [artifacts.log](artifacts.log) identifies executables. The parent
record's `revision` plus `source.patch` reconstruct the tested source.

Command: `sh tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD`.
All features, target `x86_64-unknown-linux-musl`, no coverage instrumentation.
Other userspaces were not executed in this run.
