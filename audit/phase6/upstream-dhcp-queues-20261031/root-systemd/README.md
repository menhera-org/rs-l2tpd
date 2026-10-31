# Root sandbox with released iphost 0.4.3

The unmodified musl P6 case passes on Ubuntu `6.8.0-147-generic` in
27.27 seconds: `ROOT_SYSTEMD_RESULT=0`. A real systemd PID 1 runs in the
guest's initial user namespace; the supplied unit has no drop-ins.

[run.log](run.log) retains sandbox, capability, module-autoload,
network-online, tunable, descriptor-store, re-exec and cleanup assertions.
[command.log](command.log) identifies QEMU and the kernel;
[artifacts.log](artifacts.log) identifies executables. The parent record's
`revision` and `initial-source.patch` reconstruct the tested production
tree. Its later readiness-test addition does not change production bodies.

Command: `sh tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD`.
All features, target `x86_64-unknown-linux-musl`, no coverage instrumentation.
Other userspaces were not executed here.
