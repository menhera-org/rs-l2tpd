# Root sandbox after the queue-storage fixes

The full unmodified musl P6 case passes on Ubuntu `6.8.0-147-generic` in
27.46 seconds: `ROOT_SYSTEMD_RESULT=0`. The guest runs a real systemd PID 1
in the initial user namespace. The supplied unit has no drop-ins.

[run.log](run.log) retains the actual sandbox, capability, module-autoload,
network-online, tunable, descriptor-store, re-exec and cleanup assertions.
[command.log](command.log) records QEMU and kernel/baseline identities;
[artifacts.log](artifacts.log) records executable identities. `revision` and
`source.patch` match the final resource-history coverage tree.

Run `sh tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD` with
the matching stock Ubuntu image/modules/config and prepared systemd userspace.
Features are `all`, target is `x86_64-unknown-linux-musl`; this run has no
coverage instrumentation. Other distribution userspaces were not tested here.
