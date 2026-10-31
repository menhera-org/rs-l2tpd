# Root sandbox after the shared-resolver and queue-index changes

The full unmodified musl P6 case passes on Ubuntu `6.8.0-147-generic` in
26.80 seconds: `ROOT_SYSTEMD_RESULT=0`. A real systemd PID 1 runs in the
guest's initial user namespace. The supplied unit has no drop-ins.

[run.log](run.log) retains the sandbox, capability, module-autoload,
network-online, tunable, descriptor-store, re-exec and cleanup assertions.
[command.log](command.log) records QEMU and kernel/baseline identities;
[artifacts.log](artifacts.log) records executable identities. The parent
record's `revision`, `source.patch` and test-only `workers_cost.rs` identify
the tested source. Source did not change during the run.

Run `sh tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD`
with matching stock Ubuntu image/modules/config and prepared systemd
userspace. Features are `all`, target is `x86_64-unknown-linux-musl`,
without coverage instrumentation. Other distribution userspaces were
not tested here.
