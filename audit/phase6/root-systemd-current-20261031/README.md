# Current root-systemd sandbox verification

The unmodified musl daemon and supplied system unit pass the full P6 case
on Ubuntu kernel `6.8.0-147-generic`, with a real systemd PID 1 in the
initial user namespace. `ROOT_SYSTEMD_RESULT=0`; the one comprehensive
scenario passes in 26.30 seconds. [run.log](run.log) retains the guest
release, assertions and result; [command.log](command.log) identifies the
QEMU command and kernel/baseline identities.

The test checks actual private mounts, read-only root/kernel tunables,
the one writable bindv6only exception, the writable runtime directory,
private temporary files, no-new-privileges and exact effective/permitted/
bounding/ambient capabilities. It compares the installed unit with the
supplied template and requires no drop-ins. Kernel module autoload is
exercised in the guest; withholding the Ethernet driver prevents readiness
and network-online until autoload is restored. The shared manager exercise
checks tunable handling, descriptor-store/re-exec and cleanup.

Reproduction uses `tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD`
with the matching Ubuntu stock image/modules/config and prepared systemd
userspace image. Features are `all`, target `x86_64-unknown-linux-musl`.
`revision` is the controller revision `e572eeb`, and `source.patch` is empty;
Rust sources and tests still match qualified source `0f5292e`. No coverage
instrumentation or sandbox override was used. This is one kernel/userspace
profile; it does not establish P6 behavior on every required distribution.
