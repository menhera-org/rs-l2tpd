# Phase 6 P6 root system-unit sandbox — 2026-10-30

P6 passed in a QEMU guest booting Ubuntu 6.8.0-147-generic with a real
root systemd from the Ubuntu 24.04 image. The daemon was installed by
--setup-systemd. No daemon-unit drop-in or sandbox override was used.

The test requires initial-user-namespace UID mapping and PID 1 systemd.
A production LinuxKernel family request first proves kernel module
autoload. Temporarily refusing module autoload withholds the session,
PID publication and unit readiness; network-online.target stays waiting.
Restoring autoload permits Ethernet-module loading, interface creation,
readiness and then network-online activation.

The shared manager contract verifies the namespace-local bindv6only
correction, PID file, exactly the three effective capabilities,
descriptor-store survival after SIGKILL while MainPID is zero, automatic
adoption with the original interface, requested re-exec, and ordered
shutdown/PID/kernel cleanup.

Root-only assertions inspect the actual process, not just unit settings:
its mount namespace differs from PID 1; root and proc/sys are mounted
read-only; run/rs-l2tpd and the single bindv6only exception are writable;
the service cannot see a file in the manager's tmp; NoNewPrivs is set;
effective, permitted, bounding and ambient capability masks contain
exactly NET_ADMIN, NET_RAW and NET_BIND_SERVICE. The installed unit
matches the template and has no drop-ins. The journal records
ROOT_SANDBOX=active and the guest powers off with ROOT_SYSTEMD_RESULT=0.

- [Successful guest run](qemu-root-systemd-20261030/run.log): 1 passed,
  zero failed, 32.05 s; root result 0.
- [Command, image and kernel configuration](qemu-root-systemd-20261030/).
- [Driver transcript](entry/qemu-root-systemd.log).
- [Ordinary tests, formatting and clippy](entry/boot-systemd-final-checks.log).
- [Strict source link: four passed](entry/qemu-final-srclink.log).
- [Strict rule map: still 70 missing citations](entry/qemu-final-rulemap.log).

The first root fixture also ran P5's staged networkd/MAC suffix and
failed its address/MAC wait after the P6 assertions had succeeded.
That failure remains in qemu-root-systemd-20261030-extra-manager-failure.
It was not counted as a P6 pass. P6 now runs its specified contract;
the separate H11/P5 policy suffix remains in the Incus test. The full
H11 manager-version/staging matrix is still open. The first fixture's
missing poweroff alias was corrected to systemctl poweroff.

The refactored Incus wrapper still independently asserts unprivileged
mapping, then runs both shared manager and MAC-policy parts. The final
recheck passed its production buffer case and system-container case
(8.06 s), with no skip and successful deletion:
[transcript](entry/incus-shared-manager-final.log),
[record](incus-20261030T095101Z-3313757/).

P6 is locally satisfied. This does not complete the full required kernel
matrix, P2 scenario coverage, strict rule map or merged coverage.
