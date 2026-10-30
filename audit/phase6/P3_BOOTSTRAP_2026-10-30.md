# Phase 6 QEMU bootstrap — 2026-10-30

This is partial P3 evidence, not a passing required matrix.

The Ubuntu fetcher resolves published security/updates metadata, records
the selected package stanzas, checks package SHA256 digests, and unpacks
in networkless Ubuntu containers. It accepts both lib/modules and
usr/lib/modules layouts and supplies matching kmod tools for guest boot.
Today's fetched candidates were 6.8.0-147.147 and 7.0.0-42.42. The
maintainer clarified that 6.8.0-148.148 is not ready; proposed packages
are not substituted for published stock targets. Re-resolve before a
required-matrix pass, especially with forthcoming security updates.

The vanilla builder uses x86_64_defconfig plus the required networking
features, including nlmon, bridge and 802.1Q, in a networkless Debian
toolchain container. Build identity is fixed rather than taken from the
machine. Logs identify source archive, configuration and image hashes.
6.8.12, 7.0.14 and 7.3 built successfully, plus 7.3 with CONFIG_IPV6=n.
Initial outer command timeouts are not successful build records; the
final resumptions completed and recorded the image hashes.

- [6.8.12 build](entry/build-linux-6.8.12-final.log).
- [7.0.14 build](entry/build-linux-7.0.14-final.log).
- [7.3 build](entry/build-linux-7.3-final.log).
- [7.3 without IPv6](entry/build-linux-7.3-no-ipv6.log).
- [Ubuntu 24.04 packages and module tools](entry/fetch-ubuntu-noble-with-tools.log).
- [Ubuntu 26.04 package verification](entry/fetch-ubuntu-resolute.log).

H4/T4 passes in both separately booted conditions: ipv6.disable=1 and
CONFIG_IPV6=n. Each run asserts the real AF_INET6 refusal, native IPv4
kernel endpoints and bidirectional frames, disconnected IPv6 peers
whose transmissions drop, once-only reports, preserved interface
indices through reload, and shutdown cleanup.

- [IPv6 disabled at boot](qemu-ipv6-disabled-20261030/run.log).
- [IPv6 compiled out](qemu-no-ipv6-20261030/run.log).

The socket-option read-back and all eight H20 MTU/family/VRF combinations
also pass on the earlier vanilla 7.3 guest:
[scoped fragmentation run](entry/qemu73-fragmentation.log). That is not
the full matrix.

Both stock Ubuntu guests completed the private live kernel suite,
kernel conformance/method cases, review probes, binary tests and process
suite, with CONFORMANCE_RESULT=0. Their full scenario stages exceeded
the original 360-second outer TCG timeout. Neither run has a successful
SCENARIO_RESULT, so neither passes P3. The runner now streams suite
output and permits 900 seconds for the guest; assertions are unchanged.
Those longer full runs remain to be executed.

- [Ubuntu 24.04 partial run](qemu-ubuntu2404-20261030/run.log).
- [Ubuntu 26.04 partial run](qemu-ubuntu2604-20261030/run.log).
- The earlier Ubuntu 26.04 initramfs and module-index failures are
  retained separately. Rootfstype=ramfs, a real /dev mountpoint and guest
  depmod allow boot/module loading; these are fixture corrections.

The guest runner requires nonempty successful suites and explicit
conformance, scenario and guest result markers. QEMU exit status alone
cannot pass. Boot-only runs clearly label their narrower scope.

Still open: matrix.sh and run.sh matrix dispatch, fresh target comparison
at the end of a required run, every required full kernel/profile result,
the H16 clock case, the remaining P2 scenarios and merged coverage.
