# Optional kernel qualification after the nlmon capture fix

All six maintained profiles pass after signed fixture commit
69a0b42d46cf71f938a4da51503265730aab4a17 was synced. Initial/final source
patches are empty. Production source remains c599b1f; production-source.patch
is empty. Only scenario capture startup and its regression changed.

| Target | Release | Normal | Clock/pause |
|---|---|---|---|
| Debian 13 | 6.12.115+deb13.1-amd64 (6.12.115-2) | Pass: 28 scenarios, 37 process cases | Pass |
| Rocky 9 | 5.14.0-687.61.1.el9_8.x86_64 | Pass: 28 scenarios, 37 process cases | Pass |
| Rocky 10 | 6.12.0-211.72.1.el10_2.x86_64 | Pass: 28 scenarios, 37 process cases | Pass |

All normal guests also pass 31 private live cases, 24 Linux cases, five
review cases, ordinary binary units and selected permission/resource-refusal
cases. Each normal guest executes all three 300-session expansion/shrink
cycles, both frame directions, identical reload and unrelated-event request
checks. Clock guests require the controller-confirmed QMP pause/resume marker.
The Incus system-container scenario is explicitly excluded by the maintained
QEMU profile; its separate required qualification is unchanged.

The capture socket previously opened with ETH_P_ALL, registering immediately
on all interfaces. Ethernet queued before nlmon bind survives the bind and
is rejected by the strict netlink parser. The fix opens with protocol zero
and activates only on bind. Capture windows, thresholds, positive controls,
parsing and packet-drop checks remain intact. The daemon uses AF_NETLINK;
it has no AF_PACKET sockets and needs no production change.

The added live regression injects Ethernet between socket opening and bind.
Its old-opening control receives foreign Ethernet; the fixed opening has an
empty queue and then captures a deliberate route request. It passes ten
consecutive GNU runs and ten consecutive musl runs on Ubuntu 6.8.0-147, as
well as all three optional normal guests. The single-change mutant restores
only ETH_P_ALL in capture_socket and fails deterministically with exit 101
and "foreign Ethernet was queued before binding to nlmon".

The standalone bind-race diagnostic passes on stock Debian 13. It records
ARP from an underlay interface after nlmon bind with the old opening, an
empty protocol-zero queue and valid post-bind netlink. The original failed
packet was not retained; its exact contents cannot be recovered. The
controlled probe establishes the defect and recreates the same parser
rejection without claiming that original packet was specifically ARP.

A full old-capture diagnostic with richer parser errors also passes all 27
original scenarios. It did not reproduce the intermittent error and is not
a fixed-suite qualification. diagnostics/fixtures.txt retains disposable
fixture sources as historical evidence, not current gating scripts.
Diagnostic artifacts.log files describe the base build before injection;
diagnostics/executables.log identifies the actual diagnostic replacements.
The standalone bind-race guest uses a scoped PID-1 script and runs only its
named probe; the full-old-capture guest uses the maintained full normal init.

Reproduce maintained qualification with tests/kernel/README.md: fetch the
three pinned package selections, then run tests/kernel/run-optional.sh.
This rerun reuses the previously fetched, checksum-verified exact packages;
their SHA256 metadata and extractor identities are retained here. Each guest
records its image/configuration and executable identities. source-review.log
links packet(7) and upstream 6.12.115 packet_create, packet_do_bind and
packet_recvmsg. Actual stock-kernel observations corroborate that behavior;
a complete optional-kernel source audit is not claimed.

GNU/musl logs, the mutant diff/result and production-scope.log retain the
additional checks. regression-missing-container-marker.log is a refused
manual invocation missing the mandatory container marker; it is neither a
kernel failure nor a counted pass. It was corrected without changing tests.
CI and CodeQL pass on 69a0b42. CI's full Ubuntu 6.8.0-147 guest passes
28 scenarios, and production coverage remains 8,582/8,582 merged lines and
1,844/1,844 outcomes; ci-summary.log retains selected excerpts and full-log
links. Common CI gates and local Markdown link checks pass. CHECKOUT replaces the
local checkout path; local source-file timestamps/build durations are omitted.
Kernel-only guests do not qualify distribution userspace, SELinux, packaging
or manager integration. No assertion, production exclusion or kernel behavior
was weakened, and no fetched kernel.org HTML is committed. The earlier failed
optional run remains in signed 8766a43 history; it is not reclassified.
