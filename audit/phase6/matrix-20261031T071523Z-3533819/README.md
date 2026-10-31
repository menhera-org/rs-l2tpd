# Fresh required-kernel matrix after the approved distinction

Command: `tests/docker/run.sh matrix required`. All features;
`x86_64-unknown-linux-musl` daemon/tests; TCG QEMU, 2048 MiB, two vCPUs,
no host networking. `revision` plus `source.patch` identify the tested
state; `final-source.patch` is byte-identical. The source patch contains
the approved K26/K34 conformance correction and the cold-boot KHO setting.
The production daemon already includes the readiness/signal-order fix.

**MATRIX_RESULT=0.** Initial/final publication manifests agree. Required
versions did not move during this run. Each guest's recorded release
matches the resolved target; every required result marker is zero.
All five normal guests used identical daemon/test executable identities
(artifacts.log compared byte-for-byte), with the same 0.1.5 baseline.

| Target | Actual guest release | Empty-VRF IPv6 errno | Conformance/process | Scenarios | H20 |
|---|---|---|---|---|---|
| Ubuntu 24.04, 6.8.0-147.147 | 6.8.0-147-generic | 99 / EADDRNOTAVAIL | Pass | 18 passed | Eight combinations passed |
| Vanilla 6.8.12 | 6.8.12 | 101 / ENETUNREACH | Pass | 18 passed | Eight combinations passed |
| Ubuntu 26.04, 7.0.0-42.42 | 7.0.0-42-generic | 99 / EADDRNOTAVAIL | Pass | 18 passed | Eight combinations passed |
| Vanilla 7.0.14 | 7.0.14 | 99 / EADDRNOTAVAIL | Pass | 18 passed | Eight combinations passed |
| Mainline v7.3 | 7.3.0 | 99 / EADDRNOTAVAIL | Pass | 18 passed | Eight combinations passed |

Each normal guest passes 10 library live cases, 16 kernel cases, five
review probes, 38 ordinary binary cases plus three explicit privileged
binary cases, 26 process cases and 18 scenarios. The scenario duration
is respectively 206.05, 162.96, 195.02, 162.22 and 170.23 seconds; these
are test durations, not resource-contract or build-performance claims.
Every buffer comparison reports FORCE_RESULT=allowed. All five
32-cycle session-ID reuse probes observe zero EEXIST retries; source,
not that observation, establishes synchronous versus queued deletion.
The namespace-notification review probes pass their precise expected
pre-7.3 cross-namespace / 7.3 namespace-local behavior.

Extra mainline boots `ipv6-disable` and `no-ipv6` each pass exactly the
scoped H4/T4 test and record the explicit scope plus zero result markers.
They do not run or claim the ordinary IPv6-dependent profile.

The Ubuntu 26.04 guest command adds `kho=off` because its supplied stock
config enables KHO by default; the other four commands do not add it.
This preserves the stock image/modules/config, ASLR and memory size and
avoids the controlled initramfs OOM described in
[the boot record](../boot-memory-20261031/README.md). It tests cold boot,
not kernel handover. No boot retry was needed in this matrix.

The required target set is published Ubuntu release/updates/security,
latest vanilla equivalents and mainline, re-resolved at start/end.
Proposed/unpublished Ubuntu versions do not replace these artifacts.
Source tarball/image/config hashes, package SHA256 verification, baseline
identity, exact commands, compile features, suite results and full guest
logs are retained in this directory. No guest is still running.

This is a passing **implemented profile**, not completion of Phase 6.
H15, H16, full H17 and the remaining promise/delegated proof are still
missing; Incus/systemd-manager cases run separately and are not executed
by the normal guest PID 1. Coverage, rule-map completeness, strict CI
and the final latest-target phase-exit rerun remain open. The optional
broader vanilla range did not run.

[Per-kernel behavior and limitations](../../../docs/kernel-behavior.md)
connect these results to every K fact and the exact distribution sources.
