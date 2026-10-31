# P3 matrix driver, current required targets and discovered failures

The documented entry point now exists:

```sh
tests/docker/run.sh matrix required
tests/docker/run.sh matrix v6.8..v7.3
```

The driver resolves Ubuntu release/updates/security candidates and
kernel.org source indexes, records the manifests at start/end, and
rejects a moved required target. It requires conformance/scenario result
markers and the expected guest release, records executable hashes, and
rejects tracked test/source changes during the run. The archived 0.1.5
peer is prepared by one shared helper, so a matrix run no longer needs a
prior host scenario run. No new dependency is introduced.

The required set resolved on 2026-10-31 is Ubuntu 6.8.0-147.147,
vanilla 6.8.12, Ubuntu 7.0.0-42.42, vanilla 7.0.14 and mainline 7.3.
The maintainer clarified that Ubuntu 148 was not yet ready; proposed
packages are not substituted. Metadata before/after the first matrix
run is in matrix-20261031T062607Z-3496031/initial and final. Required
versions did not move during that run; its result was failure.

| Run | Result and precise scope |
|---|---|
| First full required driver | MATRIX_RESULT=1; records under matrix-20261031T062607Z-3496031 |
| Ubuntu 6.8.0-147-generic | 10 library-live, 16 kernel, five review, 38 ordinary binary plus three explicit privileged binary, 26 process and 18 scenario cases passed; all result markers zero |
| Vanilla 6.8.12 | 10 library-live passed; kernel conformance failed one shared case (15 of 16 test functions passed), errno 101 instead of 99 in an empty IPv6 VRF; later suites not run |
| Ubuntu 7.0.0-42.42 first fetch | failed at missing kmod in updates/security-only metadata; no guest run in the first driver |
| Mainline 7.3.0 first guest | conformance/process passed; 16 scenarios passed, two nlmon fixtures refused the built-in driver because /sys/module/nlmon was absent |
| Mainline 7.3.0 IPv6 disabled | one scoped H4/T4 case passed, all scoped markers zero |
| Mainline 7.3.0 CONFIG_IPV6=n | one scoped H4/T4 case passed, all scoped markers zero |

Two harness corrections were tested without changing the K26/K34
assertion: include the Ubuntu release pocket for an unchanged kmod
candidate, and explicitly identify the builder's built-in nlmon in the
guest fixture. The host fixture still requires an already loaded module;
it never tries to load a host module. Actual nlmon creation and capture
positive controls continue to prove availability and request observation.

The fixed fetch succeeded, recording each package digest in
kernel-contract-20261031/resolute-fixed-fetch.log. Subsequent full guest
runs are separate evidence, not replacements for the first failed run:

- qemu-mainline-driver-fix-20261031: conformance/process and all 18
  scenarios pass, including H8 and H20; release 7.3.0.
- qemu-vanilla7014-driver-fix-20261031: conformance/process and all 18
  scenarios pass, including H8 and H20; release 7.0.14.
- qemu-resolute-driver-fix-20261031: conformance/process pass; 17
  scenarios pass and H8's immediate reload times out. This exposed the
  daemon's readiness/signal ordering race; its correction and separate
  verification belong to ready-signal-race-20261031.

kernel-contract-20261031 contains the K26/K34 source comparison and the
reviewed patch. The maintainer approved the documented kernel distinction
on 2026-10-31; the patch is now applied. Both refusals already have the
same transient policy, so no daemon behavior changes. The fresh required
run is matrix-20261031T071523Z-3533819; per-target results and remaining
limits are recorded in [required-kernel behavior](../../docs/kernel-behavior.md).
The Ubuntu 26.04 boot-memory cause and controlled KHO comparison are in
[boot-memory-20261031](boot-memory-20261031/README.md).

Driver checks: POSIX shell syntax, ShellCheck, publication-parser
self-test, rejected patch-level range, rejected zero-test scenario
selection, and the one-case legacy interoperability run all pass their
expected result. See kernel-contract-20261031 and
scenarios-20261031T062541Z-3495657. The earlier mistyped `legacy` filter
ran zero tests and is explicitly not evidence; run.sh now rejects it.

Limits: only final mainline releases and the v6/v7 source indexes are
supported by the current builder/resolver; a future release-candidate or
new-major target fails closed and needs its source-fetch path added.
The range path is parser-checked but its broader optional matrix was not
run. No complete Phase 6 matrix or scenario gate is claimed: P2 remains
partial. The first required driver failed; the fresh post-decision driver
returns MATRIX_RESULT=0 for all five currently implemented profiles and
both scoped H4 boots. Its [record](matrix-20261031T071523Z-3533819/README.md)
retains unchanged version/source manifests and identical executable
identities across the five normal guests. Complete scenario/delegated
proof and a consistent phase-exit rerun are still required.
