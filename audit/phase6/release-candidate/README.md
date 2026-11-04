# Qualification and release audit snapshot

Production source: `81d49f9d2e54e89c47aefa7ae9edc4943e6374f8`.
Release tooling: `97fbbf8e4b2d650e9517a41d0cf05363189c531f`.
Their `src/`, `tests/` and root Cargo files are identical; the empty
qualified-source-equivalence.patch records the comparison. Later changes
in the current index refresh documentation only.

All functional qualification gates pass. Binary distribution is held for
the service-policy and license-notice findings in release-readiness-audit.md.
The project dependency audits pass; the published cross tool lock remains
non-clean, with its Linux/source applicability recorded separately.

| Evidence | Result |
|---|---|
| common-gates.log and vendor-common-gates.log | Mandatory ordinary checks pass |
| ../matrix-20261104T082517Z-1628766 | All 13 required profiles; unchanged source and published selections |
| optional/profiles.log | Six normal/clock passes on Debian 13, Rocky 9 and Rocky 10 |
| container-results.log | Three scenario/Incus pairs; source unchanged |
| systemd/run.log | Unmodified root-systemd unit passes |
| coverage/merged-source-coverage.log | 8,607/8,607 source lines; 1,834/1,834 condition outcomes |
| coverage/llvm-export.json.xz | Full combined LLVM export; no new production exclusions |
| coverage/source-and-mapping-inventory.json | Exact source blob IDs and frozen production mappings |
| coverage/raw-coverage.log | Raw per-instantiation summary, separate from merged source totals |
| source-work/curves.log | All 240 cases across eight workloads, three sizes and ten repetitions |
| source-work/exports.tar.xz | All 480 normalized full before/after LLVM JSON exports |
| reproducibility/comparisons.log | Both architectures and feature variants identical and stripped; registry-cache paths absent |
| cross-environment-packages.log | Local and CI packages are byte-identical for amd64 and arm64 |
| package-consumer.log | Real Debian dpkg install/upgrade/remove/purge checks pass |
| msrv-commands.log and msrv-library-features.log | Rust 1.89 GNU/musl and library feature combinations pass |
| source-package-commands.log | All-feature musl source-package verification passes |
| dependency-audit/results.log | Three project locks pass; cross lock reports one vulnerability and six warnings |
| package-policy-repro.log | Administrator service policy is bypassed: an open audit finding |
| package-docs-and-notices.log | Missing package link targets and Tokio notice: open audit findings |
| ci-97-summary.log | CI, CodeQL, Packages and Documentation workflows pass |

Kernel selections are Ubuntu `6.8.0-147.147` and `7.0.0-42.42`,
vanilla `6.8.12` and `7.0.14`, and mainline `7.4-rc1`.
Optional releases are Debian `6.12.115+deb13.1-amd64` (package `6.12.115-2`),
Rocky 9 `5.14.0-687.61.1.el9_8.x86_64` and Rocky 10
`6.12.0-211.72.1.el10_2.x86_64`. Each normal run includes all 28 scenarios,
37 process cases, 31 private live cases, 24 Linux conformance cases and
five review cases, plus the capture-startup control and second shrink cycle.

Gate entrypoints remain in the repository root, `tests/`, `tools/` and
`musl-deb/`. kernel-commands.log, coverage-commands.log and
container-commands.log retain the actual orchestration. The maintained CI
workflow supplies the equivalent merged-coverage recipe. Reproducibility
uses `musl-deb/test-reproducible.sh` from the release-tooling revision.

Machine path prefixes are normalized as `CHECKOUT`, `CARGO_HOME`,
`RUSTUP_HOME` and `REGISTRY`. Temporary build locations use `REPRO_ROOT`,
`RELEASE_TEMP` and `SOURCE_PACKAGE_ROOT`. ANSI escapes, download progress
and Cargo build timings are removed. No fetched HTML is retained.

For a coverage replay, check out the qualified production source, decompress
the full export and replace `CHECKOUT` in it and the inventory with the
JSON-escaped absolute checkout path. Run the maintained phase6-coverage
checker with that root, inventory and export. The replay result is retained
alongside the snapshot. The source-work archive contains JSON under its
original case/before.json and case/after.json paths.

The older matrix directories ending `1554190` and `1576461` are deliberately
stopped preliminary runs. They are neither passes nor regression findings.
packaging-initial-81d contains initial packaging checks before reproducible
release tooling; package-revision identifies the current artifact checks.

The Debian/Rocky runs qualify kernels, not their service managers or SELinux
policies. Package maintainer commands use a recorded systemctl stub in the
consumer test; the separate root-unit qualification uses Ubuntu 24.04
userspace. Arm64 ELF construction/linkage is checked; arm64 execution was
not performed. Upstream protocols retain their explicit delegated scope.
