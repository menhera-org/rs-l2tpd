# Release readiness

The five findings in the [prior audit](https://github.com/menhera-org/rs-l2tpd/blob/1f261be0dbff7584a14cc39a3bfe91b38919fd4e/audit/phase6/release-candidate/release-readiness-audit.md)
are closed. No binary-distribution blocker remains from that review.
Version 0.2.0 is still unpublished.

Release inputs are qualified at `ff37e219fccb68d37cd4fbae863a2d533ecaf8bb`.
The production source, root Cargo files and Rust conformance assertions
remain identical to the source qualified at `81d49f9`.

| Area | Verified behavior |
|---|---|
| Service policy | Real Debian helpers honor policy-rc.d denial for starts/stops and preserve administrator masks and disabled state. Upgrades only reload manager definitions; no daemon restart or stop is allowed by the consumer assertions. Helper-owned removal masks are undone on reinstall and cleaned on purge. |
| License notices | Both artifact formats contain project licenses, locked dependency notices/source URLs, the pinned Rust compiler/runtime inventory and musl's copyright text. An empty-license negative control is rejected. |
| Installed documentation | The packaged README links directly to published operator guides and names notice files present beside it. The installed-tree consumer passes. |
| Build tool | cross is pinned to upstream revision a9301e91f72bba3850460512685f6b16062015ff with its unchanged lockfile. All three project locks and that tool lock pass cargo audit with no warnings or ignored advisories. |
| Systemd image | The builder and Dockerfile live under tests/kernel/. Fresh preparation, a fully offline rebuild, corrupt-package rejection and the unmodified root-unit guest gate pass. |
| Reproducibility | Both musl architectures and feature variants produce identical stripped binaries/tarballs across clean paths, mtimes and umasks. Both Debian packages match. Notice contents are checked, including under forced Cargo colors. |

The [Packages workflow](https://github.com/menhera-org/rs-l2tpd/actions/runs/41848373078)
qualifies the release inputs. The [verification record](VERIFICATION.md)
links the complete kernel/coverage evidence and current CI checks.

Arm64 runtime execution and full Debian/Rocky service-manager/SELinux
integration remain outside qualification. The Debian consumer uses real
package helpers and a systemctl stub; the root-unit gate uses real Ubuntu
systemd in QEMU.
