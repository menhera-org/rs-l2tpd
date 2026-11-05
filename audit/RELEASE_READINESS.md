# Release readiness

The five findings in the [prior audit](https://github.com/menhera-org/rs-l2tpd/blob/1f261be0dbff7584a14cc39a3bfe91b38919fd4e/audit/phase6/release-candidate/release-readiness-audit.md)
are closed. No binary-distribution blocker remains from that review.
Version 0.2.0 was released on 2026-11-05.

Release inputs are qualified at `f12798ec54c17b45be8777d802ce8bf6dc7e9aaf`.
The production source, root Cargo files and live-kernel assertions
remain identical to the source qualified at `81d49f9`. A fake-kernel
logging regression now runs deterministically under its capture logger.
The full local and CI merged collections reach 8,607/8,607 mapped lines
and 1,834/1,834 condition outcomes without new exclusions.

| Area | Verified behavior |
|---|---|
| Service policy | Real Debian helpers honor policy-rc.d denial for starts/stops and preserve administrator masks and disabled state. Upgrades only reload manager definitions; no daemon restart or stop is allowed by the consumer assertions. Helper-owned removal masks are undone on reinstall and cleaned on purge. |
| RPM policy | Real Rocky Linux 9/10 RPM consumers verify presets, first-install startup, preserved upgrade state and masks, no restart on upgrade, stop/disable on erase, and presets on reinstall after erase. The approved unit path and .rpmnew/.rpmsave behavior are documented in the [operator guide](../docs/installation.md#rpm-packages). |
| License notices | Tarballs, DEBs and RPMs contain project licenses, locked dependency notices/source URLs, the pinned Rust compiler/runtime inventory and musl's copyright text. An empty-license negative control is rejected. |
| Installed documentation | The packaged README links directly to published operator guides and names notice files present beside it. The installed-tree consumer passes. |
| Build tool | cross is pinned to upstream revision a9301e91f72bba3850460512685f6b16062015ff with its unchanged lockfile. All three project locks and that tool lock pass cargo audit with no warnings or ignored advisories. |
| Systemd image | The builder and Dockerfile live under tests/kernel/. Fresh preparation, a fully offline rebuild, corrupt-package rejection and the unmodified root-unit guest gate pass. |
| Reproducibility | Both musl architectures and feature variants produce identical stripped binaries/tarballs across clean paths, mtimes and umasks. DEBs and RPMs for both architectures match. Notice contents are checked, including under forced Cargo colors. |

The [Packages workflow](https://github.com/menhera-org/rs-l2tpd/actions/runs/41948203053)
qualifies the release inputs. The [verification record](VERIFICATION.md)
links the complete kernel/coverage evidence and current CI checks.

Arm64 runtime execution and full Debian/Rocky service-manager/SELinux
integration remain outside qualification. The package consumers use real
dpkg/RPM transactions and a systemctl stub; the Debian consumer also uses
real policy helpers. The root-unit gate uses real Ubuntu systemd in QEMU.
