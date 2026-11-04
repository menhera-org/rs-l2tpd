# Release readiness

All five findings from the [prior audit](https://github.com/menhera-org/rs-l2tpd/blob/1f261be0dbff7584a14cc39a3bfe91b38919fd4e/audit/phase6/release-candidate/release-readiness-audit.md)
have implementation fixes. Binary distribution awaits independent clean-build
comparisons for the refreshed cross revision and notice bundle.

| Finding | Current implementation and verification |
|---|---|
| Service policy | Debian's real helpers honor policy-rc.d denial for starts/stops, preserve administrator masks and disabled state, and clean up helper-owned removal masks. The networkless Debian 13 dpkg consumer passes. |
| License notices | Both formats carry project licenses, locked dependency notices/source URLs, Rust compiler/runtime notices and musl's copyright text. Unit and installed-package checks pass; clean-build comparisons remain required. |
| Installed documentation | The packaged README links directly to published operator guides and names notice files present beside it. The installed-tree consumer passes. |
| Build tool audit | cross is pinned to upstream revision a9301e91f72bba3850460512685f6b16062015ff with its unchanged lockfile. That lock passes cargo audit without ignored advisories; artifact comparisons remain required. |
| Root-unit image | The maintained builder and Dockerfile live under tests/kernel/. A fresh Ubuntu 24.04 build, fully offline rebuild, corrupt-package rejection and root-systemd guest gate pass. |

The production daemon/library source and root Cargo files remain unchanged.
The [verification record](VERIFICATION.md) separates the existing complete
kernel/coverage qualification from the refreshed packaging qualification.

Arm64 runtime execution and full Debian/Rocky service-manager/SELinux
integration remain outside qualification. The Debian consumer uses real
package helpers and a systemctl stub; the root-unit gate uses real Ubuntu
systemd in QEMU.
