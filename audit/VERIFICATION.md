# Verification

The [release readiness findings](RELEASE_READINESS.md) are closed. Version
0.2.0 remains unpublished.

Release inputs are qualified at `f12798ec54c17b45be8777d802ce8bf6dc7e9aaf`.
The production source, root Cargo files and live-kernel assertions remain
identical to `81d49f9`, retaining the kernel qualification below. The fake
unmatched-adoption retry case now runs under its capture logger and asserts
one error across repeated refusals and a success report on recovery. The
full local and CI merged coverage collections pass without new exclusions.

[Signed qualification records](https://github.com/menhera-org/rs-l2tpd/blob/1f261be0dbff7584a14cc39a3bfe91b38919fd4e/audit/phase6/release-candidate/README.md)
preserve the full kernel/coverage commands, source guards, guest output,
compressed LLVM export and mapping inventory. Raw records remain in Git history.

| Gate | Result |
|---|---|
| Common checks | POSIX ShellCheck, formatting, warning-denied Clippy, GNU/musl tests, library/daemon builds and warning-denied rustdoc pass |
| Specification/source maps | 333 rule IDs; 43 active kernel facts, 37 source-cited; no uncited kernel-facing function |
| Required kernels | All 13 normal, clock/pause and special-boot profiles pass; target versions remained unchanged during qualification |
| Optional kernels | Debian 13, Rocky Linux 9 and Rocky Linux 10 pass normal and clock/pause profiles: six passes |
| System containers | Three consecutive scenario/Incus pairs pass, with probe cleanup |
| Supplied systemd unit | The unmodified root unit passes with a freshly built Ubuntu 24.04 image and Ubuntu 6.8; offline rebuild and corrupt-package rejection pass |
| Merged production coverage | 8,607/8,607 mapped source lines and 1,834/1,834 condition outcomes; no new production exclusions; current CI repeats the pass |
| Dispatch work | All 240 cases pass across eight workloads, three sizes and ten repetitions |
| Allocation/resource checks | GNU/musl allocation tests and live thread/fork refusal profiles pass |
| Release reproducibility | Both musl architectures and feature variants produce identical stripped binaries/tarballs across independent clean paths, mtimes and umasks; DEBs and RPMs for both architectures match |
| Artifact notices | Tarballs, DEBs and RPMs contain the same project/dependency/runtime notices; forced Cargo colors leave their bytes unchanged; an empty-license negative control is rejected |
| Debian lifecycle | Real dpkg install, upgrade, remove, reinstall and purge pass with real Debian policy helpers and a systemctl stub; policy denial, disabled/masked units, configuration preservation and command failures are checked |
| RPM lifecycle | Real RPM install, upgrade, erase and reinstall pass on Rocky Linux 9 and 10 with a systemctl stub; presets, enabled/disabled/masked units, changed defaults, .rpmnew/.rpmsave, retained fragments, --excludedocs and scriptlet failures are checked |
| Source package / minimum Rust | Clean all-feature musl source-package verification passes; Rust 1.89 GNU/musl/library-feature checks remain valid; the changed package builder also passes Rust 1.89 tests |
| Documentation | mdBook, local links and rendered anchors pass; GitHub Pages deploys through Actions |
| Qlty/CodeQL | Qlty has only the existing build.rs note; current CodeQL passes |
| Dependency audit | Daemon, coverage-tool, package-builder and pinned cross lockfiles pass against a fresh official registry index, with no warnings or ignored advisories |

The qualified revision passes [CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41948203100),
[Packages](https://github.com/menhera-org/rs-l2tpd/actions/runs/41948203053),
[CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41948202998) and
[Documentation](https://github.com/menhera-org/rs-l2tpd/actions/runs/41948203043).
The package workflow exercises forced Cargo colors, clean-build comparisons,
notice contents, real Debian helpers and real Rocky RPM transactions. Both
consumers require upgrades to leave the daemon untouched. RPM's approved
configuration and uninstall differences are documented in
[installation](../docs/installation.md#rpm-packages).

The [f31636c](https://github.com/menhera-org/rs-l2tpd/commit/f31636cc130f3fe9ba0f36885737ae72b87cb17a)
coverage miss depended on parallel logger startup. The logging test now
executes the retry case on its capture logger's owning thread.

Local and CI packages are byte-identical:

| Artifact | SHA256 |
|---|---|
| rs-l2tpd_0.2.0-1_amd64.deb | `2786b6b3a5f5820c7d80a42f1e3510f5efe70802da2e7d39ae0cd89187fa1af0` |
| rs-l2tpd_0.2.0-1_arm64.deb | `93df8c6e2b9b10e669dc7d4d2969b33e0bc9c0aabbacea9fec040afa4049b15c` |
| rs-l2tpd-0.2.0-1.x86_64.rpm | `34162ccb7c15d5d73b5ca73dfb81b43f454a17b0878d0f15ed829fe96b2737cd` |
| rs-l2tpd-0.2.0-1.aarch64.rpm | `6ddaacd7de28ccfc8069daa38b73e1487d51df7542be5dfdde764445c81bea5a` |

The dependency scan used RustSec database revision
`965bf9ad083b58e6340d65829d85217b18be9290`.
The cross input is upstream revision
`a9301e91f72bba3850460512685f6b16062015ff` with its unchanged lockfile.

Exact kernel versions and limits are in [kernel support](../docs/kernel-support.md).
The [developer guide](../docs/developer.md) gives maintained commands and
evidence classifications. Gate entrypoints live in tests/, tools/, musl-deb/
and the repository root. Fetched kernel.org HTML is never committed.

The Debian/Rocky kernel-only guests do not qualify those distributions'
service managers, SELinux policies or full userspace. The package
consumers use a systemctl stub and do not replace real Debian/Rocky systemd
tests. Arm64 packages are built and their ELF architecture/static linkage
verified; arm64 runtime
execution remains outside qualification. Raw LLVM per-instantiation totals
remain separate from the merged source result.
