# Verification

The [release readiness findings](RELEASE_READINESS.md) are closed. Version
0.2.0 remains unpublished.

Release inputs are qualified at `ff37e219fccb68d37cd4fbae863a2d533ecaf8bb`.
The production source, root Cargo files and Rust conformance assertions remain
identical to `81d49f9`. The maintained systemd-image bootstrap and package
checks have fresh qualification below.

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
| Release reproducibility | Both musl architectures and feature variants produce identical stripped binaries/tarballs across independent clean paths, mtimes and umasks; both Debian packages match |
| Artifact notices | Both formats contain the same project/dependency/runtime notices; forced Cargo colors leave their bytes unchanged; an empty-license negative control is rejected |
| Debian lifecycle | Real dpkg install, upgrade, remove, reinstall and purge pass with real Debian policy helpers and a systemctl stub; policy denial, disabled/masked units, configuration preservation and command failures are checked |
| Source package / minimum Rust | Clean all-feature musl source-package verification passes; Rust 1.89 GNU/musl/library-feature checks remain valid; the changed package builder also passes Rust 1.89 tests |
| Documentation | mdBook, local links and rendered anchors pass; GitHub Pages deploys through Actions |
| Qlty/CodeQL | Qlty has only the existing build.rs note; current CodeQL passes |
| Dependency audit | Daemon, coverage-tool, package-builder and pinned cross lockfiles pass against a fresh official registry index, with no warnings or ignored advisories |

The qualified revision passes [CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41848373489),
[Packages](https://github.com/menhera-org/rs-l2tpd/actions/runs/41848373078),
[CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41848373258) and
[Documentation](https://github.com/menhera-org/rs-l2tpd/actions/runs/41848373147).
The package workflow exercises forced Cargo colors, clean-build comparisons,
notice contents and the real Debian consumer. The consumer also requires
upgrade and failed-reload traces to contain only manager daemon-reload calls.

Local and CI Debian packages are byte-identical:

| Architecture | SHA256 of rs-l2tpd_0.2.0-1_ARCH.deb |
|---|---|
| amd64 | `1ef56ba72fb0f3883c4901e04af811e93fb9e86ddeda9da90faeb50cd0e5fb04` |
| arm64 | `e1c1957e882960c3abaded0a4b46f7b5ab3fb3ad9eb0619b0bf420e4890d9a94` |

The dependency scan used RustSec database revision
`965bf9ad083b58e6340d65829d85217b18be9290`.
The cross input is upstream revision
`a9301e91f72bba3850460512685f6b16062015ff` with its unchanged lockfile.

Exact kernel versions and limits are in [kernel support](../docs/kernel-support.md).
The [developer guide](../docs/developer.md) gives maintained commands and
evidence classifications. Gate entrypoints live in tests/, tools/, musl-deb/
and the repository root. Fetched kernel.org HTML is never committed.

The Debian/Rocky kernel-only guests do not qualify those distributions'
service managers, SELinux policies or full userspace. The Debian package
consumer does not replace a real Debian systemd test. Arm64 packages are
built and their ELF architecture/static linkage verified; arm64 runtime
execution remains outside qualification. Raw LLVM per-instantiation totals
remain separate from the merged source result.
