# Verification

Binary distribution is held for the [release readiness findings](RELEASE_READINESS.md).

The production source qualified at `81d49f9` is unchanged by release-build
commit `97fbbf8`. Signed [qualification records](https://github.com/menhera-org/rs-l2tpd/blob/1f261be0dbff7584a14cc39a3bfe91b38919fd4e/audit/phase6/release-candidate/README.md)
retain commands, source guards, guest output, package checks and the full
compressed LLVM export and mapping inventory. Raw records are preserved in Git history.

| Gate | Result |
|---|---|
| Common checks | POSIX ShellCheck, formatting, warning-denied Clippy, GNU/musl tests, library/daemon builds and warning-denied rustdoc pass |
| Specification/source maps | 333 rule IDs; 43 active kernel facts, 37 source-cited; no uncited kernel-facing function |
| Required kernels | All 13 normal, clock/pause and special-boot profiles pass; target versions remain unchanged during the run |
| Optional kernels | Debian 13, Rocky Linux 9 and Rocky Linux 10 pass normal and clock/pause profiles: six passes |
| System containers | Three consecutive scenario/Incus pairs pass, with probe cleanup |
| Supplied systemd unit | Unmodified root-systemd unit passes with Ubuntu 24.04 userspace and Ubuntu 6.8 |
| Merged production coverage | 8,607/8,607 mapped source lines and 1,834/1,834 condition outcomes; no new production exclusions |
| Dispatch work | All 240 cases pass across eight workloads, three sizes and ten repetitions |
| Allocation/resource checks | GNU/musl allocation tests and live thread/fork refusal profiles pass |
| Release reproducibility | Both musl architectures and both feature variants produce identical stripped binaries/tarballs across independent clean builds; both Debian packages are identical |
| Debian package lifecycle | Real dpkg install, upgrade, remove and purge pass; maintainer-script commands and failures checked with a systemctl stub |
| Source package / minimum Rust | All-feature musl source-package verification and Rust 1.89 GNU/musl/library-feature checks pass |
| Documentation | mdBook build, local links and rendered anchors pass; GitHub Pages deploys through Actions |
| Qlty/CodeQL | Qlty checks have no actionable findings; maintainability badge A; CodeQL passes |
| Dependency audit | Daemon, coverage and package-builder lockfiles pass; cross's published lockfile reports one vulnerability and six warnings, with platform/source analysis retained |

Exact kernel versions and operating limits are in [kernel support](../docs/kernel-support.md).
The [developer guide](../docs/developer.md) gives the current commands and
evidence classification. Gate entrypoints live in `tests/`,
`tools/`, `musl-deb/` and the repository root. Fetched kernel.org HTML is
never committed.

The Debian/Rocky kernel-only guests do not qualify those distributions'
service managers, SELinux policies or full userspace. The Debian package
consumer check does not replace a real Debian systemd test. Arm64 packages
are built and their ELF architecture/static linkage verified; arm64 runtime
execution is outside this record. Raw LLVM per-instantiation totals remain
separate from the merged source result.
