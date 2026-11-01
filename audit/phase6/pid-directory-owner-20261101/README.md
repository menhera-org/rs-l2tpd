# PID-directory ownership refusal

The existing privileged permissions test now makes its empty directory
readable and searchable, transfers ownership to another user, and calls
publication as root. Filesystem access therefore reaches the daemon's
ownership check. Publication must return the precise permission diagnostic
and create no PID file or temporary inode. The fixture restores ownership.

Three GNU and three musl runs pass in disposable networkless containers.
Reversing the ownership comparison makes the new assertion fail. Common
checks, Rust 1.89 and ARM64/RISC-V64/PowerPC64LE musl compile checks pass.
No production code changes.

The guest initializer shares the existing ordinary CLI and three privileged
filesystem selections between normal and binary profiles. All five kernel
versions of the earlier full-matrix snapshot pass 65 ordinary CLI tests and
the three separately selected filesystem cases, including the new ownership
check. The ordinary summary retains five ignored tests; three run separately,
leaving the manager and tunable cases outside this profile. Those five kernels
are Ubuntu 6.8.0-147-generic, vanilla 6.8.12, Ubuntu 7.0.0-42-generic,
vanilla 7.0.14 and 7.3.0.

These results are scoped to that snapshot. The later publication check found
mainline 7.4-rc1; it is untested and reopens P3. No result here qualifies that
new target or a new distribution's manager/container behavior.

Coverage reaches **8,514/8,687 lines (98.01%) and 1,704/1,852 branches
(92.01%)**, leaving 173 lines and 148 branches. All 4,327 production mappings
remain identical; source patches agree. There is no production exclusion,
profile mismatch or saturated region.

`commands.sh` records positive commands. Control patch/log retain the deliberate
ownership-guard defect. Complete clause proof and P4 remain open.
