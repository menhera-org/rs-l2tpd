# Required-kernel qualification with request I/O and socket-error guards

All thirteen profiles pass on frozen signed revision
`2d5ae458a990a6ae4208db295019cc38f0ce4b05`. Both tracked-source patches are
empty. Initial and final publication checks select the same versions;
`result.log` records `MATRIX_RESULT=0`.

| Required target | Guest release | Normal scenarios, seconds | H16 clock/pause, seconds |
|---|---|---:|---:|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 534.71 | 65.05 |
| Vanilla 6.8.12 | 6.8.12 | 485.42 | 64.35 |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 539.49 | 64.49 |
| Vanilla 7.0.14 | 7.0.14 | 455.71 | 64.17 |
| Mainline 7.3 | 7.3.0 | 442.03 | 64.32 |

Each normal guest passes **22 serial library, 24 Linux, five review,
65 ordinary binary, three selected privileged binary and 29 process cases**,
followed by all 27 normal scenarios. The ordinary binary result leaves five
ignored tests; the runner selects three filesystem-permission cases separately.
The eight daemon setup-fault markers pass on every target. The normal suite
includes H20 fragmentation, both 300-entry daemons, resolver wire/client-ID
checks, anonymous Reply validation and absent-family recovery.

The two additional serial library cases qualify controlled request I/O faults
and synthetic library-error mapping on all five targets. They do not establish
naturally malformed kernel replies or new buffer-force results. Ordinary
synthetic reply-decoder cases remain outside the matrix's ignored-library
selection and retain their GNU/musl qualification.

The separate `ipv6.disable=1` and `CONFIG_IPV6=n` cases pass in 3.11 and
3.22 seconds. Missing-Ethernet-driver degradation and recovery pass in
4.94 seconds. Ubuntu 7.0 uses the documented `kho=off` cold-boot setting.
All guests use stable musl binaries with released iphost 0.4.4.

The raw copy was compared with the completed frozen-worktree record before
this README was added. Later test-only lifetime, policy and custom-resolver
assertions retain their local execution scopes. No per-distribution
udev/networkd or Incus result is inferred from these bare-kernel guests,
and no live non-x86 architecture was tested.

P4 and complete clause proof remain open. This frozen revision also passes
[GitHub CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41349127664).
