# Required-kernel qualification of checked netlink replies

All thirteen profiles pass on frozen signed revision
`3f503cdd432deb5a5bdf38715d7a63a3074a2835`. Both tracked-source patches are
empty. Initial and final publication checks select the same versions;
`result.log` records `MATRIX_RESULT=0`.

| Required target | Guest release | Normal scenarios, seconds | H16 clock/pause, seconds |
|---|---|---:|---:|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 573.85 | 64.87 |
| Vanilla 6.8.12 | 6.8.12 | 474.48 | 64.55 |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 538.87 | 65.09 |
| Vanilla 7.0.14 | 7.0.14 | 460.38 | 64.29 |
| Mainline 7.3 | 7.3.0 | 475.70 | 64.36 |

Each normal guest passes 20 serial library, 24 Linux, five review,
65 ordinary binary, three selected privileged binary and 29 process cases,
followed by all 27 normal scenarios. The ordinary binary result leaves five
ignored tests; the runner selects three filesystem-permission cases separately.
User-manager and tunable-namespace cases have separate local qualification.
The normal suite includes H20 fragmentation, both 300-entry daemons, resolver
wire/client-ID checks, anonymous Reply validation and absent-family recovery.

The separate `ipv6.disable=1` and `CONFIG_IPV6=n` cases pass in 3.01 and
3.09 seconds. Missing-Ethernet-driver degradation and recovery pass in
4.66 seconds. Ubuntu 7.0 uses the documented `kho=off` cold-boot setting.
All guests use stable musl binaries with released iphost 0.4.4.

The corrected production reply decoder runs against each required kernel.
Its eight ordinary synthetic decoder cases were qualified separately on
GNU and musl; the guest's `--ignored` library selection does not run them.
The synthetic cases establish no live malformed reply from these kernels.
Later test-only netlink I/O assertions have separate qualification.

This run provides no distribution-specific udev/networkd or Incus result
beyond the separately recorded Ubuntu 24.04 / 6.8.0-147 userspace runs.
No live non-x86 architecture was tested. P4 and complete clause proof remain
open. The same revision also passed [GitHub CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41336009240).
