# Required-kernel matrix with mainline 7.4-rc1

All thirteen profiles pass on frozen signed Rust/test source
`455eef71cd75dedcb0696824fef5b5d0d45575e4`. Initial and final publication
selections agree; both tracked-source patches are empty. The only main-tree
commit during the run changes documentation, retained evidence and the
common CI parser hook. It changes no consumed Rust or kernel-runner source.
`result.log` records `MATRIX_RESULT=0`; `matrix-checks.log` checks all thirteen
profile markers, five normal suite counts and source/publication consistency.

| Required target | Guest release | Normal scenarios, seconds | H16 clock/pause, seconds |
|---|---|---:|---:|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 591.13 | 64.73 |
| Vanilla 6.8.12 | 6.8.12 | 518.87 | 64.51 |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 509.01 | 64.58 |
| Vanilla 7.0.14 | 7.0.14 | 470.51 | 64.68 |
| Mainline 7.4-rc1 | 7.4.0-rc1 | 447.91 | 64.48 |

Each normal guest passes 22 serial library, 24 Linux, five review,
65 ordinary binary, three selected filesystem-permission and 29 process
cases, followed by all 27 normal scenarios. Five ordinary binary declarations
remain ignored in that suite; three execute separately. All eight daemon
setup-fault markers pass. H20 fragmentation, both 300-entry daemons,
resolver wire/client-ID checks, anonymous Reply validation, E27 recovery,
selected inventories and absent-family recovery are included.

The extra mainline `ipv6.disable=1` and `CONFIG_IPV6=n` cases pass in 3.27
and 3.12 seconds. Missing-Ethernet-driver degradation/recovery on Ubuntu
7.0 passes in 4.70 seconds. Its cold boot uses the documented `kho=off`
setting. All guests use stable musl and released iphost 0.4.4.

The RC empty IPv6 VRF refuses with EADDRNOTAVAIL (99). Its foreign-namespace
delete probe observes no matching event while local objects survive; the
review case checks its five-second observation against the release boundary.
The [source/build record](../mainline-rc-qualification-20261102/README.md)
retains the exact RC archive, source comparison and both build identities.
The 7.3 matrix remains historical and is superseded for the mainline target.

Cargo build durations and package-download progress are omitted. Test
execution durations remain. Bare-kernel guests establish no new
udev/networkd, Incus or distribution userspace result. Later test-only
additions retain their separate qualification. P4 and complete
clause/history/resource/event-cost proof remain open.
