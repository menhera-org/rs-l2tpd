# Required-kernel matrix for streamed inventories

`tests/docker/run.sh matrix required` passes in a clean frozen checkout of
`012764fa4c7701c2be8081ec9210b9f84bfc2066`. Both `source.patch` and
`final-source.patch` are empty. Initial and final publication selections
match; `result.log` records MATRIX_RESULT=0.

| Target | Guest release | Normal scenarios | H16 clock/QMP |
|---|---|---|---|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 26 pass, 563.22 s | pass, 64.65 s |
| Vanilla 6.8.12 | 6.8.12 | 26 pass, 491.30 s | pass, 64.34 s |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 26 pass, 534.34 s | pass, 64.58 s |
| Vanilla 7.0.14 | 7.0.14 | 26 pass, 446.11 s | pass, 64.26 s |
| Mainline 7.3 | 7.3.0 | 26 pass, 488.03 s | pass, 64.34 s |

Each normal guest also passes 14 privileged library, 20 Linux, five review,
three privileged binary and 28 process cases. Every target runs H20's
IPv4/IPv6 fragmentation and full-size frame checks, the 300-tunnel resource
and traffic case, and the approved retry deadline/completion fixture.
Each clock guest checks wall-clock changes and pause/resume independently.
The IPv6-disabled and IPv6-absent profiles pass on mainline; missing
l2tp_eth degradation passes on Ubuntu 7.0. Every guest result marker is zero.

The resolved Ubuntu package versions are the published stable targets.
The maintainer's anticipated 6.8.0-148.148 is not substituted for an
unpublished image; final publication checks still select 6.8.0-147.147.

This matrix includes the socket application/cleanup fixes, approved MAC/
timing fixtures and streamed inventories. It predates the new checked
libc signal calls. Later test-only coverage additions and the libc fix
need their own qualification. No systemd/udev distribution behavior or
live non-x86 architecture support is inferred from these bare-kernel guests.
The per-target distinctions remain documented in `docs/kernel-behavior.md`.

The runner records image/config/executable identities and bounded QEMU
commands for each guest. Cargo build durations are omitted. The isolated
checkouts and guests do not change host networking.
