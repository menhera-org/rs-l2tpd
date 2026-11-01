# Required-kernel matrix for checked signal calls

`tests/docker/run.sh matrix required` passes in a clean frozen checkout of
`ce6a70a362fba716e7f5226ce61e032771b4819c`. Both source patches are empty;
initial and final published versions match. All thirteen guest profiles
have zero conformance, scenario and guest result markers; the driver
records MATRIX_RESULT=0.

| Target | Guest release | Normal scenarios | H16 clock/QMP |
|---|---|---|---|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 26 pass, 557.56 s | pass, 64.38 s |
| Vanilla 6.8.12 | 6.8.12 | 26 pass, 461.43 s | pass, 64.36 s |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 26 pass, 491.09 s | pass, 64.47 s |
| Vanilla 7.0.14 | 7.0.14 | 26 pass, 432.07 s | pass, 64.31 s |
| Mainline 7.3 | 7.3.0 | 26 pass, 435.94 s | pass, 64.24 s |

Each normal guest also passes 14 privileged library, 20 Linux, five review,
56 ordinary binary, three privileged binary and 28 process cases. Eight
daemon fault cases include checked signal-mask and signal-wait refusals.
Every target checks H20's eight fragmentation combinations, 300 tunnels
with bidirectional traffic, and the approved retry deadline/completion
distinction. Each clock guest independently checks wall-clock changes and
controller-confirmed pause/resume. Mainline passes both IPv6-absent boots;
Ubuntu 7.0 passes missing-Ethernet-driver degradation and recovery.

These are published stable targets, not anticipated unpublished packages.
The record contains exact commands, features, image/config/executable
identities and guest releases. Cargo build durations are omitted.
Isolated checkouts and guests do not change host networking.

The matrix includes streamed inventories and checked libc signal calls.
Later installer, thread-limit-driver and file-conflict tests do not change
production mappings but are not claimed as executed by these frozen guests.
`precommit-common.log` instead checks the later tree identified by
`precommit-revision`. GitHub run 41277232235 passes both jobs, including
the new signal-thread resource step; `ci-jobs.json` records their results.

A separate one-event witness still exposes namespace-wide address reads
(`audit/phase6/event-inventory-cost-20261101/`). This matrix does not prove
the complete event-cost contract or 100% coverage. Bare-kernel guests do not
establish per-distribution udev/networkd or system-container behavior;
those userspace checks remain separately scoped in
`docs/kernel-behavior.md`.
