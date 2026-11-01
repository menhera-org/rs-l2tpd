# Required kernels at fb0620d: all thirteen profiles pass

The frozen signed source is fb0620d6a28f5ee62aaf1363848457192f6787e4.
Shipping logic and registry iphost 0.4.4 match production 584062d; later
commits add tests and coverage harnesses. Both source.patch and
final-source.patch are empty. Initial and final publication selections
agree; every profile and MATRIX_RESULT is zero.

| Required target | Guest release | Normal scenarios | H16 clock/pause |
|---|---|---|---|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 27 pass, 595.05 s | pass, 64.88 s |
| Vanilla 6.8.12 | 6.8.12 | 27 pass, 489.78 s | pass, 64.35 s |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 27 pass, 552.40 s | pass, 64.62 s |
| Vanilla 7.0.14 | 7.0.14 | 27 pass, 461.17 s | pass, 64.29 s |
| Mainline 7.3 | 7.3.0 | 27 pass, 459.84 s | pass, 64.35 s |

Each normal guest also passes 20 serial library, 24 Linux, five review,
63 ordinary binary, three privileged binary and 29 process cases. All eight
daemon setup faults pass. The new absent-family case observes ENOENT,
invalidates the stale family, resolves it again, queries an absent tunnel
and subscribes successfully on each required kernel. The existing positive
client-identity/binding, anonymous Reply, fragmentation, 300-entry daemons,
selected inventories, VRF reload and E27 stale-notice cases also pass.

Mainline passes ipv6.disable=1 in 2.93 s and CONFIG_IPV6=n in 3.01 s.
Ubuntu 7.0 passes missing-Ethernet-driver degradation/recovery in 4.74 s.
Ubuntu 7.0 retains the documented kho=off cold-boot setting. These bare-
kernel guests do not establish Incus or distribution-manager behavior.

This record extends the earlier 584062d matrix's test scope. It excludes
the later host-adapter success/completion fixtures and the production
netlink reply-state correction. That correction needs a new matrix.
No broader distribution or non-x86 execution is claimed. Phase 6 remains
open; complete clause/history/resource proof and 100% coverage are still
required.
