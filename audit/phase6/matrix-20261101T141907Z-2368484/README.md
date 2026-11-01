# Required kernels with released iphost 0.4.4: all thirteen profiles pass

The frozen signed production commit is
`584062d9bcc90c5034d0461b652a795af9401f3b`. The shipping manifest and lockfile
use registry iphost 0.4.4, including anonymous Reply validation. The source
also contains checked atomic admission and the check-output writer boundary.
Both source.patch and final-source.patch are empty. Initial and final
publication selections agree; every profile and MATRIX_RESULT is zero.

| Required target | Guest release | Normal scenarios | H16 clock/pause |
|---|---|---|---|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 27 pass, 555.54 s | pass, 64.59 s |
| Vanilla 6.8.12 | 6.8.12 | 27 pass, 487.12 s | pass, 64.42 s |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 27 pass, 549.94 s | pass, 64.59 s |
| Vanilla 7.0.14 | 7.0.14 | 27 pass, 460.22 s | pass, 64.49 s |
| Mainline 7.3 | 7.3.0 | 27 pass, 476.57 s | pass, 64.27 s |

Each normal guest also passes 19 serial library, 24 Linux, five review,
62 ordinary binary, three privileged binary and 29 process cases. All
eight daemon setup faults pass. The 19 library cases include the four
client-identifier modes/static DNS binding and the anonymous Reply
counterexample. Both pass on all five required kernels with released 0.4.4.
Fragmentation, both 300-entry daemons, filtered inventories, VRF-binding
reload and the E27 live stale-notice replay pass on each target.

Mainline passes ipv6.disable=1 in 2.97 s and CONFIG_IPV6=n in 2.87 s.
Ubuntu 7.0 passes missing-Ethernet-driver degradation/recovery in 4.67 s.
The Ubuntu 7.0 cold-boot profile retains the documented kho=off setting.
Bare-kernel guests do not establish Incus or distribution-manager behavior;
those separate results remain in the integration record.

The former 11bef84 matrix qualifies the earlier iphost 0.4.3 source. This
record supersedes its current-source status. Later host-worker, runtime,
service and netlink test additions have separate qualification records;
this frozen run does not execute those declarations. No broader kernel or
non-x86 execution is claimed. Complete clause/history/resource proof and
100% coverage remain open.
