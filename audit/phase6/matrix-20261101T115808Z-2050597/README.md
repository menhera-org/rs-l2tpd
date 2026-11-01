# Required kernels: advisory deletion verification

All thirteen profiles pass on frozen production source
`11bef84ac2a3b7c282f2a29552e7ff854a9915ee`. This includes the E27 correction:
a queued-deletion announcement keeps its verification task while the current
session remains present. Each kernel passes the live stale-notice replay
while preserving the active replacement's index, MAC and UP state.
The replay does not force kernel deletion work to remain queued.

`source.patch` and `final-source.patch` are empty. Initial and final
publication selections agree; package metadata, kernel configurations,
artifact identities and complete guest/controller logs are retained.

| Required target | Normal scenarios | H16 clock/pause |
|---|---|---|
| Ubuntu 6.8.0-147.147 / 6.8.0-147-generic | 27 pass, 559.54 s | Pass, 64.78 s |
| Vanilla 6.8.12 | 27 pass, 484.36 s | Pass, 64.33 s |
| Ubuntu 7.0.0-42.42 / 7.0.0-42-generic | 27 pass, 540.15 s | Pass, 64.70 s |
| Vanilla 7.0.14 | 27 pass, 464.66 s | Pass, 64.79 s |
| Mainline 7.3 / 7.3.0 | 27 pass, 445.57 s | Pass, 64.43 s |

Each normal guest also passes 17 serial library cases, 24 Linux cases,
five review cases, 59 ordinary binary cases, three privileged binary cases
and 29 process cases. Eight daemon setup-fault paths pass. Four additional
binary declarations remain ignored in its ordinary invocation; privileged
probes have their separate commands, and the actual user-manager case has
separate local qualification.

All five kernels pass H20's eight fragmentation combinations, H17's two
300-entry daemons and zero unrelated-event queries, selected inventories
and the known-parent VRF reload regression. Clock controllers confirm
pause/resume and zero results. Mainline's IPv6-disabled and CONFIG_IPV6=n
profiles pass in 2.98 and 2.99 s; Ubuntu 7.0's missing-Ethernet-driver
degradation/recovery passes in 4.64 s. Ubuntu 7.0 uses the documented
`kho=off` cold-boot override.

K26/K34 retain the documented errno difference: vanilla 6.8.12 refuses an
empty IPv6 VRF with ENETUNREACH, the other targets with EADDRNOTAVAIL.
K41 remains namespace-wide before 7.3 and namespace-local in 7.3.
Per-target evidence and source distinctions are in
[the kernel behavior page](../../../docs/kernel-behavior.md).

## Scope and remaining proof

This matrix uses released iphost 0.4.3. The later anonymous-Reply witness
exposes a missing V12 rejection in that dependency; positive matrix results
do not close that defect. Its upstream fix, release and downstream
integration are recorded separately in
[the defect record](../anonymous-reply-20261101/README.md).

Later test-only additions have separate GNU/musl qualification, including
the resolver identity wire case on Ubuntu 6.8. These bare-kernel guests do
not establish other distributions' udev/networkd or Incus behavior.
The new dependency needs its own qualification. Complete clause/history/
resource proof and 100% coverage remain open.

```sh
tests/docker/run.sh matrix required
```

The command ran from the recorded frozen checkout.
