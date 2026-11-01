# Required-kernel matrix for selected inventories and VRF completion

`tests/docker/run.sh matrix required` returns **MATRIX_RESULT=0** on frozen
source `2051827a6b823c354098273628e416cf93e96084`. All thirteen guest
profiles pass. Initial and final publication checks select identical versions;
both tracked-source patches are empty.

| Target | Guest release | Normal scenarios | H16 clock/QMP |
|---|---|---|---|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 27 pass, 562.94 s | pass, 64.69 s |
| Vanilla 6.8.12 | 6.8.12 | 27 pass, 485.76 s | pass, 64.59 s |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 27 pass, 514.57 s | pass, 64.55 s |
| Vanilla 7.0.14 | 7.0.14 | 27 pass, 482.78 s | pass, 64.43 s |
| Mainline 7.3 | 7.3.0 | 27 pass, 447.25 s | pass, 64.32 s |

Each normal guest also passes fourteen serial library cases, 23 Linux cases,
five review cases, 58 ordinary binary cases, three privileged binary cases
and 28 process cases. All eight daemon setup faults pass, including the
checked libc signal-mask and signal-wait refusals.

Every target checks H20's eight fragmentation combinations, 300 tunnels with
bidirectional traffic and both ordinary dependency selectors. The new live
reload case binds an already-known member's parent VRF and requires the
existing sibling's address changes to reconnect only the new VRF-bound
tunnel. These guests include the known-kind/inventory-completion cache fix.

Mainline also passes both IPv6-absent profiles. Ubuntu 7.0 passes
missing-Ethernet-driver degradation and recovery. All five clock profiles
have controller-confirmed pause/resume results. `verification.log` records
the marker, source and publication checks. Guest commands, executable/config
identities, releases and exact counts remain in each profile's logs.

The first attempt stopped in publication resolution because the environment's
curl wrapper failed TLS. `initial-resolver-refusal/` retains that attempt;
no guest result is claimed for it. The successful run selects
`/usr/bin/curl` through PATH. No host networking changes are made.

The frozen source predates later test-only additions: the narrower
standard-stream fault, extra resolver validation and adapter-drop cases,
the public-constructor lifecycle and the shared rule harness. Those packages
have separate execution records. This matrix does not claim their new test
counts or a completed 100% coverage gate.

Bare-kernel guests do not establish per-distribution udev/networkd or
unprivileged-container behavior. The separately qualified userspace scope
is documented in `docs/kernel-behavior.md`. Full clause/history proof and
the global Phase 6 gates remain open.

The documentation commit's `precommit-common.log` checks the later test tree
identified by `precommit-revision` (5741e89). It is separate from the frozen
2051827 guest results. The standalone documentation-link check also passes.
