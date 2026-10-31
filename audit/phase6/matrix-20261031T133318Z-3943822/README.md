# Current required-kernel refresh: one failed scenario

`tests/docker/run.sh matrix required` returned `MATRIX_RESULT=1`.
The source revision is `0f5292e`; both source patches are empty. Published
targets at the beginning and end match exactly. This is a failed matrix,
despite the passing individual profiles below.

| Target | Normal profile | Clock/pause profile |
|---|---|---|
| Ubuntu `6.8.0-147.147`, release `6.8.0-147-generic` | 26 scenarios pass | Pass |
| Vanilla `6.8.12` | 26 scenarios pass | Pass |
| Ubuntu `7.0.0-42.42`, release `7.0.0-42-generic` | 26 scenarios pass | Pass |
| Vanilla `7.0.14` | 25 pass; H8 netlink-count assertion fails | Not run: the normal profile failed first |
| Mainline `7.3`, release `7.3.0` | 26 scenarios pass | Pass |

All five normal guests pass 11 live library cases, 19 kernel cases,
five review cases, 38 ordinary binary cases plus privileged probes and
27 process cases. They execute all 26 normal scenarios. H20's eight
fragmentation combinations and the H17 300-tunnel/resource case pass on
every target, including vanilla 7.0.14. These individual passes do not
override that target's failed scenario-suite result.

The vanilla 7.0.14 failure is in
`netlink::large_default_free_tables_do_not_add_daemon_route_queries`:
the small-table capture has 36 total requests, including 15 generic-netlink
requests; the large-table capture has 37, including 16 generic-netlink
requests. Both have exactly two route queries, the deliberate fixture
controls. The total-count equality fails. The complete failed transcript
is retained in [vanilla-7.0.14/run.log](vanilla-7.0.14/run.log); investigation
is separate from this result.

Both mainline IPv6-absent profiles pass their single scoped case:
`ipv6.disable=1` and a separate `CONFIG_IPV6=n` build. The stock Ubuntu
7.0 missing-Ethernet-driver profile also passes its single degradation/
recovery case. These boots do not execute normal IPv6-dependent suites.

Each profile retains its QEMU command, exact guest release, executable
identities, kernel configuration and result markers. Package/source logs
identify images and modules. Cargo build durations and download progress
are omitted. The Ubuntu 7.0 cold boot retains its documented `kho=off`
setting. No manager/Incus or root-systemd behavior is inferred from these
bare-kernel guests. Complete clause, event-cost, resource/history and
coverage proof remain separate Phase 6 requirements.
