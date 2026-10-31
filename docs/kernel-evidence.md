# Kernel evidence map

[Per-required-kernel behavior and execution scope](kernel-behavior.md)
records the version-dependent observations and remaining proof.

[Documentation index](README.md) · Verification results (repository file `audit/PHASE23_VERIFICATION_2026-10-29.md`)

`shared` means the same operation body runs on fake and real kernels in
`tests/kernel/conformance.rs`. `live` means a host/fixture assertion against
the production operations or a released resolver adapter. `source` and
`requirement` rows are deliberately not counted as executed live cases.
The source column of [the kernel specification](spec/kernel.md) supplies the
kernel files and versioned lines for each row; production functions repeat
their own relevant citations.

| Fact | Evidence kind and location | Source-link scope |
|---|---|---|
| K1 | requirement + live: `LinuxKernel::new` resolves the family in every fixture; `conformance_on_the_linux_kernel` | linux |
| K2 | live: `sockets_bind_connect_and_report_their_source`, both native V4 and V6 sockets | linux |
| K3 | shared: all session creation cases explicitly request Ethernet with no sublayer | linux |
| K4 | requirement + live positive: V6 socket creation; refusal policy is tested with both errnos in `socket_family_fallback_never_recreates_existing_tunnels`; the scoped mainline H4/T4 boots exercise ipv6.disable=1 and CONFIG_IPV6=n (see kernel-behavior.md) | linux |
| K5 | shared: `disconnected_sessions_count_frame_drops`; live: `disconnected_sessions_drop_outbound_but_receive_only_matching_cookies` transmits and observes counters | linux |
| K6 | shared: `connect_selects_the_source_of_the_device`, disconnect/reconnect across families | linux |
| K7 | shared: `the_monitor_reports_links_and_addresses`; live: ordered lifetime requests and loss tests | linux |
| K8 | requirement: kernel command capability checks cited by `LinuxKernel::new` and the L2TP adapter; privileged positive operation runs | linux |
| K9 | live: `links_are_found_by_name_and_dumped`; shared VRF/zone/source cases | linux |
| K10 | unit: BPF instruction cases; live: production filtered monitor observes link and address changes | linux |
| K11 | live: `a_tunable_write_changes_only_fresh_sockets` | linux |
| K12 | removed; no evidence obligation | removed |
| K13 | delegated requirement: released iphost DHCPv6 socket implementation; live positive port-546 bind in `released_unified_adapter_enables_per_family_failure_fallback` | delegated |
| K14 | delegated implementation plus live daemon fallback: H15's `without_net_raw_router_discovery_requires_accept_ra_and_binding_still_reconnects` removes CAP_NET_RAW, proves accept_ra gating and actual DNS/frames; upstream `parses_netlink_useropt` and raw/netlink equivalence regressions remain separate source evidence | delegated |
| K15 | live: `disconnected_sessions_drop_outbound_but_receive_only_matching_cookies`, foreign source and correct/wrong/absent cookies | linux |
| K16 | shared: stored-name and rename cases; live review: duplicate stored creation names; policy: ambiguity refuses deletion | linux |
| K17 | shared: closing the socket deletes tunnel and sessions; live real-manager reference test and handover test | linux |
| K18 | shared: identifier reuse after deletion; live review: 32 delete/recreate cycles; policy: reuse waits for confirmed absence; source comparison establishes the release boundary | linux |
| K19 | shared: tunnel and namespace-wide session uniqueness, wrong-tunnel lookup and deletion refusal; verified on both sides of the newer lookup behavior | linux |
| K20 | shared: a taken name leaves no session | linux |
| K21 | source/requirement: autoload call sites in the kernel specification; fixtures exercise normal family/link creation, without claiming that already-loaded modules prove autoload policy | linux |
| K22 | shared: bound/unbound binding semantics; fake runs without NET_RAW, live runs with it; reconnect policy is tested without that capability in the fake | linux |
| K23 | live: tunable write, old socket stays v6-only, fresh socket reads dual-stack; fake policy covers both fallbacks and failed read-back | linux |
| K24 | shared: stale source/bare connect refusal and disconnect/reselection | linux |
| K25 | live: `the_kernel_keeps_the_previous_ipv6_peer_after_disconnect` | linux |
| K26 | shared: empty IPv6 VRF refusal (EADDRNOTAVAIL, or ENETUNREACH on vanilla 6.8.12), link-local/binding refusal; fake policy explicitly covers every transient connect errno; route-type errno table remains source evidence | linux |
| K27 | shared: zone must equal the bound link or belong to its VRF; policy tests replacement, rename and membership dependencies | linux |
| K28 | shared: ordinary bound link without a route, VRF source selection | linux |
| K29 | live production unit tests: actual lifetime overflow, missing mutation reply with applied mutation and socket reopening; unit framing/absolute deadline tests | linux |
| K30 | live: a second netlink port sends a forged removal; ordered production lookup preserves the registration | linux |
| K31 | shared: hardware-address EBUSY while up, unchanged address succeeds, rename while up | linux |
| K32 | requirement + unit: configuration name validation; shared explicit-name and name-collision operations | linux |
| K33 | source: IPv6 down transition; the Kernel boundary has no operation to lower a device, and policy tests preserve administrative state and child records | source-only |
| K34 | shared/live: unspecified IPv4 source and missing IPv6 source; policy treats an unspecified returned source as a failed connect | linux |
| K35 | live production unit: every cookie length 0 through 8 is read; invalid configuration lengths stay rejected and Debug hides bytes | linux |
| K36 | source/requirement: initial-user-namespace capability check; live production unit: `subscription_buffer_matches_force_or_capped_fallback` compares the production buffer with FORCE or ordinary-buffer behavior; the unprivileged Incus runner requires the EPERM fallback branch to run; finite-buffer overflow is exercised separately | linux |
| K37 | live: descriptor duplicate/adoption and real systemd manager holds the only reference until acknowledged withdrawal | linux |
| K38 | delegated source/requirement: released iphost shared DHCPv6 listener and the kernel socket-selection sources; downstream live adapter binds 546 and exchanges a Reply | delegated |
| K39 | requirement + live: raw RA socket under NET_RAW; fake binding conformance also runs without NET_RAW | linux |
| K40 | live raw-source adapter explicitly receives RDNSS with `accept_ra=0`; netlink gating is source/requirement evidence | delegated |
| K41 | shared: commanded deletions announced; live: socket close not announced; review probe tests colliding foreign-namespace IDs on pre-7.3 and 7.3 kernels | linux |
| K42 | live: namespace move and explicit index/name reuse within one lifetime generation; old proof remains Removed and new registration has a distinct incarnation | linux |
| K43 | source + live 2026-10-30 (repository directory `audit/phase5-completion/fragmentation/`: current and 0.1.5 daemons, sessions at 1500 and 9000 over a 1500-byte veth, IPv4 and IPv6 underlays, full-size pings both ways, sender fragment counters growing, whole frames on the receiving session device) + Phase 6 scenario H20; no daemon code path depends on it (T5) | source-only |
| K44 | source + live T5 option setting on every tunnel socket (`kernel::linux` socket creation cites it); a live case reads the options back with `getsockopt` on both families; the H20 scenario proves the IPv4 contract and, together with K43, the IPv6 behaviour | linux |

The source-link gate reads the scope column. Every active fact needs an
explicit scope: linux requires a production function citation; delegated
and source-only require a test declaration citation and the evidence above.
These classifications do not claim that a source assertion ran on a kernel.
This treatment was approved by the maintainer on 2026-10-30.

K13, K14, K33, K38 and K40 are not facts used by production functions in
`kernel::linux`: the resolver operations are delegated to iphost and device
lowering is absent. Their classified test evidence satisfies the source-link
gate without manufacturing production citations or equating source assertions
with live execution.
