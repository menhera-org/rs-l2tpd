# Kernel evidence map

[Documentation index](README.md) · [Verification results](../audit/PHASE23_VERIFICATION_2026-10-29.md)

`shared` means the same operation body runs on fake and real kernels in
`tests/kernel/conformance.rs`. `live` means a host/fixture assertion against
the production operations or a released resolver adapter. `source` and
`requirement` rows are deliberately not counted as executed live cases.
The source column of [the kernel specification](spec/kernel.md) supplies the
kernel files and versioned lines for each row; production functions repeat
their own relevant citations.

| Fact | Evidence kind and location |
|---|---|
| K1 | requirement + live: `LinuxKernel::new` resolves the family in every fixture; `conformance_on_the_linux_kernel` |
| K2 | live: `sockets_bind_connect_and_report_their_source`, both native V4 and V6 sockets |
| K3 | shared: all session creation cases explicitly request Ethernet with no sublayer |
| K4 | requirement + live positive: V6 socket creation; refusal policy is tested with both errnos in `socket_family_fallback_never_recreates_existing_tunnels`; boot-disabled/no-IPv6 builds are Phase 6 |
| K5 | shared: `disconnected_sessions_count_frame_drops`; live: `disconnected_sessions_drop_outbound_but_receive_only_matching_cookies` transmits and observes counters |
| K6 | shared: `connect_selects_the_source_of_the_device`, disconnect/reconnect across families |
| K7 | shared: `the_monitor_reports_links_and_addresses`; live: ordered lifetime requests and loss tests |
| K8 | requirement: kernel command capability checks cited by `LinuxKernel::new` and the L2TP adapter; privileged positive operation runs |
| K9 | live: `links_are_found_by_name_and_dumped`; shared VRF/zone/source cases |
| K10 | unit: BPF instruction cases; live: production filtered monitor observes link and address changes |
| K11 | live: `a_tunable_write_changes_only_fresh_sockets` |
| K12 | removed; no evidence obligation |
| K13 | delegated requirement: released iphost DHCPv6 socket implementation; live positive port-546 bind in `released_unified_adapter_enables_per_family_failure_fallback` |
| K14 | delegated requirement: released iphost RA netlink source; upstream `parses_netlink_useropt` and raw/netlink equivalence regressions; no claim that the downstream raw-source run executes capability-denied fallback |
| K15 | live: `disconnected_sessions_drop_outbound_but_receive_only_matching_cookies`, foreign source and correct/wrong/absent cookies |
| K16 | shared: stored-name and rename cases; live review: duplicate stored creation names; policy: ambiguity refuses deletion |
| K17 | shared: closing the socket deletes tunnel and sessions; live real-manager reference test and handover test |
| K18 | shared: identifier reuse after deletion; live review: 32 delete/recreate cycles; policy: reuse waits for confirmed absence; source comparison establishes the release boundary |
| K19 | shared: tunnel and namespace-wide session uniqueness, wrong-tunnel lookup and deletion refusal; verified on both sides of the newer lookup behavior |
| K20 | shared: a taken name leaves no session |
| K21 | source/requirement: autoload call sites in the kernel specification; fixtures exercise normal family/link creation, without claiming that already-loaded modules prove autoload policy |
| K22 | shared: bound/unbound binding semantics; fake runs without NET_RAW, live runs with it; reconnect policy is tested without that capability in the fake |
| K23 | live: tunable write, old socket stays v6-only, fresh socket reads dual-stack; fake policy covers both fallbacks and failed read-back |
| K24 | shared: stale source/bare connect refusal and disconnect/reselection |
| K25 | live: `the_kernel_keeps_the_previous_ipv6_peer_after_disconnect` |
| K26 | shared: no IPv6 source, link-local/binding refusal; fake policy explicitly covers every transient connect errno; route-type errno table remains source evidence |
| K27 | shared: zone must equal the bound link or belong to its VRF; policy tests replacement, rename and membership dependencies |
| K28 | shared: ordinary bound link without a route, VRF source selection |
| K29 | live production unit tests: actual lifetime overflow, missing mutation reply with applied mutation and socket reopening; unit framing/absolute deadline tests |
| K30 | live: a second netlink port sends a forged removal; ordered production lookup preserves the registration |
| K31 | shared: hardware-address EBUSY while up, unchanged address succeeds, rename while up |
| K32 | requirement + unit: configuration name validation; shared explicit-name and name-collision operations |
| K33 | source: IPv6 down transition; the Kernel boundary has no operation to lower a device, and policy tests preserve administrative state and child records |
| K34 | shared/live: unspecified IPv4 source and missing IPv6 source; policy treats an unspecified returned source as a failed connect |
| K35 | live production unit: every cookie length 0 through 8 is read; invalid configuration lengths stay rejected and Debug hides bytes |
| K36 | source/requirement: initial-user-namespace capability check; production subscription opens attempt FORCE then ordinary receive buffer; actual finite-buffer overflow is exercised separately |
| K37 | live: descriptor duplicate/adoption and real systemd manager holds the only reference until acknowledged withdrawal |
| K38 | delegated source/requirement: released iphost shared DHCPv6 listener and the kernel socket-selection sources; downstream live adapter binds 546 and exchanges a Reply |
| K39 | requirement + live: raw RA socket under NET_RAW; fake binding conformance also runs without NET_RAW |
| K40 | live raw-source adapter explicitly receives RDNSS with `accept_ra=0`; netlink gating is source/requirement evidence |
| K41 | shared: commanded deletions announced; live: socket close not announced; review probe tests colliding foreign-namespace IDs on pre-7.3 and 7.3 kernels |
| K42 | live: namespace move and explicit index/name reuse within one lifetime generation; old proof remains Removed and new registration has a distinct incarnation |

K13, K14, K33, K38 and K40 are not facts used by production functions in
`kernel::linux`: the resolver operations are delegated to iphost and device
lowering is absent. The global Phase 6 source gate still reports these five
as uncited in that module; this table does not manufacture production citations
or equate source assertions with live execution.
