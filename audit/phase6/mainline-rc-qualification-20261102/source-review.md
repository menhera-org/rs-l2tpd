# Mainline 7.4-rc1 source comparison

The comparison uses the extracted 7.3 and 7.4-rc1 kernel build trees.
`source-identities.log` identifies all 43 selected files by Git blob digest;
`source-diff.patch` retains their complete difference and
`source-contracts.log` gives line-numbered anchors in the RC tree.
`archive-source-identity.log` confirms that all 43 selected files in each
tree match a fresh extraction from their respective source archives.
The archive identities are recorded there and by the builder. This is source evidence;
the live profiles establish execution separately.

| Facts | Reviewed RC source and effect of the changes |
|---|---|
| K1–K4, K8, K9, K21 | L2TP Makefile, generic-netlink family registration and capability/autoload paths, IPv4/IPv6 socket registration and VRF Kconfig remain applicable. IPv6 initialization moves earlier in boot; live socket and IPv6-absent profiles must verify availability. |
| K5, K6, K15, K17, K19 | The L2TP/IP socket files are unchanged. The core still drops sends through an unestablished userspace socket, selects receive sessions by namespace/session ID and retains socket-owned tunnel deletion. Sequence-state accesses become READ_ONCE/WRITE_ONCE; header construction snapshots the sequence flag. The daemon requests no L2-specific sublayer. |
| K7 | Strict link/master and IPv4/IPv6 address selectors and absent-IPv6-state detection remain. Link replies gain a pacing-offload attribute; unknown attributes must remain tolerable. The getlink liveness helper is renamed from dev_isalive to netif_is_alive with the same registration-state predicate. |
| K10 | Changes in filter.c concern eBPF helpers and access checks; the classic filter attachment, instruction validation and loads used by the monitor retain their contract. |
| K11, K23, K24, K25 | Socket creation still fixes V6ONLY; L2TP pins inet_num. IPv4-mapped and native IPv6 connect/disconnect handling retains the cited source and binding rules. Removing IPV6_ADDRFORM conversion and moving FREEBIND/TRANSPARENT handling does not change the options used by the daemon. |
| K13, K38, K39 | Privileged-port checks, raw-socket permissions and fixed-port reuse/receive selection remain. UDP's automatic free-port scan now treats every occupied bitmap slot as busy; the explicit port-546 reuse check still honors reuse options. |
| K14, K40 | RA acceptance still gates ND_USEROPT forwarding. Router-discovery neighbor lookups move to per-network-namespace tables. The source requirement and the released adapter's raw/netlink fallback distinction remain; live RA cases must exercise the RC. |
| K16, K18, K20, K35 | Stored creation names, session lookup/dump, workqueue deletion and cookie policies remain. Netlink sequence-state modification no longer recomputes header length; the daemon does not request this sequence option. Ethernet registration gains the common driver-ops validation; the L2TP Ethernet driver is unchanged. |
| K22, K26–K28, K34 | Binding/disconnect and scope checks remain. IPv6 source selection in ip6_route.h is unchanged, including the L3-domain selection responsible for the newer empty-VRF refusal. IPv4 FIB changes add namespace context to traces. Neighbor-table and cached-route cleanup change independently of these connect rules; the exact refusal remains a live assertion. |
| K29, K30, K36 | Netlink overrun, sender permissions, strict checking and receive-buffer capability rules remain. netlink_dump changes its queue-budget check to allow a chunk when previously queued memory is below the limit and reject totals above INT_MAX. This retains flow-controlled dump delivery; it does not remove ENOBUFS handling for other messages. FORCE still checks the initial-user-namespace capability and ordinary RCVBUF is capped/doubled. |
| K31–K33, K42 | The Ethernet driver's random MAC, MAC-while-up refusal, equal-address fast path, name validation and index allocation/move contracts remain. Device registration/unregistration locking and cached-route flushing change. IPv6 address removal adds hash unlinking and locking; keep_addr_on_down remains the preservation condition. |
| K37, K41 | Socket reference lifetime remains unchanged. Both L2TP delete-notification helpers still multicast on the tunnel's namespace before deletion; close-driven removal retains its separate notification behavior. |
| K43, K44 | L2TP still marks data ignore_df and selects the IPv4/native-IPv6 output paths. IPv4 DF decisions and IPv6 fragment checks remain. Neighbor lookup helpers and IPv4 identification bookkeeping change; neither supplies a new IPv6 PMTU-option guarantee. H20 must still prove actual full-size delivery and fragmentation on the RC. |

No contract change has been inferred from this comparison. The existing
precise errno, identity, overflow, fragmentation and lifecycle assertions
remain enabled for the live matrix. The selected-file comparison is not a
claim to have reviewed every kernel change or every unrelated networking
subsystem. Broader daemon clause/history/resource/event-cost proof and
production coverage remain separate open requirements.
