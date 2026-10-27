# Specification audit — 2026-10-27

| Audit detail | Value |
|---|---|
| Date | **2026-10-27 (Asia/Tokyo)** |
| Repository | **rs-l2tpd** |
| Revision | **d1450de8f7ec1818d676bb4f262da0ea22fbc110** (`specs`) |
| Scope | **All 14 files in docs/spec, 1,758 lines**, plus normative references to docs/contracts.md |
| Deliverable | Specification findings and proposed validation; no specification or implementation changes |

The specification needs revision before it can serve as a consistent conformance oracle. This audit identifies **37 findings: 11 High, 22 Medium, and 4 Low**. Several requirements prescribe mutually exclusive outcomes. Other requirements rely on ownership evidence or kernel behavior that cannot support the stated guarantee.

The first decisions should concern traffic isolation (F01, F05, F12, F36), ownership after replacement or notification loss (F02–F06), and reconciliation/readiness semantics (F07–F10). These can affect traffic exposure, deletion of unrelated state, or whether startup and recovery can complete. The report distinguishes errors established by the text or kernel source from behavior that still needs an experiment.

## Scope and method

Every specification page was read in full. Findings were checked across the requirements, promises, architecture, state model, process, configuration, tunnel/session lifecycle, events, host cases, observability, and library API. Each finding includes requirement IDs, source locations, a concrete consequence, and a proposed resolution.

This is **not an audit of whether the current daemon implements the specification**. The known gaps already listed in docs/spec/README.md—absent bind devices, bind changes, external session deletion, restart preservation, and unknown-key reporting—are not counted merely because they are unimplemented. Where those areas appear below, the finding concerns the coherence or correctness of the target specification itself. No repository implementation conformance conclusion is made.

For kernel-dependent questions, Linux source was read before formulating the container experiments. The reproducible reference is upstream **Linux v6.12**; device-rename behavior was also spot-checked at v6.6. These tags are evidence baselines, not an assertion that either is the minimum or newest supported kernel. The specification currently declares neither a minimum kernel nor a supported behavior matrix. Downstream backports can change results, so proposed experiments must record and inspect the actual test kernel's corresponding source.

Primary source paths examined include:

| Kernel source | Relevant functions or behavior |
|---|---|
| net/l2tp/l2tp_ip.c and l2tp_ip6.c | Data versus control receive dispatch; bind, connect, disconnect |
| net/l2tp/l2tp_core.c | Session lookup/registration, cookies, transmit gating, asynchronous teardown |
| net/l2tp/l2tp_eth.c and l2tp_netlink.c | Device/session creation, stored interface name, session lookup/query |
| net/core/sock.c | Device binding and capability check |
| net/core/dev.c | Interface-name validation and renaming |
| net/ipv6/af_inet6.c and datagram.c | IPv6-only default and mapped IPv4 connect |
| net/ipv4/route.c and udp.c | Bound output-interface routing and disconnect |
| net/netlink/af_netlink.c | Queue overflow, error reporting, and reply delivery |
| drivers/net/dummy.c; net/ethernet/eth.c | Dummy transmit/MAC behavior and MAC-change checks |
| net/ipv6/addrconf.c | Link-local generation and its dependency on host settings |

RFC, IANA, kernel documentation, Linux man-pages, and systemd documentation were consulted where the specification relies on their behavior. Citations appear beside the relevant findings. No privileged network tests, container experiments, daemon tests, or Cargo builds were run: this change is a report, and the proposed experiments are not represented as completed validation.

**Severity:** High means conflicting safety or essential lifecycle guarantees, or a concrete host/security-boundary error. Medium means materially divergent valid implementations, missing transitions, or unreliable operational guarantees. Low means localized wording, diagnostic, or scope errors. A severity describes the consequence of implementing the text literally; it does not assert an exploitable bug in the current code.

## Finding index

| ID | Severity | Finding |
|---|---|---|
| [F01](#f01) | High | Binding failure is allowed to bypass the configured interface |
| [F02](#f02) | High | A creation-time name cannot prove a session's lifetime after notification loss |
| [F03](#f03) | High | A matching MAC address does not prove ownership of a null device |
| [F04](#f04) | High | Closing an owned tunnel can delete sessions the daemon does not own |
| [F05](#f05) | High | The discard addresses are not interchangeable, guaranteed packet sinks |
| [F06](#f06) | High | Discard-route ownership is never defined precisely enough for safe deletion |
| [F07](#f07) | High | The global reconcile order conflicts with teardown and mixed name changes |
| [F09](#f09) | High | The unchanged-reload guarantee forbids required recovery |
| [F10](#f10) | High | The applied configuration can contain entries that readiness expressly permits to be absent |
| [F12](#f12) | High | Opening an AF_INET6 socket does not guarantee the required dual-stack behavior |
| [F36](#f36) | High | A tunnel socket's device binding does not establish L2TP/IP data ingress isolation |
| [F08](#f08) | Medium | Preserving previous entries and resolving collisions has no deterministic priority rule |
| [F11](#f11) | Medium | PID publication is detailed, but ownership at removal and failure ordering are not |
| [F13](#f13) | Medium | The permanent IPv4-family latch conflicts with automatic promotion |
| [F14](#f14) | Medium | Routing contexts are reduced to tables, ignoring policy rules and ordinary-device constraints |
| [F15](#f15) | Medium | A substitute connection can lose its only route without any recovery trigger |
| [F16](#f16) | Medium | Connected, pending, and discard states disagree about source validity and failure handling |
| [F17](#f17) | Medium | DNS selection, stale-answer retention, and family changes are underspecified |
| [F18](#f18) | Medium | Name collisions have no temporary-name path for sessions without a configured MAC |
| [F19](#f19) | Medium | The identity and manager-state promises omit several intentional destructive transitions |
| [F20](#f20) | Medium | Continuous fidelity conflicts with accepting manager changes and permanently skipped updates |
| [F21](#f21) | Medium | Failure of either monitor appears to invalidate identity proofs supplied by the other |
| [F22](#f22) | Medium | One bounded event channel is not reconciled with continuous lifetime monitoring |
| [F23](#f23) | Medium | The unconditional zero-cost event promises exclude their own fallback paths |
| [F24](#f24) | Medium | Retry intervals are presented as end-to-end completion deadlines |
| [F25](#f25) | Medium | The declared valid-name grammar accepts names Linux rejects |
| [F27](#f27) | Medium | Strict conversion cannot both ignore unknown keys and fail on every reported problem |
| [F28](#f28) | Medium | An unknown event cannot be forwarded by a wildcard arm that does nothing |
| [F29](#f29) | Medium | Library construction, drop, and filesystem boundaries do not match the claimed daemon parity |
| [F31](#f31) | Medium | Signal reloads cannot promise one ordered reload per signal |
| [F32](#f32) | Medium | The systemd socket-family restriction can exclude the host resolver |
| [F34](#f34) | Medium | The specification and its parent contracts disagree without a precedence rule |
| [F35](#f35) | Medium | An overflowed netlink lookup is not guaranteed to fail only by timeout |
| [F26](#f26) | Low | Merge depth, ordering, and missing-file transitions need concrete examples |
| [F30](#f30) | Low | An ordinary reload callback error is both recoverable and an exit failure |
| [F33](#f33) | Low | Diagnostic severity and entry identifiers are not defined for all promised cases |
| [F37](#f37) | Low | Identifier uniqueness is described as host-wide instead of namespace-scoped |

<a id="f01"></a>

## F01 — Binding failure is allowed to bypass the configured interface

**Severity: High. Type: Contradiction; kernel-dependent prerequisite.**

**Evidence:** [R4](docs/spec/requirements.md#the-host), line 20; [H15](docs/spec/hosts.md#missing-kernel-support-and-privilege), lines 116–122; [G5](docs/spec/promises.md#unconditional-promises), line 19; [T10–T13](docs/spec/tunnels.md#bind-devices), lines 77–102.

R4 and H15 prescribe an unbound tunnel after a binding privilege failure. G5 forbids a bound configuration from sending through another device. A host with a usable main-table route therefore has two incompatible prescribed outcomes. T13's missing-device rule does not resolve failures when the device exists but binding fails. Changing the configured binding to a missing device also lacks an explicit transition rule.

Linux v6.12's `sock_bindtoindex_locked` checks CAP_NET_RAW when the socket already has a binding; lack of that capability does not categorically prevent the first binding. R4/H15's explanation is consequently too broad. [Kernel source](https://github.com/torvalds/linux/blob/v6.12/net/core/sock.c#L627-L718).

**Resolution:** Specify one traffic-safe policy for absent devices, failed binding, failed verification, and failed rebinding. State when a discard connection may temporarily be unbound and what prevents real-peer traffic then. Describe capability requirements by operation and supported kernel version, rather than assuming every initial bind fails.

**Validation:** Container cases K2 and K3 below.

<a id="f02"></a>

## F02 — A creation-time name cannot prove a session's lifetime after notification loss

**Severity: High. Type: Invalid ownership proof.**

**Evidence:** [S19–S24](docs/spec/sessions.md#identity-loss), lines 139–180; [A17](docs/spec/architecture.md#why-this-shape), lines 151–153; [M9–M10](docs/spec/model.md#ownership), lines 93–102.

S22 assumes a foreign session reusing identifiers must have another creation-time name. The specification imposes no enforceable uniqueness across time. During notification loss, an administrator can delete a session and create another with the same identifiers and original name. S22 then authorizes deletion of the foreign session. S23 likewise treats an old index plus a matching temporary name as enough to re-identify a staged device, conflicting with S19's lost proof and S24's prohibition on touching replacements.

The kernel copies the device name into `session->ifname` at registration and returns that string through generic netlink; this is a stored label, not a generation token. [Creation source](https://github.com/torvalds/linux/blob/v6.12/net/l2tp/l2tp_eth.c#L223-L305), [query source](https://github.com/torvalds/linux/blob/v6.12/net/l2tp/l2tp_netlink.c#L725-L748).

**Resolution:** Either require stronger lifetime evidence or explicitly limit the ownership guarantee under indistinguishable replacement. Random temporary names reduce accidental collisions but do not prove identity against an actor able to observe and reuse them. The accepted proof-to-mutation race in M10 does not justify an already ambiguous proof.

**Validation:** K4, including replacement with the exact original name.

<a id="f03"></a>

## F03 — A matching MAC address does not prove ownership of a null device

**Severity: High. Type: Invalid ownership proof.**

**Evidence:** [D7–D10](docs/spec/discard.md#the-null-device), lines 57–78; [M9–M10](docs/spec/model.md#ownership), lines 93–102; [R33](docs/spec/requirements.md#other-network-managers), line 70.

D9 says ownership is proved by the assigned hardware address, yet also says a replacement with the old index or name is foreign. A replacement dummy can be assigned the same MAC. An owned dummy can also have its MAC changed, or be deleted and reappear after a monitor gap. The specified MAC predicate cannot distinguish these cases.

Linux's dummy driver accepts an explicitly supplied valid MAC and uses the ordinary Ethernet MAC-setting operation; the address is mutable metadata. [Kernel source](https://github.com/torvalds/linux/blob/v6.12/drivers/net/dummy.c#L85-L139).

**Resolution:** Define null-device lifetime tracking and loss handling, including the role of the stored index, type, creation result, and MAC. Treat a matching MAC as corroboration, not a lifetime proof. State the same unavoidable race limitations as for sessions.

**Validation:** K5: replace a dummy using its old name, index where available, and MAC, then request repair and shutdown.

<a id="f04"></a>

## F04 — Closing an owned tunnel can delete sessions the daemon does not own

**Severity: High. Type: Impossible unconditional guarantee.**

**Evidence:** [G2 and G9](docs/spec/promises.md#unconditional-promises), lines 16 and 23; [S21, S26](docs/spec/sessions.md#identity-loss), lines 156–161 and 188–190; [P16](docs/spec/process.md#shutdown), lines 104–112.

S21 already admits that an unmanageable or moved session remains only until its tunnel is torn down. P16 nevertheless says an unprovable session is left alone, while G2 universally forbids deleting foreign objects. Another privileged manager can attach a new session to an owned tunnel or replace a deleted session within it. Closing that tunnel necessarily removes those sessions too.

Linux v6.12's `l2tp_tunnel_closeall` schedules deletion of every session on the tunnel's list; it has no userspace-owner exception. [Kernel source](https://github.com/torvalds/linux/blob/v6.12/net/l2tp/l2tp_core.c#L1378-L1438).

**Resolution:** Distinguish direct management from unavoidable destruction of descendants when an owned parent is removed. State the ownership boundary for sessions attached by others and the consequence for moved devices. Also qualify G9: P14's proposed descriptor-store restart deliberately permits tunnels to survive the old process.

**Validation:** K6. This conflict does not require a race to reproduce.

<a id="f05"></a>

## F05 — The discard addresses are not interchangeable, guaranteed packet sinks

**Severity: High. Type: Incorrect standards claim; ambiguous traffic guarantee.**

**Evidence:** [D1–D6](docs/spec/discard.md#addresses), lines 12–53; [H1](docs/spec/hosts.md#address-families), lines 11–12; [G5](docs/spec/promises.md#unconditional-promises), line 19.

D1 says both addresses are reserved for this use and never answer or get forwarded. RFC 7600 allocates 192.0.0.8 as a dummy **source** for synthesized ICMP errors; IANA marks it invalid as a destination. It is not an IPv4 equivalent of the IPv6 discard prefix. [RFC 7600 §4.8](https://www.rfc-editor.org/rfc/rfc7600.html#section-4.8), [IANA IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml). RFC 6666's prefix still relies on routing/filtering policy to discard traffic. [RFC 6666](https://www.rfc-editor.org/rfc/rfc6666.html).

D6 and H1 intentionally accept an ordinary default route. Consequently, payload encapsulated toward a substitute peer can leave the host. The operator-route exception in D3/G5 allows that, but C10's statement that frames are dropped and the unconditional wording in D1 conceal the difference. A default route need not represent an intentional decision to export otherwise undeliverable payload.

**Resolution:** Describe 192.0.0.8 as a local implementation convention, not an RFC-defined discard destination. Define whether any pre-existing default route constitutes the operator's egress opt-in. Tie local dropping to the actual selected sink route, not the address's name.

**Validation:** K3, with packet capture on the underlay.

<a id="f06"></a>

## F06 — Discard-route ownership is never defined precisely enough for safe deletion

**Severity: High. Type: Missing ownership and lifecycle rules.**

**Evidence:** [M9–M10](docs/spec/model.md#ownership), lines 93–102; [A11](docs/spec/architecture.md#state), lines 106–114; [D8, D11–D12](docs/spec/discard.md#the-null-device), lines 64–68 and 82–95; [P16](docs/spec/process.md#shutdown), lines 104–107.

Devices have proposed ownership predicates, but routes only have the phrase “the daemon installed.” The spec does not define the full route identity, metric, protocol, output device, table, or how ownership changes after an external replacement. A route once installed can be removed and recreated by another manager at the same prefix and metric; remembering the successful original installation is not proof that the current route is owned.

D11 also leaves an old VRF table alone after table migration, whereas P16 requires removal of all owned routes. It does not say whether old routes are forgotten, retained for cleanup, or intentionally abandoned.

**Resolution:** Specify an exact installation record and a conservative ownership/replacement policy, including ambiguous monitor gaps. Define route migration, context retirement, and shutdown cleanup separately from route repair. Do not treat prefix equality as ownership.

**Validation:** K5 and K7, especially an external route replacement without a conveniently observed delete/add pair.

<a id="f07"></a>

## F07 — The global reconcile order conflicts with teardown and mixed name changes

**Severity: High. Type: Contradictory operation ordering.**

**Evidence:** [M6](docs/spec/model.md#reconciliation), lines 58–62; [A8](docs/spec/architecture.md#concurrency), lines 90–93; [C14](docs/spec/configuration.md#semantics-of-changes), lines 114–121; [S26](docs/spec/sessions.md#removal), lines 188–190; [P16](docs/spec/process.md#shutdown), lines 104–112.

M6 orders tunnel deletions before session deletions. S26 and P16 require session deletions first, and P16 implements shutdown by applying an empty configuration, which is itself a reconcile. Both sequences cannot govern that operation.

M6 also puts session renames before session deletions. If session B is removed while surviving session A takes B's name, the final rename cannot precede release of B's name unless B is moved temporarily. S11 covers exchanges but does not specify this mixed removal case or an unmanageable B.

**Resolution:** Replace the unconditional phase list with explicit dependency rules: remove provable children before their parent; release every required name/identifier before claiming it; preserve independent progress. Spell out mixed deletion, rename, recreation, and ownership-loss cases.

**Validation:** Specification-level transition tests for empty configuration, name takeover from a removed session, name swaps, and a failed deletion. Kernel experiments are unnecessary to establish the contradiction.

<a id="f09"></a>

## F09 — The unchanged-reload guarantee forbids required recovery

**Severity: High. Type: Contradiction.**

**Evidence:** [M2, M3, M5](docs/spec/model.md#reconciliation), lines 38–56; [G18](docs/spec/promises.md#conditional-promises), line 39; [E17](docs/spec/events.md#operator-events), lines 113–117; [T25](docs/spec/tunnels.md#identifier-conflicts), lines 191–199.

M2 and E17 say an unchanged configuration reload causes no kernel change at all. T25 requires every reload to retry omitted entries. If a conflicting identifier becomes free and the operator reloads identical files, creation is both required and forbidden. The same conflict occurs when a previous reconcile stopped after a failed operation and the next identical reconcile must continue it.

Idempotence means an already satisfied state remains unchanged when relevant inputs are unchanged; it does not mean a repeated desired configuration suppresses repair of incomplete or externally changed state.

**Resolution:** Limit the no-op promise to already converged entries with unchanged relevant host state and no deferred work. Explicitly permit pending creation, publication, cleanup, and conflict recovery on identical reloads.

**Validation:** A trace with a conflict, external release, and identical reload; a trace with a partial failure followed by success.

<a id="f10"></a>

## F10 — The applied configuration can contain entries that readiness expressly permits to be absent

**Severity: High. Type: Contradictory readiness and existence definitions.**

**Evidence:** [Model terms](docs/spec/model.md#terms), lines 7–10 and 26–27; [P6–P8](docs/spec/process.md#readiness), lines 36–51; [G8, G15–G16](docs/spec/promises.md), lines 22 and 36–37; [C13](docs/spec/configuration.md#reload), lines 107–110.

P6 and the model define readiness as every applied entry existing. G8/P7/T25 allow readiness after conflict retries with entries missing. C13 retains the accepted configuration as the next reload's base, and T25 needs the omitted entries to remain available for retry. It is therefore unclear whether “applied configuration” includes desired-but-omitted entries. G16 adds a conditional continuous-existence promise, but its relationship to the deliberately degraded readiness state is left implicit; it should not be read as covering failures outside its prerequisites.

A staged session with a temporary name technically exists, but S6 still calls publication incomplete. The relationship between existence readiness, publication retries, and Service.converge completing needs an explicit rule.

**Resolution:** Separate accepted desired configuration, observed realization, and readiness eligibility. Define readiness as a predicate with stated exclusions, say whether temporary names qualify, and explain that the startup notification is not revoked after later degradation.

**Validation:** Trace startup with permanent ID conflicts, a blocked publication name, and post-readiness external session deletion.

<a id="f12"></a>

## F12 — Opening an AF_INET6 socket does not guarantee the required dual-stack behavior

**Severity: High. Type: Kernel-source-confirmed host incompatibility.**

**Evidence:** [T3–T5](docs/spec/tunnels.md#address-families), lines 32–50; [H1–H3](docs/spec/hosts.md#address-families), lines 11–27; [G10](docs/spec/promises.md#unconditional-promises), line 24.

T3 requires IPv4-mapped operation whenever an IPv6 L2TP socket can be opened. T5 forbids changing socket defaults except device binding. These requirements conflict on a host with `net.ipv6.bindv6only=1`: socket creation succeeds, but IPv4-mapped connection is refused. T4 does not apply because creation did not return either listed error.

In Linux v6.12, `inet6_create` initializes the socket's IPv6-only flag from that sysctl; `l2tp_ip6_connect` calls `__ip6_datagram_connect`, whose mapped-address path returns ENETUNREACH for an IPv6-only socket. [Socket creation](https://github.com/torvalds/linux/blob/v6.12/net/ipv6/af_inet6.c#L214-L235), [L2TP connect](https://github.com/torvalds/linux/blob/v6.12/net/l2tp/l2tp_ip6.c#L386-L435), [datagram connect](https://github.com/torvalds/linux/blob/v6.12/net/ipv6/datagram.c#L141-L219).

**Resolution:** Permit explicitly disabling IPV6_V6ONLY on each socket before binding, with a defined failure policy, or add a host prerequisite and a coherent degraded alternative. Changing a per-socket option need not violate G10's ban on global kernel-setting changes.

**Validation:** K1. This is established by the cited source, not merely a proposed hypothesis.

<a id="f36"></a>

## F36 — A tunnel socket's device binding does not establish L2TP/IP data ingress isolation

**Severity: High. Type: Kernel-source-confirmed security-boundary error.**

**Evidence:** [H7](docs/spec/hosts.md#vrfs), lines 46–53; [T10](docs/spec/tunnels.md#bind-devices), lines 77–81; [R24–R25](docs/spec/requirements.md#the-peers), lines 53–54; [C8](docs/spec/configuration.md#tunnel-entries), line 60.

H7 says a VRF-bound tunnel sends and receives through the VRF's table. This can be read as an ingress isolation guarantee from SO_BINDTODEVICE. The kernel data path does not justify that claim.

In Linux v6.12, both `l2tp_ip_recv` and `l2tp_ip6_recv` dispatch a nonzero-session-ID data packet with `l2tp_v3_session_get(net, NULL, session_id)` and pass it to the session receive routine. Address/device-bound socket lookup appears in the separate session-ID-zero control-packet branch. [IPv4 receive source](https://github.com/torvalds/linux/blob/v6.12/net/l2tp/l2tp_ip.c#L129-L214), [IPv6 receive source](https://github.com/torvalds/linux/blob/v6.12/net/l2tp/l2tp_ip6.c#L133-L213).

**Resolution:** Separate outbound routing policy, outer-IP packet admission, and L2TP session demultiplexing. Do not imply that configuring remote_addr, tunnel IDs, or a bind device authenticates incoming data or isolates it to that VRF. Document the role of cookies and externally configured packet filtering without silently changing the default wire contract.

**Validation:** K11 checks actual delivery from a different ingress device/VRF with controlled session IDs and cookies. Other host packet filters can still block traffic; the finding concerns the L2TP binding mechanism itself.

<a id="f08"></a>

## F08 — Preserving previous entries and resolving collisions has no deterministic priority rule

**Severity: Medium. Type: Ambiguous reload validation precedence.**

**Evidence:** [C9, C12–C13](docs/spec/configuration.md#reload), lines 67–68 and 92–110; [G7](docs/spec/promises.md#unconditional-promises), line 21.

C9 makes the later name the loser in a collision. C12 preserves old values for erroneous existing entries but rejects a whole reload when preserved values no longer fit. The order in which new values and retained old values enter the uniqueness checks changes the result.

Example: A previously uses ID 10 and B uses ID 20. A now has a hard error; valid B requests ID 10; unrelated C changes. A name-ordered pass can retain A, classify B as the later duplicate, retain B, and apply C. A pass validating requested valid entries first can reserve ID 10 for B, discover that retaining A conflicts, and reject everything. C12 does not clearly choose.

Likewise, retaining a session while its old tunnel is intentionally removed needs an explicit dependency rule.

**Resolution:** Define validation passes and collision precedence over the final candidate graph, including missing parents. Give worked examples stating whether the whole reload is refused and which entry is blamed.

**Validation:** Table-driven configuration examples; no daemon implementation inspection is needed.

<a id="f11"></a>

## F11 — PID publication is detailed, but ownership at removal and failure ordering are not

**Severity: Medium. Type: Missing lifecycle and security rules.**

**Evidence:** [P4, P6, P10–P11, P16–P17](docs/spec/process.md), lines 24–28, 36–40, 60–70 and 104–117; [O7](docs/spec/observability.md#exit-codes), lines 35–39.

P10 specifies careful creation and an inode check for in-place updates. P11 merely says to remove the file. It does not say what happens if the pathname now denotes another instance's PID file, a replacement inode, or a file renamed into place after publication. Non-overlapping instances are otherwise not forbidden, yet the default PID pathname is shared.

The ordering of PID publication and the parent-success notification is also not defined as a failure protocol: an unwritable PID path, broken readiness pipe, or shutdown request between those steps needs one outcome.

**Resolution:** Specify ownership-sensitive unlink behavior and the identity retained after publication. Define whether independent instances require distinct PID paths. Publish the PID before notifying success; state cleanup and parent/daemon exit outcomes if either step fails.

**Validation:** Ordinary filesystem/process tests using replacement files and injected failures; no network privilege required.

<a id="f13"></a>

## F13 — The permanent IPv4-family latch conflicts with automatic promotion

**Severity: Medium. Type: Contradictory recovery policy.**

**Evidence:** [T4](docs/spec/tunnels.md#address-families), lines 38–46; [M7–M8, M12](docs/spec/model.md), lines 66–89 and 114–117; [R27](docs/spec/requirements.md#the-peers), line 56; [H15](docs/spec/hosts.md#missing-kernel-support-and-privilege), lines 116–122.

T4 permanently remembers one IPv6-socket refusal and uses AF_INET for later tunnels. M8 requires automatic promotion when an obstacle disappears, while R27 describes an IPv6 peer as pending only while the host remains incapable. If the missing IPv6 L2TP module becomes available later, the specified latch prevents recovery even for newly created tunnels.

Existing AF_INET sockets also cannot become AF_INET6 sockets in place, so M12's interface-preserving family changes require an explicit limitation in this degraded mode.

**Resolution:** Specify the scope and lifetime of the fallback decision, whether capabilities are re-probed, and whether upgrading existing tunnels requires a restart or an explicitly allowed recreation. Distinguish immutable kernel absence from temporarily unavailable protocol support.

**Validation:** K1 on a separately provisioned kernel/module configuration. A container sysctl alone cannot simulate an absent kernel protocol implementation.

<a id="f14"></a>

## F14 — Routing contexts are reduced to tables, ignoring policy rules and ordinary-device constraints

**Severity: Medium. Type: Incorrect routing model; unresolved fallback.**

**Evidence:** [D4, D7–D8](docs/spec/discard.md#routes), lines 37–41 and 57–68; [H7](docs/spec/hosts.md#vrfs), lines 46–53; [T10, T13](docs/spec/tunnels.md#bind-devices), lines 77–102.

D4 equates unbound or ordinary-device sockets with the main table and VRF-bound sockets with the VRF table. Linux routing policy can select another table; even VRF routing can be overridden by higher-priority rules. [Linux VRF documentation](https://docs.kernel.org/networking/vrf.html).

More importantly, a socket bound to an ordinary physical device has an output-interface constraint. Installing a host route through a separate dummy does not by itself establish that this socket will use that route. Linux's IPv4 output path carries the requested interface into routing and can even construct an on-link result after lookup failure for an ordinary bound interface. [Kernel source](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/route.c#L2630-L2810).

**Resolution:** Define route usability using the socket's actual lookup inputs and policy context. Specify how no-route fallback works while preserving an ordinary-device binding, including an administratively down device. Do not assume that installing a dummy route proves local dropping or successful connection.

**Validation:** K2 and K3 resolve end-to-end outcomes for IPv4, IPv6, VRFs, and policy routing. Source establishes the missing constraint; packet behavior still needs the experiment.

<a id="f15"></a>

## F15 — A substitute connection can lose its only route without any recovery trigger

**Severity: Medium. Type: Missing state transition.**

**Evidence:** [D6, D11–D12](docs/spec/discard.md), lines 48–53 and 82–95; [E9, E13](docs/spec/events.md), lines 65–72 and 95–98; [H8](docs/spec/hosts.md#routers), lines 57–62; [T18](docs/spec/tunnels.md#peers-that-cannot-be-reached), lines 141–143.

Consider a tunnel with a tolerated invalid endpoint, connected to a discard address using the host's default route. The default route disappears. E9/H8 deliberately ignore that change; no owned route exists for D11 to repair; D12 forbids creating a previously uninstalled route during repair. With no pending real peer, E13 need not run, and T18 excludes address-driven reconnects.

The specification does not say whether this remains an acceptable degraded state, whether discard-route grace is re-entered, or whether any later event revisits it. Similar ambiguity arises when another manager brings an owned null device down without deleting it.

**Resolution:** Define whether fallback route availability is a maintained invariant or only a creation prerequisite. If maintained, supply a trigger that respects the route-churn constraints; otherwise qualify T1/T2/G17 and readiness's continuing meaning.

**Validation:** K7: remove a covering foreign route and separately lower the owned dummy while no real peer is pending.

<a id="f16"></a>

## F16 — Connected, pending, and discard states disagree about source validity and failure handling

**Severity: Medium. Type: Contradictory state definitions.**

**Evidence:** [T1, T16, T20–T21](docs/spec/tunnels.md), lines 19–23, 127–135 and 160–171; [H5](docs/spec/hosts.md#address-families), lines 34–36; [E13](docs/spec/events.md#timers), lines 95–98.

T1 requires a connected socket to have a specified source still present on the host. H5 explicitly accepts an unspecified IPv4 source for a discard connection. Without an exception, the promised IPv6-only-host fallback never reaches T1's right state.

For a previously working real peer whose source disappears, T16 says to use a discard peer, while T20 says to retain binding, mark disconnected, and schedule reconnect. E13 may move a disconnected tunnel back to discard, but it only runs when there is a pending peer. The rules do not define which flags and timer own this transition or what happens when fallback itself fails.

Linux v6.12's L2TP transmit path drops frames on a userspace-managed socket that is not established, making disconnected retention a concrete possible policy, rather than something the spec must conflate with a discard connection. [Kernel source](https://github.com/torvalds/linux/blob/v6.12/net/l2tp/l2tp_core.c#L1250-L1295).

**Resolution:** Define the state tuple and transition table explicitly. Permit an unspecified source only in the intended sink state; specify the retry owner and transmitted-frame policy after every failed connect/reconnect.

**Validation:** K2 and K8.

<a id="f17"></a>

## F17 — DNS selection, stale-answer retention, and family changes are underspecified

**Severity: Medium. Type: Ambiguous peer selection and freshness.**

**Evidence:** [T14–T17](docs/spec/tunnels.md#peers), lines 106–139; [E10–E11](docs/spec/events.md#dns-events), lines 76–88; [A9](docs/spec/architecture.md#concurrency), lines 95–97.

“The first usable answer” does not say whether usable means syntactically valid, family-compatible, or successfully connectable. An answer list containing an unreachable address followed by a reachable one therefore has no deterministic selection rule. T14 also says an invalid answer keeps the current peer, without defining whether later valid answers are considered.

T15 retains an old answer for the same hostname, while T17 says an unreachable peer change moves to discard. The intended DNS exception needs to be explicit. No maximum age or intentional indefinite-retention policy is given for NXDOMAIN, repeated errors, or a resolver that hangs. T15's family-changing answer also conflicts with E10's instruction to ignore other-family answers unless it means a configuration-family change.

**Resolution:** Specify answer ordering, validity versus connectability, stale-answer policy, and the identity of a resolver generation (hostname plus requested family). Define the exception to T17 and handling of old pending results after another answer or reload arrives.

**Validation:** A controlled resolver and K8; test lists, errors, delayed responses, and rapid successive changes.

<a id="f18"></a>

## F18 — Name collisions have no temporary-name path for sessions without a configured MAC

**Severity: Medium. Type: Incomplete creation algorithm.**

**Evidence:** [S4–S7](docs/spec/sessions.md#creation), lines 27–54; [H12](docs/spec/hosts.md#other-network-managers), lines 94–99; [P6–P8](docs/spec/process.md#readiness), lines 36–51.

S4 stages only sessions with a configured hardware address; others are created directly under the configured name. S7/H12 promise that a name collision preserves the session under a temporary name. For the direct-creation branch, no such session or temporary name exists yet. Linux registers the requested netdevice as part of Ethernet session creation and unwinds the session when device registration fails. [Kernel source](https://github.com/torvalds/linux/blob/v6.12/net/l2tp/l2tp_eth.c#L223-L305).

The spec also needs to qualify S4's promise that a configured-name observer never sees the wrong MAC: S5 explicitly permits publishing a staged device before its MAC change.

**Resolution:** Specify temporary-name fallback for direct-creation name conflicts, or define them as creation failures with their own readiness policy. Distinguish identifier collision from name collision even if the kernel errno overlaps. State the manager-race exception to the MAC-before-publication guarantee.

**Validation:** K9 with MAC absent, present, and a manager activating the temporary device.

<a id="f19"></a>

## F19 — The identity and manager-state promises omit several intentional destructive transitions

**Severity: Medium. Type: Overbroad invariant.**

**Evidence:** [G3–G4](docs/spec/promises.md#unconditional-promises), lines 17–18; [M8, M11–M12](docs/spec/model.md), lines 87–89 and 106–117; [C14](docs/spec/configuration.md#semantics-of-changes), lines 114–121; [S17, S23](docs/spec/sessions.md), lines 120–124 and 173–177; [P14, P16](docs/spec/process.md), lines 89–96 and 104–112.

G3/M11 allow identity changes only for specified kernel-immutable parameters. C14 requires recreation merely for renaming a configuration key; S17 also recreates for changing tunnel_name; S23 recreates a staged session after identity loss. Shutdown and explicit removal are further obvious exceptions. M8's absolute ban on identity change while degrading does not account for these recovery paths.

G4/S2's “never undoes” manager changes similarly needs the documented exceptions for removal, recreation, and an explicitly requested MAC change. P14's restart-preservation proposal also needs its own lifecycle exception to G9.

**Resolution:** Publish one authoritative matrix of identity-preserving operations and permitted destructive operations. Include explicit removal, stop, restart policy, configuration-key identity, parent changes, external deletion recovery, and lost staging identity. Make the summary promises reference that matrix.

**Validation:** Review the matrix against every operation in C14, T22–T24, S17–S27, and P14–P18.

<a id="f20"></a>

## F20 — Continuous fidelity conflicts with accepting manager changes and permanently skipped updates

**Severity: Medium. Type: Contradictory desired-state model.**

**Evidence:** [G19](docs/spec/promises.md#conditional-promises), line 40; [M1, M7–M8](docs/spec/model.md), lines 31–36 and 66–89; [S1, S10, S12, S20](docs/spec/sessions.md), lines 7–13, 74–79, 88–98 and 150–154.

G19 requires configured names and MACs whenever the host permits them. S10 accepts an external rename indefinitely; S12 does not reassert a MAC another manager changes. Those outcomes are possible on a host that fully permits the configured values. S20 marks a skipped update applied even though the device never received it, and S19 says a lost identity cannot necessarily be recovered.

The right state therefore depends on prior accepted operations and external-manager decisions, not just the current configuration and host snapshot as the simple model suggests. M8's automatic promotion cannot apply to irrecoverably lost identity.

**Resolution:** Separate desired configuration from the fields the daemon is currently entitled to enforce. Model acknowledged external overrides, deferred changes, and permanently skipped changes explicitly. Define which later configuration change clears each condition. Specify what original kernel MAC is restored when a configured MAC is removed.

**Validation:** Traces for external rename/MAC replacement, removing the MAC key, and a skipped rename followed by another reload.

<a id="f21"></a>

## F21 — Failure of either monitor appears to invalidate identity proofs supplied by the other

**Severity: Medium. Type: Ambiguous monitor-loss scope.**

**Evidence:** [A5, A7](docs/spec/architecture.md), lines 69–70 and 83–88; [S19](docs/spec/sessions.md#identity-loss), lines 139–148; [E20](docs/spec/events.md#monitor-loss), lines 128–137.

The dedicated lifetime subscription exists to establish identity independently of the ordinary event monitor. S19 ties identity loss to that subscription losing notifications. E20 instead says that when “a subscription” fails, all earlier session identities are marked lost.

An overflow solely in the filtered event monitor can therefore either trigger only a state resync or permanently disable safe management of every existing session. These are materially different behaviors, especially during routing or link bursts.

**Resolution:** Specify loss handling separately for each subscription. Ordinary event loss should cause the required state refresh without discarding an independently intact lifetime proof. Lifetime loss must invalidate its own affected generations. Define barriers between reopening, seeding, new creations, and queued pre-loss events.

**Validation:** K10 must overflow each subscription independently, then verify whether session renames remain eligible.

<a id="f22"></a>

## F22 — One bounded event channel is not reconciled with continuous lifetime monitoring

**Severity: Medium. Type: Incomplete concurrency contract.**

**Evidence:** [A6–A7, A13–A14](docs/spec/architecture.md), lines 75–88 and 123–131; [M15](docs/spec/model.md#timing), lines 156–158; [L6](docs/spec/library.md#the-service), lines 43–47.

A6 says every producer, including the lifetime task, only sends into one channel and the reconciler owns all state. A7 requires the lifetime reader never to be starved by a busy reconciler. L6 establishes that the queue can fill. If that producer waits for room, it stops reading; if it drops messages, identity proofs require explicit invalidation. A proof lookup awaited by the reconciler also needs a response path that cannot wait behind messages only that reconciler can drain.

No queue capacity, coalescing rule, loss marker, producer shutdown behavior, or ordering scope across independent sockets is specified.

**Resolution:** Describe the lifetime task's own proof state and query/response protocol as an explicit exception to the one-writer simplification, or provide another bounded design. Define loss and generation barriers, queue pressure behavior, and shutdown wakeup independent of producer progress.

**Validation:** Saturate the event queue while issuing an identity query and shutdown. Require completion or explicit loss, never silent proof retention or deadlock.

<a id="f23"></a>

## F23 — The unconditional zero-cost event promises exclude their own fallback paths

**Severity: Medium. Type: Contradictory performance guarantee.**

**Evidence:** [R6, R35](docs/spec/requirements.md), lines 22 and 72; [G12, G23](docs/spec/promises.md), lines 26 and 44; [M16](docs/spec/model.md#scale), lines 162–168; [E2, E9](docs/spec/events.md), lines 19–25 and 65–72; [H8, H17](docs/spec/hosts.md), lines 57–62 and 133–136.

R6 permits continuing without the socket filter and acknowledges route-churn buffer pressure. G12/E9/H8 nonetheless promise that route churn never reaches userspace or overflows the monitor. Those statements cannot remain unconditional when filter attachment fails.

E2 requires reevaluating every binding on a rename, while M16/H17 claim cost proportional only to concerned entries. Resource accounting also needs to say whether G23 bounds current configuration, maximum historical configuration, retained cleanup records, or all namespace links encountered during resync.

**Resolution:** State normal and degraded performance contracts separately. Define whether an unrelated event permits an O(configuration) scan, and make the architectural algorithm match that bound. Include queues, resolver work, lifetime records, retained routes, and null devices in resource accounting.

**Validation:** Controlled filter rejection, unrelated link churn, repeated configuration growth/shrink, and resync in a namespace with many unrelated interfaces.

<a id="f24"></a>

## F24 — Retry intervals are presented as end-to-end completion deadlines

**Severity: Medium. Type: Unachievable bounds; unspecified timing semantics.**

**Evidence:** [G15, G20 and convergence bounds](docs/spec/promises.md#conditional-promises), lines 36–41 and 48–66; [A9, A14](docs/spec/architecture.md), lines 95–97 and 130–131; [M14](docs/spec/model.md#timing), lines 141–154; [H6, H16](docs/spec/hosts.md), lines 38–42 and 126–129; [P17](docs/spec/process.md#shutdown), lines 114–117.

A one-second retry cadence does not guarantee a pending peer is connected within one second. Queueing, sequential kernel operations, resolver duration, and callback execution also consume time. A resolver explicitly allowed to hang contradicts an unconditional “thirty seconds to notice, one more to apply.” P17 bounds waiting for deletion; G20 instead guarantees identifiers are free within that time. Kernel L2TP deletion uses workqueues, with no corresponding two-second completion contract. [Kernel source](https://github.com/torvalds/linux/blob/v6.12/net/l2tp/l2tp_core.c#L1713-L1734).

“Survive suspend” also does not specify whether deadlines include suspended time: Linux CLOCK_MONOTONIC excludes it and CLOCK_BOOTTIME includes it. [Kernel timekeeping documentation](https://docs.kernel.org/core-api/timekeeping.html).

**Resolution:** Separate scheduling intervals, operation timeouts, observed completion, and conditional service objectives. Define timer origins, fixed-delay versus fixed-rate behavior, suspend semantics, cancellation points, and how failed bounded waits affect readiness/shutdown.

**Validation:** Delay kernel responses and resolver callbacks; suspend/resume on a suitable VM; verify scheduling and timeout outcomes rather than assuming real-time kernel completion.

<a id="f25"></a>

## F25 — The declared valid-name grammar accepts names Linux rejects

**Severity: Medium. Type: Incomplete validation grammar; factual omission.**

**Evidence:** [C5–C8](docs/spec/configuration.md#documents), lines 30–65; [L4](docs/spec/library.md#configuration-types), lines 28–32.

C7 lists length, slash, whitespace, dot, and dot-dot restrictions, but omits colon and embedded NUL. For example, “eth:1” passes the enumerated rules but is rejected by Linux's `dev_valid_name`; an embedded NUL cannot represent the requested full C-string name. Kernel name allocation also gives percent patterns special meaning, which needs a policy if names are intended to be exact. [Kernel validation/allocation source](https://github.com/torvalds/linux/blob/v6.12/net/core/dev.c#L1058-L1180).

The remote_addr grammar also leaves “host name” undefined: single-label names, trailing dots, international names, zone-qualified IPv6 literals, and IPv4-mapped literals can be classified differently by independent implementations. This changes whether an entry is valid, pending, or silently converted to a discard peer.

**Resolution:** Define the exact byte-level name and endpoint grammars, including normalization and family classification. State which checks are kernel constraints and which are project policy. Specify MAC separator/case handling and cookie text normalization as part of the same validation table.

**Validation:** Pure configuration test vectors with explicit accepted values, diagnostics, and normalized results.

<a id="f27"></a>

## F27 — Strict conversion cannot both ignore unknown keys and fail on every reported problem

**Severity: Medium. Type: Contradictory conversion rules.**

**Evidence:** [C6, C15](docs/spec/configuration.md), lines 38–41 and 125–130; [O7–O8](docs/spec/observability.md), lines 35–47.

C6 says unknown keys MUST be ignored for forward compatibility and SHOULD be reported as document problems. C15 says strict conversion fails on the first problem of any kind, including direct deserialization. One reading accepts a future field; another rejects it because its warning is a problem. The specification does not state whether strict parsing, strict completion, and check-mode diagnostics have distinct acceptance rules.

C15 also promises each lenient problem carries an entry kind and name, although file-level parse errors and top-level unknown keys may have no such entry.

**Resolution:** Distinguish structural parsing errors, semantic entry errors, and advisory diagnostics. Specify strict-mode behavior for unknown keys explicitly, and give file/document diagnostics their own location representation. Define whether an advisory unknown-key warning alone makes --check fail.

**Validation:** The same document with an unknown top-level, tunnel, and session key through all conversion paths.

<a id="f28"></a>

## F28 — An unknown event cannot be forwarded by a wildcard arm that does nothing

**Severity: Medium. Type: Contradictory library event contract.**

**Evidence:** [L9–L10](docs/spec/library.md#the-reconciler), lines 60–72; [R39](docs/spec/requirements.md#programs-embedding-the-library), line 85; [A21](docs/spec/architecture.md#extension), lines 170–174.

L10 requires forwarding every event and forbids dropping any. Its prescribed wildcard arm for new variants does nothing, which drops exactly those events. A21 says new behaviors arrive through new event variants and handlers, so silently ignoring a required new variant can prevent convergence even while an embedding program follows the documented pattern.

Non-exhaustiveness allows source-compatible matching; it does not automatically preserve semantic correctness of a manually maintained dispatcher.

**Resolution:** Define a stable catch-all dispatch operation that handles all runtime events, or require embedding applications to update their dispatch when upgrading and weaken the blanket compatibility promise accordingly. Identify which control events belong to the embedding application rather than a runtime handler.

**Validation:** An embedding example compiled against an API version with an additional required event, with a stated observable outcome.

<a id="f29"></a>

## F29 — Library construction, drop, and filesystem boundaries do not match the claimed daemon parity

**Severity: Medium. Type: Incomplete library lifecycle and boundary contract.**

**Evidence:** [G14](docs/spec/promises.md#unconditional-promises), line 28; [P5](docs/spec/process.md#start-up), lines 30–32; [L1, L5, L8–L9](docs/spec/library.md), lines 11–15, 36–41 and 53–67; [R7, R37–R40](docs/spec/requirements.md), lines 23 and 83–86.

The daemon must retry kernel-interface opening indefinitely, while library constructors open those interfaces and the errors section promises kernel refusals as error values. It is unclear whether construction returns immediately, retries, or creates a service that cannot yet converge.

L8 says dropping the blocking service removes everything; L9 says dropping Runtime only stops tasks and closes sockets, with orderly cleanup requiring shutdown. The async Service drop contract and the necessary cleanup when blocking Service is dropped before run are unstated.

L1's absolute “reads no file” also conflicts with the declared procfs dependency and ordinary resolver operation. The intended boundary is probably no configuration-file or process-policy ownership.

**Resolution:** Specify constructor failure semantics, method call order, cancellation/drop guarantees for each public type, and ownership of retries. Narrow the file boundary to the intended abstraction without concealing dependency access.

**Validation:** Lifecycle examples for construction failure, converge without run, drop, explicit shutdown, and a blocked reload callback.

<a id="f31"></a>

## F31 — Signal reloads cannot promise one ordered reload per signal

**Severity: Medium. Type: Unimplementable request-count guarantee; shutdown ambiguity.**

**Evidence:** [P9, P12–P13](docs/spec/process.md), lines 53–56 and 74–85; [A13–A14](docs/spec/architecture.md#failure-containment), lines 123–131; [L6–L7](docs/spec/library.md#the-service), lines 43–51.

P12 says reload requests cannot be lost and are processed in order. Standard SIGHUP signals coalesce while pending, so counting every signal as a separate ordered request cannot be guaranteed. Waiting for application queue capacity only protects requests already observed by the signal reader. [Linux signal documentation](https://www.man7.org/linux/man-pages/man7/signal.7.html).

P9 intentionally ignores pre-readiness reloads. A handler waiting to enqueue a reload must also not prevent it from observing shutdown. A blocking reload callback needs a defined cancellation policy before “shutdown takes precedence” has a useful meaning.

**Resolution:** Define SIGHUP as a coalescible request to reload the latest files, with explicit pre-readiness behavior. Reserve stronger queue semantics for successfully accepted Control requests. State how shutdown bypasses signal-reader backpressure and what happens to in-flight callbacks.

**Validation:** Bursts of SIGHUP followed by SIGTERM with a full queue and with a stalled callback.

<a id="f32"></a>

## F32 — The systemd socket-family restriction can exclude the host resolver

**Severity: Medium. Type: Contradictory deployment requirements.**

**Evidence:** [P21](docs/spec/process.md#the-supplied-systemd-unit), lines 141–149; [R16](docs/spec/requirements.md#the-operator), line 40; [A5](docs/spec/architecture.md#layers), line 71.

P21 requires confinement to “netlink and IP sockets” while preserving hostname resolution. A supported host resolver can use AF_UNIX: systemd's nss-resolve communicates with systemd-resolved using a Unix socket. A literal implementation of the prescribed family allowlist breaks that resolver. [systemd nss-resolve documentation](https://www.freedesktop.org/software/systemd/man/latest/nss-resolve.html).

The precise requirements also depend on whether the binary uses a libc/NSS resolver or another resolver, so “the host's resolver” needs a defined scope.

**Resolution:** Permit the local socket families and read access required by supported resolver backends, or explicitly restrict resolver support. Publish the actual unit contract as an enumerated allowlist and distinguish ordinary operation from installer behavior.

**Validation:** A systemd-enabled container configured for nss-resolve with no working DNS fallback, on a build that uses that resolver backend.

<a id="f34"></a>

## F34 — The specification and its parent contracts disagree without a precedence rule

**Severity: Medium. Type: Competing normative authorities.**

**Evidence:** [Specification introduction](docs/spec/README.md), lines 5–14 and 51–63; [T22](docs/spec/tunnels.md#changes-applied-in-place), lines 175–179; [G22](docs/spec/promises.md#conditional-promises), line 43; [Contracts](docs/contracts.md), lines 5–9, 18–24, 35–41 and 49–58.

The contracts describe themselves as rules every change must keep and allow bind-device changes to recreate a session. T22 and G3 prohibit that recreation and classify it as an implementation defect. Contract readiness requires every entry to exist without stating the conflict exception; specification G8 expressly permits missing entries. Startup-rejection severity also differs.

G22's absolute ban on any connectivity regression from 0.1.5 needs scope: correcting unintended egress or enforcing a configured binding can deliberately stop traffic that formerly succeeded through the wrong path.

**Resolution:** State the normative precedence between docs/contracts and docs/spec, then align the overlapping rules. Define compatibility in terms of supported, intended configurations and behaviors, with explicit treatment of security/correctness corrections. Date the known-gap inventory separately from the target contract.

**Validation:** Cross-document review, rather than measuring the spec against current daemon code.

<a id="f35"></a>

## F35 — An overflowed netlink lookup is not guaranteed to fail only by timeout

**Severity: Medium. Type: Kernel-source-confirmed overstatement.**

**Evidence:** [E20–E21](docs/spec/events.md#monitor-loss), lines 128–142; [A7](docs/spec/architecture.md#concurrency), lines 83–88.

E21 states that a lookup on an overflowed subscription times out “rather than failing.” Linux can both drop the reply and report receive-buffer overflow through ENOBUFS. The exact observed result depends on queue state and socket options; timeout is one possible symptom, not the only one.

In Linux v6.12, `netlink_overrun` sets the socket error to ENOBUFS unless that reporting is disabled. The unicast enqueue path can drop a response when the receiver is congested, while broadcast overflow uses the same error reporting. [Kernel source](https://github.com/torvalds/linux/blob/v6.12/net/netlink/af_netlink.c#L350-L361), [enqueue path](https://github.com/torvalds/linux/blob/v6.12/net/netlink/af_netlink.c#L1216-L1245).

**Resolution:** Require loss handling for explicit overflow/error indications and for missing replies. Specify a finite lookup timeout and which generation of identities it invalidates. Do not infer intact notification history merely because a subsequent query succeeds.

**Validation:** K10, recording actual errno, reply sequences, loss markers, and recovery.

<a id="f26"></a>

## F26 — Merge depth, ordering, and missing-file transitions need concrete examples

**Severity: Low. Type: Ambiguous document semantics.**

**Evidence:** [C1–C5](docs/spec/configuration.md#files), lines 7–36; [C12](docs/spec/configuration.md#reload), lines 92–105.

C2 describes later “values” replacing earlier values without explicitly saying that merging recurses through both top-level maps and individual entries. Replacing the whole tunnels table is different from merging only one tunnel field. C5 suggests the latter, but an implementer should not have to infer it.

“Lexicographic” ordering does not state byte order, case sensitivity of the sort, or treatment of non-UTF-8 filenames. Only extension matching is expressly case-insensitive. C3 permits an absent main file/directory; C4 makes failed lookup an error. A previously present path becoming absent, a dangling symlink, and a file disappearing during enumeration need explicit outcomes because absence can delete running entries on reload.

**Resolution:** Add one two-file fieldwise-merge example and a precise ordering rule. State that removing an optional field requires editing/removing its earlier definition if drop-ins have no deletion syntax. Define absent versus failed lookup and the supported file-update transaction model.

**Validation:** Filesystem fixtures covering partial overrides, filename order, absent paths, dangling links, and concurrent replacement.

<a id="f30"></a>

## F30 — An ordinary reload callback error is both recoverable and an exit failure

**Severity: Low. Type: Contradictory exit-code policy.**

**Evidence:** [L7](docs/spec/library.md#the-service), lines 49–51; [P13](docs/spec/process.md#signals-and-requests), lines 80–85; [O7](docs/spec/observability.md#exit-codes), lines 35–39.

L7 keeps the old configuration after a callback error and terminates only for a panic. P13 also singles out panic. O7 says the daemon exits non-zero when “the reload callback failed,” without distinguishing an ordinary returned error from panic. It could mean immediate exit, or remembering a recoverable error until later shutdown; neither is specified elsewhere.

**Resolution:** State separately the outcomes for a callback returning an error, panicking, or not returning. Say whether a recovered reload error affects a later clean shutdown's status. Keep parent startup status separate from daemon lifetime status.

**Validation:** A callback error followed by a successful reload and clean shutdown, plus a callback panic with cleanup.

<a id="f33"></a>

## F33 — Diagnostic severity and entry identifiers are not defined for all promised cases

**Severity: Low. Type: Contradictory diagnostics.**

**Evidence:** [C10, C12](docs/spec/configuration.md), lines 75–80 and 95–101; [O2–O4](docs/spec/observability.md#logging), lines 10–24; [G13](docs/spec/promises.md#unconditional-promises), line 27.

O2 calls a configuration entry left out an error, but also calls a left-out entry a warning. C10 uses error for startup rejection and C12 warning for a new invalid reload entry. That distinction is plausible but absent from O2's categorical wording. O4 requires every entry message to include identifiers even when the problem is a missing or invalid identifier.

“Once per episode” also needs an episode key: whether a changed errno, rejected reload, new desired value, or retry after thirty seconds starts another episode affects both usefulness and log-volume guarantees.

**Resolution:** Provide one severity table keyed by startup/reload/runtime context and condition. Use configuration name/field when an identifier is unavailable. Define warning deduplication and recovery messages across reload generations.

**Validation:** Repeated identical errors, changed errors, recovery, and entries lacking identifiers; inspect output at both normal and verbose levels.

<a id="f37"></a>

## F37 — Identifier uniqueness is described as host-wide instead of namespace-scoped

**Severity: Low. Type: Incorrect uniqueness scope.**

**Evidence:** [R11, R14, R21](docs/spec/requirements.md), lines 27, 38 and 45; [C8](docs/spec/configuration.md#tunnel-entries), line 60; [T7](docs/spec/tunnels.md#creation-and-identifiers), lines 59–61; [H9](docs/spec/hosts.md#containers-and-namespaces), lines 66–72.

Several clauses say tunnel/session identifiers must be unique on the host and that the kernel refuses any second use. R11/R21 and H9 explicitly support independent network namespaces. Linux stores L2TP tunnel/session registries per network namespace, so the same identifiers can be used in separate namespaces. The important additional rule for IP encapsulation is session-ID uniqueness across tunnels within that namespace. [Kernel registration source](https://github.com/torvalds/linux/blob/v6.12/net/l2tp/l2tp_core.c#L552-L623).

**Resolution:** Replace “host” with the relevant network namespace wherever it describes identifier or interface-name uniqueness, and distinguish this from configuration-local validation. Keep peer-side identifier mirroring as a separate requirement.

**Validation:** K6 can create the same IDs in a second isolated namespace and verify that teardown of the first has no effect there.

## Proposed kernel and container experiments

These are **test designs, not test results**. Start with a small Rust socket/generic-netlink probe and controlled packet sender/receiver so that the experiment tests the kernel contract independently of this repository's daemon. Use the documented socket-backed L2TP creation path; an unmanaged tunnel created with ordinary `ip l2tp` alone does not test descriptor ownership.

Run only in disposable, isolated network namespaces on an already provisioned container test runner. The runner must provide the required L2TP/dummy/VRF support and capabilities. This audit does not require sudo or any privilege escalation on the current dev host. Containers share the host kernel: different kernel versions, IPv6 compiled out, and module-availability changes require separate prepared hosts/VMs, not merely different container images.

For every case, save the kernel version/configuration and relevant source revision, capabilities, namespace identity, routes/rules, sysctls, socket errno and endpoint observations, generic-netlink records, link indexes, and packet captures or counters. Use finite deadlines. Keep traffic within fixture namespaces/veth links, and identify injected frames by a harmless test payload. Confirm cleanup in the fixture; never change host-global routing or unload host modules as part of a container case.

| Case | Setup and action | Observations that resolve the ambiguity |
|---|---|---|
| **K1 — Socket families** | On a kernel with both L2TP families, set namespace bindv6only to 0 and then 1 before socket creation. Bind an AF_INET6 L2TP/IP socket to the unspecified address and connect to mapped IPv4. Repeat with explicit IPV6_V6ONLY=0. Separately test a prepared host lacking IPv6 L2TP support, then making it available. | Socket creation versus connect errors, selected family, whether explicit per-socket configuration restores IPv4, and whether an existing AF_INET socket can satisfy the chosen recovery policy. Distinguish sysctl disablement from missing kernel support. Addresses F12/F13. |
| **K2 — Binding and source failure** | Provide a physical-style veth and a VRF. Exercise initial bind, rebind, missing name, rename-away, delete/recreate, down state, and no address. Repeat without CAP_NET_RAW but with the other required privileges. Connect, disconnect, rebind, then inspect the socket after each step. | Actual capability-dependent failures, binding after disconnect/failure, source address, readiness-feasible states, and absence of unintended real-peer transmission. Addresses F01/F14/F16. |
| **K3 — Discard egress** | Use unresolved/invalid peers with (a) an ordinary default route, (b) no route, (c) reject routes, (d) an owned dummy host route, and (e) a socket bound to an ordinary veth or VRF. Repeat for both families and with a higher-priority policy rule. Inject Ethernet payload into the session and capture each fixture underlay. | Whether connect succeeds, selected route/source, actual outer destination and egress, and whether payload is locally discarded. This separates an address convention from a proven sink and tests whether an ordinary-device binding defeats dummy fallback. Addresses F05/F14. |
| **K4 — Session replacement and stale identity** | Create a socket-backed tunnel and session, record creation name and index, then stop/drastically constrain a dedicated link observer. Delete the session through generic netlink and recreate it with the same IDs and creation name. Repeat for a staged temporary name and, where supported, an explicitly reused index. Query the kernel record before any proposed ownership decision. | Whether the surviving object is distinguishable using only S22/S23's stated evidence. The safe decision must not rely on a name comparison claiming more information than the kernel returns. Addresses F02. |
| **K5 — Null and route replacement** | Create a dummy with a chosen MAC and an owned host route. Replace the dummy with one carrying the same name/MAC, and separately replace the route with another manager's identical or similar route. Vary table, metric, protocol and output interface. Exercise the proposed repair and cleanup decisions. | Which attributes distinguish objects, what delete/replace notifications are delivered, and which cases are inherently indistinguishable after loss. This supplies evidence for the ownership policy; it does not make matching attributes a proof by itself. Addresses F03/F06. |
| **K6 — Parent teardown and namespaces** | Hold the tunnel socket in one probe. Use a second client to attach a session to that tunnel; move an Ethernet session device into another fixture namespace where supported. Close the owning socket and observe all descendants. Create the same tunnel/session IDs in an independent namespace. | Which sessions/devices are removed by parent teardown, actual deletion completion time, and namespace isolation of IDs. Include asynchronous completion rather than assuming socket close is a synchronous deletion barrier. Addresses F04/F24/F37. |
| **K7 — Route lifecycle** | Establish a discard connection using a covering foreign route, remove that route, and leave no pending real peer. Separately remove an owned route, lower/delete the owned dummy, and replace a VRF under the same name with a different table. | Which events are emitted, whether the socket remains usable, which recovery trigger is required, and whether old-table routes remain. Check external replacements survive cleanup. Addresses F06/F15. |
| **K8 — Reconnect transitions** | With a real peer connected, remove the selected source or route, change family, restore connectivity, and apply rapid endpoint changes. Include an IPv4 discard connection with no assigned IPv4 source and a bound IPv6 link-local peer. Feed controlled DNS sequences separately. | Socket connected state, endpoint/source after each failed operation, which timer owns recovery, and frame dropping while disconnected. Resolve T16/T20/E13 by selecting an explicit state machine, not by treating every errno as the same state. Addresses F16/F17. |
| **K9 — Publication and manager races** | Occupy the configured session name with a foreign link. Attempt creation both with and without a configured MAC. On another run, have a fixture manager bring the temporary session up before MAC application and attach a child. | Direct-creation failure versus staged-session survival, error origin, readiness while unpublished, MAC update refusal/deferral, and rename behavior on the tested kernel. Preserve the foreign name holder and child throughout retries. Addresses F10/F18/F20. |
| **K10 — Independent monitor loss** | Open separate lifetime and event sockets before object creation. Constrain one receive buffer or pause one reader while generating bounded fixture link bursts. Issue ordered lookups during congestion; repeat on the other socket and with/without ENOBUFS reporting. Also saturate the application channel separately. | Explicit ENOBUFS, missing replies, timeout behavior, order/generation boundaries, continued proofs from an intact independent monitor, and shutdown responsiveness under backpressure. Addresses F21/F22/F35. |
| **K11 — Ingress boundary** | Bind a tunnel socket to one fixture VRF/device. From a second fixture ingress path, send protocol-115 data carrying the target session ID and a recognizable Ethernet payload, first without cookies, then with correct/incorrect cookies. Control outer-IP admission and firewall rules so the test distinguishes L2TP demultiplexing from prior packet filtering. Repeat IPv4 and IPv6. | Actual session delivery from each ingress path and cookie case. Compare nonzero-session-ID data dispatch with the control-packet path; do not infer data isolation from socket binding or tunnel-ID matching. Addresses F36. |

Before implementing any kernel-dependent policy change, select the supported kernel matrix and read those versions' corresponding paths. Run the smallest applicable case first, then the relevant combinations. A result on one host cannot establish a universal kernel promise.

## Specification examples needed alongside kernel experiments

The following are logic/contract tests and do not require privileged execution:

- A reload with a hard-invalid existing entry, a valid entry claiming its old identifier, and an unrelated valid edit; also a retained session whose old parent is removed (F08).
- An identical reload after a conflict disappears or a partial operation succeeds on retry (F09).
- Readiness with omitted entries, temporary publication names, and later external deletion (F10).
- Every lifecycle operation against the authoritative identity-change matrix, including configuration-key rename and lost staging identity (F19).
- Unknown keys through strict parsing, strict completion, lenient startup/reload, and --check (F27).
- Callback error, callback panic, callback hang, pre-readiness reload, and shutdown while queues are full (F22/F29–F31).
- Missing/invalid identifiers and warning deduplication across repeated retries and reloads (F33).

## Coverage and disposition

| Page reviewed | Principal findings |
|---|---|
| [README](docs/spec/README.md) | F19, F34; distinguish a target contract from its known implementation gaps |
| [Requirements](docs/spec/requirements.md) | F01, F23, F25, F29, F32, F37 |
| [Promises](docs/spec/promises.md) | F01–F10, F12, F19–F20, F23–F24, F34 |
| [Architecture](docs/spec/architecture.md) | F02, F07, F17, F21–F24, F28 |
| [Model](docs/spec/model.md) | F02–F10, F13, F19–F20, F23–F24 |
| [Process](docs/spec/process.md) | F04, F07, F10–F11, F19, F24, F29–F32 |
| [Configuration](docs/spec/configuration.md) | F05, F07–F10, F19, F25–F27, F33, F37 |
| [Tunnels](docs/spec/tunnels.md) | F01, F09, F12–F17, F19, F36–F37 |
| [Discard](docs/spec/discard.md) | F03, F05–F06, F14–F16 |
| [Sessions](docs/spec/sessions.md) | F02, F04, F07, F10, F18–F21 |
| [Events](docs/spec/events.md) | F09, F15–F17, F21–F24, F31, F35 |
| [Hosts](docs/spec/hosts.md) | F01, F05, F12, F14–F16, F18, F23–F24, F36–F37 |
| [Observability](docs/spec/observability.md) | F11, F27, F30, F33 |
| [Library](docs/spec/library.md) | F22, F25, F27–F30 |

Several investigated kernel assumptions were **not** reported as errors: the specified cookie send/receive direction matches the inspected source; disconnect clearing device binding is supported; the inspected l2tpeth MAC setter rejects changing the address while running; and renaming an up device is not categorically forbidden by the inspected v6.12/v6.6 device-rename paths. These checks avoid turning remembered behavior from another protocol or older kernel into an audit finding.

Additional clarifications worth including in the revision:

- State whether “ten retries” means ten total attempts or an initial attempt plus ten retries, and when counters reset after reload, recovery, or a changed failure.
- Define “current family” as socket family, configured peer family, or actual connected address family in every event rule.
- State supported kernel versions and host settings, including IPv6 link-local address generation: a dummy's automatic link-local address is not unconditional when address generation is disabled.
- Delineate --check's deliberate configuration output from logs. O8 can print valid cookie values to stdout; O5's redaction guarantee should explicitly cover error diagnostics and explain this output boundary.
- Clarify whether CLI/setup behavior is covered by this normative specification; the index promises process/installer responsibilities but provides no complete command-line or installation contract.
- Correct the S1 link labelled S19: it currently points at the general Identity section, not Identity loss. Prefer requirement anchors when linking individual rules.
- Define the observable outcome of missing procfs, not just that it is reported at startup.

## Recommended revision sequence

1. Resolve the safety boundaries: permitted traffic during bind failure, actual discard egress policy, ingress isolation, identity after loss, and parent teardown effects. Use F01–F06/F12/F36 and K1–K6/K11.
2. Define accepted configuration, observed state, readiness, and the complete operation/state-transition rules. Resolve F07–F10/F13–F20 before writing additional conformance tests.
3. Specify monitor generations, queue pressure, timing objectives, and supported kernel behavior. Resolve F21–F24/F35 with the targeted experiments.
4. Align configuration grammar, library lifecycle, process diagnostics, and all overlapping normative documents. Then update the known-gap inventory separately.

Unverified: the proposed runtime/container experiments, downstream kernel differences, and current daemon conformance. The report's counterexamples are textual or source-based analyses, not claims that those scenarios were executed.
