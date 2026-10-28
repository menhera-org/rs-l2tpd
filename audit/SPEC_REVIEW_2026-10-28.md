# Specification review — 2026-10-28

| Review detail | Value |
|---|---|
| Date | 2026-10-28 (Asia/Tokyo) |
| Scope | All 16 files of `docs/spec/` at commit `5182576`, read as authoritative; the implementation was not consulted |
| Question | Internal inconsistencies, wrong kernel assumptions, security problems of the design, and every implementation-choice condition the design is only safe under, which the specification must state |
| Authorities | Kernel source `Ubuntu-6.8.0-147.147` (the running kernel) and mainline after v7.3, in the trees of the second audit; experiments on the running kernel, on the host and in privileged Docker containers; the `l2tp` crate 0.4.0 changelog |
| Also decided | The six "roadmap step 3" rows of the known-gaps table, as the maintainer directed, with one recommendation (E21) |
| Deliverable | This report, and the specification changes it lists under *Changes applied* |

## Summary

The design holds. The retirement of the discard addresses rests on K5, which stands; the ownership model (sockets for tunnels, link lifetime for devices, the kernel's creation-time name for sessions) is consistent across the pages; readiness, the degradation ladder and the identity matrix agree with each other. No finding changes the shape of the design.

What this review found, by kind:

- **Wrong kernel assumptions: 1** (K29, used by E21). A reply the kernel cannot queue is *not* dropped silently: it raises `ENOBUFS` on the receiving socket exactly as an overflowed multicast does. This changes the E21 decision: the lookup timeout is a backstop, not the detector, and a short one only risks false losses, which are permanent for published sessions (W4).
- **Internal inconsistencies: 6**, all of wording or of a rule stated on one page and contradicted on another (A6 against P12; T27's "restores the configured one"; P21 against K21; the restart signal's effect on `Type=forking`; S19's replacement index; S12 against O3 after the maintainer's decision).
- **Security of the design: 2 statements to add, no defect.** A disconnected tunnel stops sending but keeps *receiving*; the specification says only the former, and an operator reading G5 would believe a tunnel without a peer is inert. And the descriptor hand-over into a binary that does not implement adoption leaves the tunnels alive in a process that does not know it holds them.
- **Implementation-choice conditions the design is safe only under: 11** (section *Conditions*), each now stated on the page it belongs to.
- **Four candidate findings were dismissed** by the kernel source and are recorded so that they are not raised again (section *Dismissed*).

Severity is by consequence if the implementer follows the text as written: **High** loses frames, identities or ownership; **Medium** makes a promise false in a case the specification claims to cover; **Low** is wording that could be read two ways.

## Method

Every page was read in full. Each rule that depends on the kernel was traced to the source of the running kernel, and where a claim could be shown in a container or on the host, it was. The experiments:

| Experiment | What it shows | Result |
|---|---|---|
| `nl_enobufs.c` (host, unprivileged): `NETLINK_ROUTE` socket, `SO_RCVBUF` at its minimum (2304), 200 `RTM_GETLINK` requests without reading | Whether a kernel unicast reply that does not fit is dropped silently (K29) | 199 replies dropped; the first `recv` fails `ENOBUFS`; the next returns a reply. Source: `af_netlink.c:1229-1231` (`netlink_attachskb`: a kernel sender with no timeout calls `netlink_overrun`), `350-358` |
| `udp_reuse.c` (host): bind `[::1]:P` without `SO_REUSEADDR`, then `[::]:P` with it | Whether K38's coexistence needs both sockets to opt in (V12) | `EADDRINUSE`; with both opting in, both bind |
| `l2tp6_v4mapped.c` (privileged container, static binary): `AF_INET6` L2TP/IP socket, bind with a connection id, connect to an IPv4-mapped peer, disconnect, reconnect; under `disable_ipv6=1` on `all`, `default` and `lo`; with an IPv6 peer; with `bindv6only=1` | H3, K23, K24/K25, K34, T21 | All as specified: the socket opens and carries IPv4 with no IPv6 address anywhere; `getsockname` shows the mapped source after connect and `::` after disconnect; an IPv6 peer fails `EADDRNOTAVAIL`; with `bindv6only=1` the socket is `IPV6_V6ONLY=1` and the mapped connect fails `ENETUNREACH` |
| iproute2 in a privileged container: dummy devices moved between namespaces; an unmanaged L2TP/IP tunnel and an `l2tpeth` session, the device moved to another namespace, renamed there, deleted there, then the session deleted in the origin | S19's replacement index, R31/S27/H10 | A moved device keeps its index when the target namespace has it free (7 stayed 7, 8 stayed 8). `ip link del` on an `l2tpeth` device is refused `EOPNOTSUPP`, in either namespace: a session device is deleted only through L2TP netlink. The moved device could be renamed in the other namespace; the session stayed listed in the origin namespace under its creation-time name; deleting the session in the origin removed the device from the other namespace |

Source facts checked for the dismissed candidates are cited in that section. No QEMU kernel-matrix run was made: no finding of this review depends on a kernel version within the verified range, and the second audit's tag sweep of `l2tp_core.c` covers the one property that does (K5).

## Findings

### W1 — K29 is wrong: a dropped kernel reply raises `ENOBUFS` (Medium, kernel fact; decides E21)

K29 says "unicast replies and acknowledgements that do not fit are dropped silently". In `netlink_attachskb` (`af_netlink.c:1229-1231`) a message that does not fit, sent by a kernel socket with no timeout (every rtnetlink reply, dump chunk and acknowledgement, which go out with `MSG_DONTWAIT`), calls `netlink_overrun`, which sets `sk_err = ENOBUFS` and the congested bit (`350-358`). Only a unicast from *another user-space process* is dropped silently, and E22 ignores those anyway. Dump replies are flow-controlled by `netlink_dump`, which waits for room rather than dropping. Reproduced on the host: 199 dropped replies, `ENOBUFS` on the next receive.

Consequence: on the lifetime subscription and on the request socket, a lost reply is *always* announced by `ENOBUFS` on the next receive. E21's lookup timeout therefore detects nothing the kernel does not already report; it covers only a kernel that never answers (a request stuck behind `rtnl`, a reply lost to a bug), and a short timeout produces false losses on a loaded host, which W4 shows are expensive and permanent for published sessions.

**Decision for E21 (recommendation, as asked):** keep the implementation's five seconds and state the detector correctly: `ENOBUFS` is the loss signal; the timeout is a backstop at five seconds; a lookup that times out ends the generation like a loss, because the socket is reopened and the gap cannot be proved empty. Applied to K29 and E21; the README row moves to the defects table as resolved by the specification.

### W2 — A disconnected tunnel still receives (Medium, security statement)

T1, G5, A19 and H1 say of a disconnected tunnel that "nothing leaves the host". True, but K15 means the other direction is unchanged: the kernel delivers every IP protocol 115 packet by session identifier, whatever socket, binding, source or device, so a tunnel with no peer, an absent bind device or an unusable endpoint keeps injecting received frames into its session interfaces, and a session without `peer_cookie` accepts them from anyone. An operator reading G5 would take "not connected" for inert. The design cannot do better (K15), and S14 already says cookies are the only admission control, but T1 and G5 must say it where the disconnected state is defined. Applied to T1, G5, S14.

### W3 — The restart signal and `Type=forking`: who decides hand-over against teardown (Medium, inconsistency)

P14 says the daemon hands its sockets to the store "on a restart or upgrade" and that "an explicit stop MUST still remove everything". With `Type=forking`, systemd sends the same `SIGTERM` for `stop` and for `restart`; the daemon cannot tell them apart, and no rule says which signal means hand-over. Two further facts the page does not state: `LISTEN_PID` on the next start names the process systemd executed, which is the parent that exits at readiness, not the grandchild that adopts (P4), so the grandchild must accept a `LISTEN_PID` equal to its original parent's and must carry the descriptors through the double fork; and systemd clears the store on `stop` but keeps it across `restart` only from systemd 254 with `FileDescriptorStorePreserve=restart` (its default), so the daemon's `FDSTOREREMOVE=1` on stop is what makes the behaviour the same on every systemd. Two resolutions are possible. (a) A signal of its own for "exit and keep the tunnels" (`SIGUSR1`), which the operator sends before `systemctl restart`; `SIGTERM` always tears down. (b) The store is used for what only it can give, survival of an *unplanned* exit: the daemon pushes every tunnel socket into the store as soon as the tunnel exists and withdraws it when the tunnel is deleted, an explicit shutdown sends `FDSTOREREMOVE=1` before tearing down, and a planned restart or upgrade is the in-process re-exec of P26, which needs no store. (b) is recommended and applied: it needs no new signal, it makes `systemctl stop` and `systemctl restart` behave as P14's first sentence already says (a restart re-creates the interfaces; an upgrade uses `SIGUSR2`), it turns a crash from "nothing survives" into "the tunnels and interfaces survive and the next instance adopts them", and it is the reading P14's last paragraph already suggests. Sessions on an adopted tunnel keep working; their device identities cannot be proved by the new instance (W4), so they are managed as after a loss of notifications until a re-creating change. One consequence of (b) must be stated with it: while the store holds a duplicate of a socket, closing the daemon's descriptor does not delete the tunnel (K37), so the two-second wait of T8 and P17 is meaningless until the store has been told to forget the socket; the withdrawal precedes the close. Applied to P4, P14, P16, P18, P21, G9.

### W4 — A loss on the lifetime subscription makes published sessions permanently unmanageable (Medium, consequence to state)

S19 and S20 say identities captured before a loss "cannot be proved again" and that renames and hardware-address changes on such a session are skipped and recorded as applied. Nothing re-proves a published session: the L2TP netlink record gives the creation-time name and no index, and a lookup by name is exactly the race S8 refuses. So one overflow of an 8 MiB buffer (a boot with thousands of link events, or a long stall of the loop) leaves every session that existed then unmanageable for the rest of the daemon's life; only a re-creating change (S17) or a restart recovers it, and the specification does not say so. The rule is right; its permanence and the operator's way out must be stated, and the daemon's one report of S20 must name them. Applied to S20.

### W5 — T27: every reconnect to a zoned link-local peer ends bound to the zone device (Low, inconsistency)

T27 says the daemon records the zone's device "as the binding in force until the next reconnect restores the configured one". The next reconnect binds the configured VRF and then connects to the zoned peer, which sets `sk_bound_dev_if` to the zone device again (`net/ipv6/datagram.c`, K27). Nothing ever restores the VRF binding while the peer is link-local. Applied: the recorded binding is the zone device for as long as the peer is a zoned link-local address; address events (E6, E7) match that device.

### W6 — A6 against P12: the signal thread does wait on the channel (Low, inconsistency)

A6: "A producer never blocks on it". P12: a reload the signal thread observed "MUST NOT be lost: the thread waits for queue capacity". Both are right for their producer; A6 states the rule for all. Applied to A6: the monitor and the resolvers never wait; the signal thread and `reload_wait` may, and the persistent shutdown flag is why that is safe.

### W7 — S12 after the maintainer's decision: an exception to O3 (Low, inconsistency)

The maintainer keeps the implementation's behaviour (the deferred hardware-address change is logged on every reconcile that carries it). That contradicts S12 ("reported once"), O3 and G13 unless stated as an exception. Applied to S12, O3, G13, and the README row is removed.

### W8 — P21 against K21: autoload needs no capability (Low, wording)

P21 asks the unit not to restrict "the capabilities the kernel needs to autoload the L2TP modules". K21 says autoload has no capability gate: `request_module` runs in the kernel's own helper. What the unit must not do is set `ProtectKernelModules=` in a way that matters to the daemon: it does not, since that only drops `CAP_SYS_MODULE`. Applied: P21 says the unit may set `ProtectKernelModules=yes`, and names what actually blocks autoload (a host policy such as `modules_disabled` or a missing module file, R1).

### W9 — S19: how a replacement can hold a removed device's index (Low, kernel fact to state)

S19 says a removed index "may now belong to a replacement". In the verified range indexes are allocated cyclically (`dev_index_reserve`, `dev.c:9786`, `xa_alloc_cyclic` over 31 bits), so a freshly created device never reuses a freed index before wrap; but a device *moved in from another namespace* keeps its old index when it is free in the target (`dev.c:11344-11350`; shown in the container). S24 is therefore needed, and the page should say which path makes it so, since a reader who knows the allocator would otherwise drop the rule. Applied to S19.

### W10 — Descriptor hand-over into a binary that cannot adopt (Medium, security of restart)

P26 clears close-on-exec on the tunnel sockets and executes the binary on disk. If that binary is an older version (a downgrade, a rollback), or any program that ignores `LISTEN_FDS`, the descriptors stay open in the process for its life: the tunnels exist, the new program creates its own and gets `EEXIST` on every identifier (left out after ten retries), and the only way out is to kill the process. P26 must require the daemon to establish, before the exec, that the target implements adoption (a probe run of the target, `--adopt-version`, reporting the protocol version it speaks), and must require every version from this one on to close every inherited descriptor it was not told about. Applied to P26.

### W11 — V12: `EADDRINUSE` on port 546 is not covered (Low, kernel fact)

V12 reasons from K38 that the resolver's wildcard socket "binds beside another DHCPv6 client". K38's sharing needs `SO_REUSEADDR` on *both* sockets (`udp_lib_lport_inuse`; shown on the host), and a system client that did not set it makes the bind fail `EADDRINUSE`, which is neither the `EACCES` of a missing capability nor a resolver without servers. Applied: `EADDRINUSE` is handled as the port-refused case of V12 (reported once, retried every thirty seconds, `ipv6` falls back to router advertisements).

## Conditions

Implementation choices the design is safe only under. Each was implicit in the text or missing; each is now stated on the page named.

| | Condition | Why the design needs it | Page |
|---|---|---|---|
| X1 | The registration broadcast is matched to the creation request by the temporary name, and the index is taken from that broadcast and nothing else | The name is unique at that instant because the kernel refuses a taken name (K20), and the broadcast is sent under `rtnl` before any rename can run (`l2tp_eth.c:288-313`, `register_netdevice`); a lookup by name afterwards races a rename | S8 |
| X2 | Temporary names come from the kernel's random source (`getrandom`), never from a counter, the time or the PID | S22's proof accepts that a foreign session with the same identifiers *and* the same creation-time name is indistinguishable; the argument that this "requires deliberate imitation" is only true if the name is unpredictable | S4 |
| X3 | The lifetime subscription and the event monitor never set `NETLINK_NO_ENOBUFS`; `ENOBUFS` is read as a loss and clears when the queue is drained | W1: it is the only loss signal; a timeout is a backstop | E21 |
| X4 | A link-local peer's zone device is resolved to an index at every reconnect and the index recorded as the binding in force | The kernel binds the socket to the zone device at connect (K27); the race between the lookup and the connect is the same as T10's and is accepted the same way | T27 |
| X5 | The source read back after a reconnect is `getsockname` on the tunnel socket, and an unspecified address there means "no source" | L2TP/IP `getsockname` reports `inet_rcv_saddr` or the connect-time `inet_saddr`; an IPv4 connect without any address succeeds with `0.0.0.0` (K34) | T28, T20 |
| X6 | A router-advertisement resolver's raw socket is bound to the interface (`SO_BINDTODEVICE`), filtered to type 134 (`ICMP6_FILTER`), reads the hop limit from ancillary data (`IPV6_RECVHOPLIMIT`) and takes the arrival interface from the link-local source's scope (as `iphost` 0.4.0 `ra.rs` does; an earlier draft of this row said `IPV6_RECVPKTINFO`) | V10's three acceptance checks cannot be made otherwise, and an unfiltered raw ICMPv6 socket receives every ICMPv6 packet of the namespace | V10 |
| X7 | The DHCPv6 socket is bound with `SO_REUSEADDR` and `SO_BINDTODEVICE` before `bind`, and `EADDRINUSE` is the port-refused case | W11 | V12 |
| X8 | An adopted descriptor is verified as: a socket of `SO_DOMAIN` `AF_INET` or `AF_INET6`, `SO_TYPE` `SOCK_DGRAM`, `SO_PROTOCOL` `IPPROTO_L2TP`; `getsockname` returns the configured tunnel identifier; `TUNNEL_GET` finds that tunnel with the configured peer identifier. The residual (the kernel cannot say the tunnel is registered on *this* socket) is accepted because the only hander is the daemon itself | P14, P26 |
| X9 | Every inherited descriptor from 3 up that `LISTEN_FDS` does not announce is closed at start; the exec of P26 is attempted only after a probe shows the target binary implements adoption | W10 | P26 |
| X10 | The grandchild accepts a `LISTEN_PID` equal to the PID of the process the init system executed (its original parent), and the descriptors survive the double fork and the close-on-exec rule of T6 | P4 with `Type=forking` | P14 |
| X11 | The exec of P26 resets the signal mask and dispositions it inherits before the new instance installs its handlers | A signal mask survives `execve`; a signal thread that blocks `SIGTERM` process-wide would leave the new instance deaf | P26 |
| X12 | A socket the store holds a duplicate of is withdrawn (`FDSTOREREMOVE=1`) before the daemon closes it to delete the tunnel | K37: a tunnel lives while any descriptor is open; the two-second wait of T8 and P17 otherwise never ends in deletion | P14, P16 |

## Dismissed

Candidates raised by reading the pages and settled against them by the kernel source, kept so they are not raised again.

| | Candidate | Why it is not a finding |
|---|---|---|
| D1 | K16's "creation-time name" could be a renamed name: `strscpy(session->ifname, dev->name)` runs after `register_netdevice` returns, and a manager could rename in between | `l2tp_eth_create` holds `rtnl` across `l2tp_session_register`, `register_netdevice` and the copy (`l2tp_eth.c:288-313`; mainline `277-302`); no rename can run in between |
| D2 | After `connect` then `connect(AF_UNSPEC)` an L2TP/IP socket is in neither hash table, so a second socket can bind the same connection id and T7's `EADDRINUSE` is unreliable | `l2tp_ip_connect` re-adds the socket to the bind table after a successful connect (`l2tp_ip.c:333-334`), and `__udp_disconnect`'s `unhash` is a no-op for it (never on `l2tp_ip_table`); the bind-table lookup keeps refusing the id. Registration's `EEXIST` (K19) is in any case the refusal the design relies on |
| D3 | K22's "a disconnect clears the binding" and K24's "only a disconnect resets the source" might not hold for L2TP/IP | `l2tp_ip_disconnect` and `l2tp_ip6_disconnect` call `__udp_disconnect` (`udp.c:2005-2020`: state `TCP_CLOSE`, `sk_bound_dev_if = 0`, `inet_reset_saddr`); shown in the container: `getsockname` is `::` after the disconnect and the mapped source after the reconnect |
| D4 | S19's "the index may now belong to a replacement" is impossible: indexes are allocated cyclically | True for fresh devices (`dev.c:9786`); false for a device moved in from another namespace, which keeps its index when free (`dev.c:11344-11350`, shown). S19 now says so (W9) |

## Roadmap step 3 decisions

| Row | Decision | Applied |
|---|---|---|
| C14, M17 (entry renamed in the configuration) | Keep the kernel objects: entries are keyed by the fields the kernel cannot change, not by configuration name. A tunnel is the same tunnel when `tunnel_id` and `peer_tunnel_id` are unchanged; a session is the same session when its tunnel is the same tunnel and `session_id`, `peer_session_id`, `cookie` and `peer_cookie` are unchanged (an absent `peer_cookie` compares as its default, `cookie`). Everything else (name, `interface_name`, `interface_hwaddr`, peer, binding, resolver) changes in place. A rename that changes one of those fields is a removal and an addition as before | C14, M17, S17, T23; README row removed |
| S12 (deferred change reported on every reconcile) | Keep the implementation's behaviour, as an exception to O3 and G13 | S12, O3, G13; README row removed |
| E21 (lookup timeout) | Five seconds, as a backstop to `ENOBUFS` (W1) | E21, K29; README row removed |
| R10 (`SO_RCVBUFFORCE` first) | The specification stands; the implementation's order is a defect | README row moved to the defects table |
| P2 (logging before the command line) | The command line is read first, since it sets the log level; messages before that go nowhere and there are none, because the command line is the first thing that can fail | P2; README row removed |
| E4 (bind device moved into a VRF) | The specification stands; wording tightened: the tunnels bound to a device are reconnected when that device's own `IFLA_MASTER` changes to or from a VRF (its L3 domain changed), and the tunnels bound to a VRF when any device's `IFLA_MASTER` changes to or from that VRF | E4; README row moved to the defects table |

## Changes applied

Every change made to `docs/spec/` by this review, by page; numbers are kept, no number is reused, and the README's known-gaps tables are updated for the rows above.

- `kernel.md`: K29 corrected (W1).
- `events.md`: E21 (W1, X3); E4 (step 3).
- `tunnels.md`: T1 (W2); T27 (W5, X4); T28 (X5); T23 (step 3).
- `promises.md`: G5 (W2); G9 (W3); G13 (W7).
- `sessions.md`: S4 (X2); S8 (X1); S12 (W7); S14 (W2); S17 (step 3); S19 (W9); S20 (W4).
- `process.md`: P2 (step 3); P4, P14, P16, P18 (W3, X8, X10, X12); P21 (W3, W8); P26 (W10, X9, X11).
- `observability.md`: O3 (W7).
- `architecture.md`: A6 (W6).
- `resolvers.md`: V10 (X6); V12 (W11, X7).
- `model.md`: M17 (step 3).
- `configuration.md`: C14 (step 3).
- `README.md`: known-gaps tables (step 3; W1).
