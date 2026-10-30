# Reconnection paths: new specs-based build vs v0.1.5 (live review, 2026-10-30)

Host kernel 6.8.0-147-generic. All privileged tests ran in `docker run --rm --privileged --network none`
on `rs-l2tpd-audit-vm:local` (Alpine 3.22, iproute2 6.15, util-linux nsenter); the host network was never touched.
Binaries: **new** = HEAD 0cf9252, `cargo build --locked --release --target x86_64-unknown-linux-musl`
(`CARGO_TARGET_DIR=target-recon`); **old** = v0.1.5 from `git archive v0.1.5` with its own Cargo.lock
(`scratchpad/target-v015`). Kernel facts were checked in the Ubuntu 6.8 tree
(`/tmp/claude-1001/-home-dev-rs-l2tpd/c965bace-…/scratchpad/kernels/ubuntu-6.8`).

Scenario script: `/tmp/claude-1001/-home-dev-rs-l2tpd/a5262b72-9b33-48ea-8c09-db4f8a9a44fe/scratchpad/scenario.sh`
(POSIX sh, mounted read-only; `<new|old> <s1..s8>`), plus `ll.sh` / `ll2.sh` for the link-local probes.
Per-run evidence: `scratchpad/out/<impl>-<scenario>/{result.txt,a.log,b.log}`.

Topology: netns `a` runs daemon A (the one under test, new or 0.1.5); netns `b` runs daemon B (always the new
binary, unbound tunnels, the fixed peer). A veth joins them (`bindA` in a: 10.0.0.1/24, fd00::1/64, fe80::1;
`vB` in b: 10.0.0.2 and .3/24, fd00::2, fd00:9::2/128, fe80::2). A's tunnels: t1 (v4 peer 10.0.0.2, bound to
`bindA`), t2 (v6 peer fd00:9::2, unbound, no route at start), t3 (FQDN `peerb.test` via /etc/hosts), t4 (v4,
bound to VRF `vrfA`), t5 (`fe80::2%bindA`, bound to `vrfA`). Connectivity is proven by ping across the l2tpeth
devices plus the `tx_dropped` delta on A's device (an unconnected tunnel drops its frames, K5), and by the
daemon log lines (`created`, `connected to X from Y`, `disconnected`, `disconnected: <why>`, `… pending: <errno>`).
0.1.5 was run with its own config format (`ip_version = "V4"`; it rejects lowercase) and daemonised; its
pidfile is used for SIGHUP.

## Per-scenario results

| # | Scenario (spec) | Expected | New daemon (observed) | v0.1.5 (observed) | Verdict |
|---|---|---|---|---|---|
| S1 | Bind device absent at start; appears as `tmp0` (wrong name); renamed to `bindA` (T13, E1, E2) | created unbound and disconnected; nothing on the wrong name; bind by index + connect on the rename event | `created` then `disconnected: its bind device is absent` at once; after `tmp0` appeared with addresses: no connect (t3 unbound sibling connected, t2 pending ENETUNREACH, t4/t5 absent); after `ip link set tmp0 name bindA`: `connected to 10.0.0.2 from 10.0.0.1` within 0.2 s, ping ok, tx_dropped +0 | `creating unbound socket` and connected **unbound** (traffic would leave through any route, G5 violation); readiness delayed until a route existed (`initial configuration apply failed … Network unreachable` loop); bound to `bindA` only after the rename (`bound tunnel_id=1 socket to interface bindA`) without a reconnect | new: pass. The BPF filter/monitor delivered the AF_UNSPEC RTM_NEWLINK of the rename; the E2 race (device created under another name, renamed later) converges. |
| S2 | Bind device renamed away / deleted / re-created (T11, T12, E2, E3, H13) | disconnect at once; reconnect when a device of the name exists | rename away: `disconnected` + `its bind device is absent` immediately, ping FAIL tx_dropped +5; rename back: connected, ping ok; `ip link del`: `disconnected`, t3 (unbound, source 10.0.0.1 gone) `pending: ENETUNREACH` (E7), B's unbound tunnels pending; re-created veth (new index): t1 bound + connected, B reconnected, ping ok | rename away: only `failed to resolve bind interface index` warnings, socket stays bound to the old index and **keeps sending** (ping ok through the renamed device, T11 violation); deletion: stays "connected" on a dead index; re-creation: recovered only via IPv6 address events (`reconnected … after local address change`) | new: pass |
| S3 | Address add/remove on the bind device; other-family address; unbound peer's source removed (T19, E6, E7, H14) | one reconnect per same-family address event; none for the other family; unbound tunnel reconnects only when its own source goes | +10.0.0.11: one more `connected to … from 10.0.0.1`; +fd00:1::1: count unchanged; -10.0.0.11: one more; t3 (unbound) untouched. B: deleting its source 10.0.0.2 → `connected to 10.0.0.1 from 10.0.0.3` within <1 s; adding 10.0.0.2 back → no reconnect, A's frames land again (K15) | subscribed to RTNLGRP_LINK + **IPv6** IFADDR only: no reaction to IPv4 address events; reconnects bound tunnels on any IPv6 address event regardless of family (timestamps in old-s3/a.log: reconnects at :50 = DAD of the LL address, :56 = fd00:1::1 add) | new: pass |
| S4 | Peer unreachable at start; route appears; route removed (T16, E13, E9, H6, H8) | created disconnected, ready; connect within 1 s of the route; no route subscription | `disconnected, peer fd00:9::2 pending: ENETUNREACH`, session l2tp1 exists, `ready pid=` logged before any route; route added → `connected to fd00:9::2 from fd00::1` within 1 s, ping ok; route deleted → 0 log lines, ping FAIL (tx_dropped +3: routing drop, socket still connected); route re-added → ping ok, no daemon action | `initial configuration apply failed; will retry: Network unreachable` every second, no session device, no readiness until the route appeared (G8/G21 violation); afterwards identical kernel behaviour | new: pass |
| S5 | FQDN peer: answer changes; answer disappears (T14, T15, E10, E11, V6, G5) | reconnect to the new address within ~31 s; failed lookup keeps the tunnel connected | `peerb.test resolves to 10.0.0.3` + `connected to 10.0.0.3` 28 s after the /etc/hosts change; entry removed → `resolver returned no usable address of V4; keeping the previous answer (V6)`, still connected to .3, ping ok | FQDN tunnel connects to the discard address `100::` first; with no IPv6 default route this fails forever (`adding … remote_addr=100::` / `Network unreachable` loop, `failed to update resolver hostname immediately`): the tunnel never came up in this topology | new: pass. (First attempts "failed" because `sed -i` cannot replace Docker's bind-mounted /etc/hosts; fixed in the script.) |
| S6 | VRF bind device absent → created → member joins → `unreachable default` → member leaves → re-joins → VRF deleted → VRF re-created (T10–T13, T27, E4, H7, H13); t5 = link-local peer with zone over the VRF | bound/connected only while the VRF exists and has a source; member changes reconnect; replacement rebinds; zoned peer connected only while the zone is a member | vrfA created (no members): t4 bound, connect returned source `::` → `pending: no source address was selected` (T20/K34), ping FAIL tx_dropped +3; `bindA master vrfA`: t1 reconnected (E4 domain change), t4 `connected … from 10.0.0.1`, t5 connected via zone, ping ok on l2tp0/3/4; `unreachable default` in table 100: 0 log lines; `nomaster`: t4 `pending: EHOSTUNREACH`, t5 `disconnected: the zone of its peer is neither its bind device nor a member of it`, l2tp3/4 FAIL tx_dropped +2, l2tp0 ok; re-join: all three connected, pings ok; `ip link del vrfA`: t4/t5 `disconnected: its bind device is absent`, t1 reconnected; re-created vrfA (new index) + enslave: t4/t5 rebound and connected, pings ok | vrfA created with no members: `bound tunnel_id=31 socket to interface vrfA` **without a reconnect**: kernel record `From ::ffff:10.0.0.1`, ping ok = traffic leaving outside the VRF domain; after deletion and re-creation of vrfA it **never rebinds** (socket on the dead index, ping FAIL tx_dropped +2 to the end); zoned peers unsupported | new: pass. (Topology note: enslaving a device to a VRF cycles it down/up and addrconf drops *manual link-local* addresses even with `keep_addr_on_down=1`; the script re-adds fe80::1. Kernel: drivers/net/vrf.c `cycle_netdev`, net/ipv6/addrconf.c:3847-3851 `addr_is_local`, 3965-3966.) |
| S7 | Reload: bind_interface → absent name → back + remote_addr → family change → unchanged reload (T22, G3, G18) | all in place, l2tpeth ifindex unchanged; unchanged reload changes nothing | ifindex 4 throughout: `bindX` → `disconnected: its bind device is absent`, ping FAIL tx_dropped +4; back to bindA with 10.0.0.3 → `connected to 10.0.0.3 from 10.0.0.1`; `fd00::2`/v6 → `connected to fd00::2 from fd00::1` on the same AF_INET6 socket (T28/K24 proved: a bare connect would fail EAFNOSUPPORT); unchanged reload → only `reload completed` | bind change → `deleting tunnel_id=1` + re-create (EEXIST retries), ifindex 4→6→7 (G3 violation); family change → `Address family not supported by protocol (os error 97)` retried **every second forever** (bare connect, K24), reload never completes | new: pass |
| S8 | `net.ipv6.bindv6only=1`, `fix_bindv6only=false`: AF_INET sockets (T26, T4); address events, rename, reload | v4 tunnels on AF_INET sockets with the same reconnect semantics; v6 peer on an AF_INET socket stays disconnected, reported once | kernel record `From 10.0.0.1 to 10.0.0.2` (native IPv4), `IPv6 sockets are IPv6-only (bindv6only)` reported once; +/- IPv4 address → two reconnects; rename away/back → disconnect/reconnect; reload to fd00::2 → `disconnected: an IPv6 peer cannot be reached on its AF_INET socket` (once), ping FAIL tx_dropped +2; t2 (IPv6-only AF_INET6 socket) connects when its route appears | not run (0.1.5 always used AF_INET6 sockets; with bindv6only=1 every IPv4 peer fails ENETUNREACH, K23) | new: pass |
| LL | `ll.sh`: zoned link-local peer, unbound and VRF-bound (T27, K27) | connect binds the socket to the zone device; VRF member rule | both variants `connected to fe80::2 from fe80::…`; ping ok in both once fe80::1 is present on the member | n/a | pass |
| LL2 | `ll2.sh`: unbound tunnel, zoned peer, **first connect fails** (device down), then the zone device is **replaced** (new index) before a connect succeeds | reconnect = disconnect, bind, connect (T21); the new device must be used | `keep` control (same device brought up): connected. `replace`: `pending: EINVAL: Invalid argument` **every second, forever**, at DEBUG level only (the warning episode was opened by the earlier ENETUNREACH); kernel record `From :: to ::` | n/a | **FAIL** (finding F1) |

Every scenario was also checked for sibling independence (T21): in S1–S6 the unrelated tunnels of A kept their
state (e.g. t3 stayed connected through t1's rename/VRF events; t2 kept its one-second retry).

## Code findings

### F1 (medium-high, reconnection path): a failed connect to a zoned link-local peer leaves a kernel device binding the daemon does not know about; the next reconnect skips the disconnect and can fail EINVAL forever

- `src/reconciler/tunnels.rs:412-418` (`reconnect`): the disconnect step runs only `if record.connection.is_connected() || record.bound.is_some() || record.stale`. `src/reconciler/tunnels.rs:383-393` (`disconnect_to`) has the same shortcut. T21 says the three steps "are never shortened".
- Kernel: `net/ipv6/datagram.c:221-227` (`__ip6_datagram_connect`) writes `sk->sk_bound_dev_if = usin->sin6_scope_id` *before* the route/source lookup; on failure (255-263) it restores `sk_v6_daddr`, `flow_label` and `inet_dport` but **not** `sk_bound_dev_if`. `include/net/sock.h:3023-3035` (`sk_dev_equal_l3scope`) then refuses a scope that differs from the stale binding → EINVAL.
- Consequence (live, `out/ll2-replace`): unbound tunnel with `fe80::1%vB`; vB down at start → `ENETUNREACH` (record stays `bound: None`); vB deleted and re-created (index 4→6); E1 reconnect → connect → `EINVAL` on every one-second retry, forever, logged only at DEBUG because the "pending" episode was already open. Also, `disconnect_to` → `bind_index` on such a socket hits `sock_bindtoindex_locked` with `sk_bound_dev_if` set (`net/core/sock.c:634-636`): fine only because `CAP_NET_RAW` is held.
- The VRF-bound variant is safe by accident (`bound = Some(vrf)` after the bind step forces a disconnect next time). The same stale-binding risk exists for *any* failed connect that the kernel partially applied; unconditional disconnect is the spec's rule.
- Fix (one line each): call `self.k.disconnect(socket)` unconditionally in `reconnect`, and in `disconnect_to` whenever a bind is to be applied or the record may be bound. `__udp_disconnect` (`net/ipv4/udp.c:1998-2020`) on an already-disconnected but conn-id-bound L2TP/IP socket is harmless: it clears `sk_bound_dev_if` (2009), resets the source (2010-2011: `SOCK_BINDADDR_LOCK` is set by `l2tp_ip_bind` only for a specified address, l2tp_ip.c:277-ish) and keeps the conn id; receiving is by session id (K15).

### F2 (low, churn): a rename of a device with IPv4 addresses causes two reconnects

- The kernel emits, besides the RTM_NEWLINK, one RTM_NEWADDR per IPv4 address for the label change: `net/ipv4/devinet.c:1516-1540` (`inetdev_changename` → `rtmsg_ifa(RTM_NEWADDR, …)`, despite the comment at 1639-1641 "Do not notify about label change"). Confirmed with `ip -ts monitor link address` (one link line, one `inet 10.0.0.1/24 … bindA` address line per rename).
- `src/reconciler/events.rs:252-306` (`addr_changed`) cannot tell a label change from an addition and reconnects the bound tunnel a second time (E1 then E6). Seen in new-s1, new-s2 and new-s8 (`connected to` logged twice per rename). Harmless (microsecond gap), but it doubles the churn of E2 and makes G13's "reported once" false for this event. A cheap mitigation: ignore an RTM_NEWADDR whose address is already the connected source on that device (needs no kernel query).

### F3 (medium, not reconnect but event handling): every published session is wrongly recorded as "renamed by another manager" (S10 override)

- `src/reconciler/sessions.rs:572-583` (`session_device_changed`): compares the RTM_NEWLINK's name with `current_name`. The daemon creates the device as `rsl2tp-tXXXXXX`, then renames it to the configured name (`sessions.rs:431-435` sets `current_name`/`Applied` on the request's ack). The monitor then delivers the *creation* RTM_NEWLINK, still carrying the temporary name, after the publication → `name_state = Overridden`, log `renamed to rsl2tp-tXXXXXX by another manager; kept (S10)`. Seen for every session in every run (A and B), e.g. `out/new-s1/a.log:6,16,22`.
- Consequence: the daemon believes the operator overrode the name (G19 "acknowledged override kept until the configuration changes that field"), so a later real rename by udev/networkd is indistinguishable, and the recorded `current_name` is briefly wrong. Fix: when the name differs, confirm with one `link_by_name`/getlink by index before acknowledging, or ignore link events whose name equals `created_as` while `name_state == Applied`.

### F4 (low, spec/code mismatch): retries are per tunnel, not per bound device

- T20/E8: "one retry per bound device … unbound tunnels share one retry". `src/reconciler/tunnels.rs:479-483` (`arm_retry`) and `timers.rs:62-71` keep one `retry_at` per tunnel. Functionally a superset (each failed tunnel is retried every second; `get_or_insert` honours "an event of the other family MUST NOT postpone a queued retry"); costs one connect per pending tunnel per second. No behavioural problem observed; document or adjust the spec.

### Confirmed correct (with evidence)

- Bind by index, after disconnect, never on a bound socket (T10/K22): `tunnels.rs:408-433`; `socket.rs:70-72` uses `SO_BINDTOIFINDEX` via `l2tp::TunnelSocket::bind_to_device_index` (`/home/dev/l2tp-rs/src/socket.rs:724-738`); kernel `net/core/sock.c:627-655` (EPERM only when already bound and no CAP_NET_RAW). AF_INET sockets (bindv6only hosts) go through the same path (S8).
- Disconnect semantics (K22/K24/K25): `l2tp_ip.c:343-349` and `l2tp_ip6.c:409-415` → `__udp_disconnect` (`udp.c:1998-2020`) clears `sk_bound_dev_if` and the source (sockets are bound to the unspecified address, so `SOCK_BINDADDR_LOCK` is clear). Live: S7 family move v4→v6 on one socket succeeded (0.1.5's bare connect fails EAFNOSUPPORT, as predicted by `net/ipv6/datagram.c:206-208`/K24).
- Connect outcomes (K26/K34): ENETUNREACH (no route, S4), EHOSTUNREACH (VRF with `unreachable default`, S6 nomaster), EINVAL (scope mismatch, LL2), unspecified source treated as failure (S6, `tunnels.rs:435,451-459`).
- Monitor/BPF (K7, K10, E5): `monitor.rs:146-159` subscribes RTNLGRP_LINK + IPV4_IFADDR + IPV6_IFADDR; `bpf.rs:28-38` passes AF_UNSPEC link messages and all address messages; every link/address event used by S1–S8 arrived with the filter attached (no `event monitor runs unfiltered` warning in any log).
- Peer changes are reconnects, never bare connects (T28): `tunnels.rs:408-433` is the only connect path; `ladder.rs:50-103` re-resolves bind and zone names at every converge (T20 "a retry MUST resolve the configured bind name again").
- Resolver answers (E10/E11/V6): `workers.rs:55-60` re-queries 30 s after the previous return; `resolvers.rs:509-521` keeps the answer in force on failure (S5).
- Link-local + VRF membership rule (T27/K27): `ladder.rs:81-97`, kernel `datagram.c:221-238`, `sock.h:3023-3035`; live S6/LL.

## Question 8: what 0.1.5 reacted to vs the new monitor

0.1.5 (`runtime.rs:871-945` at v0.1.5): `new_multicast_connection(&[Link, Ipv6Ifaddr])` → RTM_NEWLINK of any family
(re-check *pending* binds by name only; a bound tunnel was never re-evaluated), RTM_NEWADDR/RTM_DELADDR from the
IPv6 group only (reconnect every tunnel whose bind name resolves to that index, any family), NLMSG_OVERRUN (re-check
pending binds), DNS watcher polls (30 s refresh), SIGHUP. It never handled RTM_DELLINK, IPv4 address events, VRF
membership, unbound tunnels' source loss, or the l2tp deletion group.

New (`monitor.rs`, `bpf.rs`, `events.rs`, `l2tp.rs`): RTM_NEWLINK/RTM_DELLINK (AF_UNSPEC), RTM_NEWADDR/RTM_DELADDR for
IPv4 and IPv6, the `l2tp` generic-netlink group (K41), ENOBUFS → resync, resolver polling, one-second retries,
SIGHUP/SIGTERM/SIGUSR2. Nothing 0.1.5 reacted to is dropped: the only narrowing is ignoring link messages of
families other than AF_UNSPEC (E5), and every device lifetime event has an AF_UNSPEC message (verified by the S1/S2
rename and re-creation handling).

## What could not be tested, and why

- Monitor overflow/resync (E20): not provoked (needs >8 MiB of notifications; `SO_RCVBUFFORCE` is also refused in this
  user-namespaced host, K36).
- Real DNS (resolver entries, RA/DHCPv6 methods): the container has `--network none`; only the system resolver via
  /etc/hosts was exercised.
- systemd-networkd/udev themselves: the rename and device-replacement races were reproduced with iproute2 in the same
  order the managers produce (create → rename, delete → re-create), not with the managers.
- 0.1.5 with zoned link-local peers and bindv6only hosts: unsupported / impossible in 0.1.5 by design.
- Other kernels (6.12/6.18/7.x): host kernel only; the kernel facts used were cited from the Ubuntu 6.8 tree.
- Scale (hundreds of tunnels) and the restart hand-over (P26) are outside this review.

## Aside (not reconnect-related)

- `--foreground` does not write the pid file (`src/bin/rs-l2tpd/main.rs:144` publishes only in `Mode::Daemon`); the
  `ready pid=` log line is the readiness signal in foreground runs.
