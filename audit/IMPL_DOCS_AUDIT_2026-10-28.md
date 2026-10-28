# Implementation-docs audit — 2026-10-28

| Detail | Value |
|---|---|
| Scope | `docs/README.md`, `plan.md`, `architecture.md`, `interface.md`, `dependencies.md`, `testing.md` at commit `ddb01bc`, read against the specification and against the sources of `../l2tp-rs` 0.4.1, `socket2` 0.6.5, `nix` 0.30.1 and the local registry |
| Question | What would stop an implementer, and what is missing that the implementation needs |
| Outcome | 2 blocking issues (one needs an upstream release), 7 missing items; all written into the pages, the upstream one into `../l2tp-rs/UNCONNECTED.md` |

## Blocking

### B1 — `l2tp` cannot make a bound, unconnected tunnel socket (upstream)

The design creates every tunnel disconnected (T1, T6) and connects
later. `TunnelSocket::ip` binds and connects in one constructor
(`socket.rs:269-323`); nothing binds only. Building the socket in the
daemon would need `sockaddr_l2tpip6`, which is unsafe code the library
denies (L2). Everything after creation already works on an unconnected
socket: `from_fd` tolerates a missing peer (`peer_conn_id_in6` returns
0), `disconnect` and `reconnect_ip` are the T21 steps, and the kernel
ignores the address attributes of a descriptor-backed `TUNNEL_CREATE`
(`l2tp_core.c:1423`, `l2tp_tunnel_create` takes `sockfd_lookup` when
`fd >= 0`), so placeholder addresses in `TunnelConfig` are fine.

Resolution: `TunnelSocket::ip_unconnected` and `bind_to_device_index`
in `l2tp` 0.4.2, from an instruction written for it. Implemented the
same day in `../l2tp-rs` (commit `9877db4`), together with
`udp_unconnected` for symmetry, which the maintainer added so that both
socket kinds of that crate offer the same lifecycle; the instruction
file was consumed. Phases 0 and 1 do not need it; phase 2 starts when
0.4.2 is published. Recorded in `dependencies.md` and `plan.md`.

### B2 — a synchronous `Kernel` trait on an asynchronous crate

`architecture.md` made the trait synchronous and said its calls run "on
the reconciler task". `L2tpHandle` is `async` and needs a Tokio I/O
driver; a blocking call from a Tokio task stalls a worker, and
`block_on` inside a runtime panics. Resolution, now in the page: the
reconciler runs on a thread of its own, owns the `Kernel`, and uses
`l2tp::blocking::L2tpHandle` (its own worker thread and runtime) and
`netlink-sys` request sockets with a five-second `SO_RCVTIMEO`; the
Tokio runtime hosts only the subscriptions, timers, resolver polling
and the control handle. A6's "one task" is that thread.

## Missing

| | Item | Where added |
|---|---|---|
| M1 | A random source for temporary names: the library may not read `/dev/urandom` (L1) nor call `getrandom(2)` through `libc` (L2), and `std` has no stable API. Decision: the `getrandom` crate | `dependencies.md`, `architecture.md` |
| M2 | The binary needs `unsafe` for `fork(2)` (`nix::unistd::fork` is an unsafe fn) and `capget(2)` (no wrapper in `nix`); `libc` stays a binary dependency. The library keeps `deny(unsafe_code)` | `dependencies.md` |
| M3 | The rule-map regex missed table rows (`\| R1 \|`), which is how R, G, K, C7–C17 and M17 rows are numbered | `testing.md` |
| M4 | A clock behind the trait (`Kernel::now`) so the rules tests can advance time; the page spoke of a virtual clock without saying how the reconciler reads it | `architecture.md` |
| M5 | The trait sketch had a separate `socket` and `bind_conn_id`; the crate binds the connection id in the constructor. Merged into `create_socket(family, tunnel_id, peer_tunnel_id)` | `architecture.md` |
| M6 | How the `l2tp` crate is driven in detail: placeholder addresses for descriptor-backed creation, `bind_device_by_index_v6` through `socket2` until 0.4.2, `from_fd_with_peer` for adopted IPv4 L2TP/IP sockets (the kernel reports no peer id for them), IPv4 peers passed as IPv4-mapped `IpEndpoint::V6` (the crate rejects a family mismatch) | `architecture.md` |
| M7 | `netlink-packet-route` must be the release built on `netlink-packet-core` 0.9, the one `l2tp` uses (0.33 locally), or two core crates are built | `dependencies.md` |

## Verified, no change needed

- `socket2` 0.6.5 has `attach_filter`, `bind_device_by_index_v6`,
  `only_v6`, `set_recv_buffer_size`, `domain`, `type`, `protocol`
  (`sys/unix.rs:1712-2600`, `socket.rs:338-2065`); `nix` 0.30.1 has
  `sockopt::RcvBufForce` and `ControlMessage::ScmRights`.
- `l2tp` 0.4.1: `from_fd` reads family, type, protocol, bound device,
  connection id and (IPv6) peer id back from the kernel, which is the
  P14 verification (X8) minus the `TUNNEL_GET` check the daemon adds.
- The `blocking::L2tpHandle` worker, the reconciler thread, the Tokio
  workers and the resolver threads are all bounded in number (G23).
- Interface, testing layout, phases and exit criteria need no change
  beyond the two notes above.

## Resumed after `l2tp` 0.4.2 was published

0.4.2 is pinned and the tree builds. The remaining pass looked at the
handle types the daemon will hold, since those are where a crate's
defaults can contradict a specification silently. Findings, all written
into `architecture.md` and `dependencies.md`:

| | Finding | Rule |
|---|---|---|
| A1 | `TunnelHandle` and `SessionHandle` default to `auto_delete = true` and, on drop, spawn a netlink deletion **by identifier** onto the current runtime. T8 forbids deleting a tunnel by identifier (a foreign replacement could be removed), and M6 orders session deletions explicitly. The daemon sets `set_auto_delete(false)` on every handle at once; dropping the tunnel handle still closes the socket, which is the T8 deletion, and the daemon polls `get_tunnel` for `ENODEV` for the two-second wait instead of `delete_tunnel`, which deletes by identifier | T8, M6 |
| A2 | The descriptor for the store and for the re-exec is a duplicate from `TunnelHandle::socket().try_clone_fd()`; the binary clears close-on-exec on the duplicate only, and the original closes with the exec as T6 wants. No upstream change needed | P14, P26, T6 |
| A3 | `create_session` opens an `RTNLGRP_LINK` socket of its own per creation to capture the device index and falls back to a lookup by name when its notifications were lost. The daemon ignores `SessionHandle::ifindex` and takes the index from its generation-tracked lifetime subscription, as S8 requires; the extra socket is short-lived and harmless | S8 |
| A4 | The K41 stream from the blocking handle is a blocking `EventIter`; it is read on a thread that forwards with `try_send` and marks a resync when the channel is full, the same contract as the event monitor | A6, E27 |
| A5 | Requests through the blocking handle have no timeout. Accepted: generic netlink replies are synchronous, and E21's five-second timeout belongs to the lifetime socket, which the daemon owns | E21 |

Nothing else was found. The phases can start.

## Not audited

The specification itself (reviewed on 2026-10-28 in
`SPEC_REVIEW_2026-10-28.md`), and `tests/docker/README.md`, which phase
6 replaces.
