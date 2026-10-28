# Dependencies

[Documentation index](README.md)

The supply chain after the rewrite, with the reason for each crate, and
what the rewrite removes. The rule: a dependency stays when it replaces
more code than it adds risk, and when its maintainer is reachable (the
first two are the maintainer's own). The pre-rewrite `741117b` baseline had 199 crates; the
target is under 120, most of them `tokio` and the netlink packet
crates the `l2tp` crate already pulls.

## Library

| Crate | For | Spec |
|---|---|---|
| `l2tp` 0.4 | Tunnel sockets (bind, connect, disconnect, descriptors) and shared checked types; upstream generic-netlink handles are useful to test fixtures | T6, T21, K16, K41, L13 |
| `iphost` 0.4 | The system resolver and the four configured resolver kinds, retention, threads | V1–V15 |
| `netlink-sys`, `netlink-packet-core`, `netlink-packet-route`; add direct `netlink-packet-generic` and `netlink-packet-l2tp` imports when Phase 2 uses them | Bounded generic-netlink requests and events, the rtnetlink request socket, event monitor and lifetime subscription: raw sockets on `AsyncFd`, so that the kernel's buffer and `ENOBUFS` are seen (already dependencies of `l2tp`) | A5, A7, E20, E21, K29 |
| `socket2` | `SO_BINDTOIFINDEX`, `SO_ATTACH_FILTER`, `IPV6_V6ONLY` read-back, `SO_RCVBUF`, socket type and protocol queries for adopted descriptors | T10, K10, T26, R10, P14 |
| `nix` (`socket`, `process`, `signal`, `fs`) | `SO_RCVBUFFORCE`, process/signal/filesystem wrappers; Phase 5 must also enable `uio` when using `sendmsg` with `SCM_RIGHTS` | R10, P14 |
| `tokio` (`rt`, `sync`, `time`, `net`) | The loop, the bounded channel, timers, `AsyncFd` | A6, M14 |
| `log` | The facade | O1 |
| `getrandom` | Temporary interface names from the kernel's random source, without file I/O or unsafe code | S4, L1, L2 |
| `serde` (optional) | The `serde` feature | L1 |

`netlink-packet-route` is pinned to the release that depends on
`netlink-packet-core` 0.9, the version `l2tp` uses (0.33 in the local
registry), so that one copy of the core crate is built.

## Binary (`bin` feature)

| Crate | For | Spec |
|---|---|---|
| `toml` | Parsing the documents | C1 |
| `serde` | With it | C5 |
| `libc` | `capget(2)` for the capability report and `fork(2)` for daemonisation, the two calls `std` and `nix` do not wrap safely; the binary allows `unsafe` for them, the library denies it | R49, P4, L2 |

The `setup-systemd` feature ([packaging](packaging.md)) adds no crate:
the unit is embedded with `include_str!`, the copy is `std`, and
`systemctl` is run as a child process.

Nothing else: the command line (P27) is parsed by hand,
the logger is thirty lines over `log::Log` (O1), the PID file, signals,
`setsid` and the store protocol are `std` and `nix` calls.

## Removed

| Crate | Why it goes |
|---|---|
| `rtnetlink`, `netlink-proto`, `futures-util`, `async-trait` | `netlink-proto`'s connection drains the socket into an unbounded queue (the A6 known gap); the handful of requests the daemon makes are shorter to write directly than to adapt |
| `clap` | 70 crates for nine options |
| `env_logger` | Its format and its environment variable contradict O1 |
| `libc` (library) | Everything the library needs is in `socket2`, `nix`, `getrandom` or `std`; the binary keeps it for `capget` and `fork` |
| `setup` feature | The installer is gone (plan, phase 0) |

## Upstream needs

What the specification needs of the maintainer's own crates, checked
at phase 0; a missing item stops the rewrite until it ships upstream
(`CONTRIBUTING.md`, step 5).

| Need | Crate | Status |
|---|---|---|
| `TunnelSocket::disconnect`, `from_fd`, `into_fd`, `local_addr_ip` | `l2tp` | in 0.4.0 |
| `delete_session_by_ifname`, `get_session_by_ifname` (S22, name-only primitive; not an atomic identity check) | `l2tp` | in 0.4.0 |
| `SessionInfo` reports cookies and peer identifiers (S28) | `l2tp` | in 0.4.0 |
| `L2tpHandle::events` on the `l2tp` group (K41, E27) | `l2tp` | in 0.4.0; the bounded form `events_bounded` in 0.4.3 (below) |
| Session creation with an explicit name and no sublayer (S3) | `l2tp` | in 0.4.0 |
| **A bound, unconnected L2TP/IP socket** (T1, T6, K5): `TunnelSocket::ip` of 0.4.1 binds and connects in one constructor, and the daemon's library may not build `sockaddr_l2tpip6` itself (L2) | `l2tp` 0.4.2 | **published 2026-10-28 and pinned**: `TunnelSocket::ip_unconnected(local, device, tunnel_id, peer_tunnel_id)`, its UDP counterpart `udp_unconnected` for symmetry, `bind_to_device_index` (`SO_BINDTOIFINDEX`), and `TunnelConfig::for_socket` describing a peerless socket with the unspecified remote; the additional boundary requirements below remain |
| Handle ownership (T8, M6, P14, P26) | `l2tp` 0.4.2 | present, with rules the daemon must follow: `TunnelHandle` and `SessionHandle` default to `auto_delete = true` and issue a netlink delete *by identifier* on drop (`tunnel.rs:232-247`, `session.rs:305-321`), which T8 forbids; fixtures and any adapter using those handles call `set_auto_delete(false)` immediately; the chosen raw adapter owns `TunnelSocket` directly. Dropping a `TunnelHandle` still closes the socket, which is the T8 deletion; the daemon then polls `get_tunnel` for `ENODEV` for up to two seconds itself. The descriptor for the store and exec comes from `TunnelSocket::try_clone_fd()` (or `TunnelHandle::socket()` first in a handle-based adapter), a duplicate on which the binary clears close-on-exec |
| Bounded K41 event path and loss recovery (G23, E20) | `l2tp` 0.4.3 | **published 2026-10-28 and pinned**: `L2tpHandle::events_bounded` returns `BoundedEvents` (a `Stream` on `AsyncFd`; `blocking::L2tpHandle::events_bounded` returns `BoundedEventIter`) that reads straight from the kernel socket with no queue in between. Memory is bounded by the socket's receive buffer, which the daemon sizes through `AsFd` (`SO_RCVBUF`, R10); an overflow is reported as an `Error::Io` with `ENOBUFS` ahead of the notifications still queued, and the stream continues. The daemon reads it on the Tokio side and forwards with `try_send` plus its persistent loss flag (E20); the raw `netlink-sys` event socket planned before 0.4.3 is not needed. `events` (unbounded) stays for fixtures only |
| Kernel sender validation (E22) | `l2tp` 0.4.3 | **fixed in 0.4.3**: `Events` and `BoundedEvents` check recvmsg's sender address and skip any message whose port is not 0, before decoding. The patch kept in `audit/upstream/` was the 0.4.2 reproduction and is superseded |
| Finite generic-netlink requests | `l2tp` / daemon boundary | Existing blocking calls have no deadline contract. The selected Phase 2 raw adapter supplies the deadline, including family resolution and uncertain mutation recovery. Do not change existing default timeout semantics or accumulate abandoned workers |
| No `/proc` requirement (R7, K12) | `l2tp` 0.4.1 | **shipped 2026-10-28** and pinned: namespace identity comes from `SO_NETNS_COOKIE` (`net/core/sock.c:1981-1986` in 6.8, since 5.14), a descriptor is kept only when `/proc` is readable, and `NetNs::current` falls back to `PIDFD_GET_NET_NAMESPACE` on 6.11+. The daemon never calls `setns` and creates every socket on its own threads, so the descriptor is never needed. R7 and K12 are removed from the specification; the instruction that produced the release is `../l2tp-rs/NO_PROC.md` |
| Configured resolvers: `Resolver::Static` with `BindDevice::Interface` only (the daemon never selects `Vrf`), `Resolver::Ra`, `Resolver::Dhcpv6`, `Resolver::Ipv6` (DHCPv6 first); `max_lookup_time` of 5 s × 2 attempts per server, 3 s discovery wait, at most 3 discovered servers (V2, V4, V9, V14) | `iphost` 0.4.0 (`../iphost`, read 2026-10-28) | present: `resolver.rs`, `custom.rs:14-22`, `ipv6.rs:121-127`. Features to enable: `custom`, `ra`, `dhcpv6`; `tracing` and `broadcast` off. The manifest already uses 0.4.0; all configured resolver kinds require a runtime-validated non-VRF link (V9) |
| `ClientId::None`, `DuidLl([u8; 6])`, `RandomDuidLl`, `Raw(Vec<u8>)` with the 3–130 byte check (V12, C16) | `iphost` | present: `duid.rs` |
| Raw ICMPv6 socket: `ICMP6_FILTER` to type 134, `IPV6_RECVHOPLIMIT`, `SO_BINDTODEVICE` re-tied when the interface is re-created, arrival interface checked against the link-local source's scope, solicitations 3 × 4 s, `RTNLGRP_ND_USEROPT` fallback on `EPERM`, lifetimes with expired servers kept while none is live (V10) | `iphost` | present: `ra.rs:299-408`, `172-208`. The arrival check uses the source scope, not `IPV6_RECVPKTINFO`; the specification's V10 says so now |
| DHCPv6: one wildcard socket per interface with `IPV6_V6ONLY`, `SO_REUSEADDR` and `SO_BINDTODEVICE` before `bind`; RFC 8415 retransmission and refresh timing; transaction and client-id checks (V12) | `iphost` | present: `dhcpv6.rs:225-236`, `338-399`. `EADDRINUSE` reaches the daemon as `io::ErrorKind::AddrInUse` from `Dhcpv6ResolverConfig::new`; the daemon's retry every thirty seconds is a new config |
| Answer selection and retention (V5, V6) | `iphost` | **done by the daemon**: `IpHostResolver::resolve` returns the lookup's addresses in the resolver's order and does not filter multicast, unspecified or mapped addresses; the daemon selects (previous while present, else first usable) and keeps the answer in force itself, so `retain_stale_values` is irrelevant to it. `Resolver::System` carries no per-family failure flags, which V6 tolerates |
| Refresh thirty seconds after the previous lookup returned (V4) | `iphost` | the daemon runs the refresh thread itself (one per host name, `resolve()` then a thirty-second wait) instead of `AutoIpHostResolver`, so that it owns the list, not only the picked address |
| A zone in a literal (`fe80::1%eth0`, C7, T27) | `iphost` | `IpHost::from_str` has no zone syntax; the daemon parses the zone itself and hands `IpHost` the bare address |

## Build

Rust 1.89; `cargo build --release --locked --target x86_64-unknown-linux-musl`
for a static binary; `build-release.sh` builds the musl targets with
`cross`. Publishing uses `--registry crates-io`.
