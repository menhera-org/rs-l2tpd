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
| `l2tp` 0.5 | Tunnel sockets, shared checked types and `KernelMessage` decoding; production requests/events use the daemon's raw adapter | T6, T21, K16, K41, L13 |
| `iphost` 0.4 | General-purpose system/configured DNS and discovery; protocol fixes and additive fallback are pending upstream, while daemon scheduling/retention stay here | V1–V15 |
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

What the specification needs of the maintainer's crates. These are
general-purpose libraries: a downstream requirement is not automatically
an upstream bug. Fix discrepancies against their own documented contracts,
and request compatible additions for new policy. A missing required API
stops the dependent implementation until it ships upstream
(`CONTRIBUTING.md`, step 5); unrelated work may continue.
The [iphost instruction](upstream-iphost.md) records the distinction,
regressions, compatibility requirements and integration gate.

| Need | Crate | Status |
|---|---|---|
| `TunnelSocket::disconnect`, `from_fd`, `into_fd`, `local_addr_ip` | `l2tp` | in 0.4.0 |
| `delete_session_by_ifname`, `get_session_by_ifname` (S22, name-only primitive; not an atomic identity check) | `l2tp` | in 0.4.0 |
| `SessionInfo` reports cookies and peer identifiers (S28) | `l2tp` | in 0.4.0 |
| `L2tpHandle::events` on the `l2tp` group (K41, E27) | `l2tp` | in 0.4.0; the bounded form `events_bounded` in 0.4.3 (below) |
| Session creation with an explicit name and no sublayer (S3) | `l2tp` | in 0.4.0 |
| **A bound, unconnected L2TP/IP socket** (T1, T6, K5): `TunnelSocket::ip` of 0.4.1 binds and connects in one constructor, and the daemon's library may not build `sockaddr_l2tpip6` itself (L2) | `l2tp` 0.4.2 | **published 2026-10-28 and pinned**: `TunnelSocket::ip_unconnected(local, device, tunnel_id, peer_tunnel_id)`, its UDP counterpart `udp_unconnected` for symmetry, `bind_to_device_index` (`SO_BINDTOIFINDEX`), and `TunnelConfig::for_socket` describing a peerless socket with the unspecified remote; the additional boundary requirements below remain |
| Handle ownership (T8, M6, P14, P26) | `l2tp` 0.4.2 | present, with rules the daemon must follow: `TunnelHandle` and `SessionHandle` default to `auto_delete = true` and issue a netlink delete *by identifier* on drop (`tunnel.rs:232-247`, `session.rs:305-321`), which T8 forbids; fixtures and any adapter using those handles call `set_auto_delete(false)` immediately; the chosen raw adapter owns `TunnelSocket` directly. Dropping a `TunnelHandle` still closes the socket, which is the T8 deletion; the daemon then polls `get_tunnel` for `ENODEV` for up to two seconds itself. The descriptor for the store and exec comes from `TunnelSocket::try_clone_fd()` (or `TunnelHandle::socket()` first in a handle-based adapter), a duplicate on which the binary clears close-on-exec |
| Bounded K41 event path and loss recovery (G23, E20) | daemon / `l2tp` 0.5.0 | **Selected path:** raw `netlink-sys` subscription sharing the rtnetlink `Feed`, with finite kernel buffers, sender validation and persistent loss state. Upstream `events_bounded` and runtime-free `EventSocket` are available alternatives, not the production adapter. Unbounded `events` remains fixture-only |
| Kernel sender validation (E22) | `l2tp` 0.4.3 | **fixed in 0.4.3**: `Events` and `BoundedEvents` check recvmsg's sender address and skip any message whose port is not 0, before decoding. The patch kept in `audit/upstream/` was the 0.4.2 reproduction and is superseded |
| The tunnel and peer tunnel identifiers of an adopted `TunnelSocket` (P14, S28) | `l2tp` 0.5.0 | **published 2026-10-29 and pinned**: `TunnelSocket::tunnel_id` (what `from_fd` read with `getsockname`) and `peer_tunnel_id`; the `Debug`-parsing shortcut is gone |
| Foreign cookies of every length the kernel accepts (K35) in `SessionInfo`, none produced | `l2tp` 0.5.0 | **published 2026-10-29 and pinned**: the public `KernelMessage` parses a reply with a cookie of any length up to 8, where `netlink-packet-l2tp` 0.4.0 refuses the length (`attribute.rs:760-770`; its fix waits on other PRs), and `KernelCookie` holds it. The daemon's request adapter decodes with `KernelMessage`; its kernel `SessionInfo` holds `ReportedCookie` (a `KernelCookie` whose `Debug` gives the length only, O5), and `SessionInfo::cookies` converts to configuration cookies, failing for a length C8 forbids, so such a session matches no entry and on an adopted tunnel is deleted by identifier (S28). Nothing the daemon creates carries a length other than 4 or 8 |
| Subscriptions created on one thread and polled on another runtime | `l2tp` 0.5.0 | `EventSocket::new(family_id, group_id)` needs no handle and no runtime, and `try_next` has the bounds of `BoundedEvents`. Phase 2 still reads the `l2tp` group on its raw `netlink-sys` socket, which shares the `Feed` of the rtnetlink subscriptions (sender port 0, `ENOBUFS` as a loss, the kernel's buffer only); switching to `EventSocket` would save only the deletion decoder of `l2tp.rs`, so it is not planned |
| Finite generic-netlink requests | `l2tp` 0.5.0 / daemon | 0.5.0 handles take a `HandleConfig` with a request timeout (30 s by default), but they still need a Tokio runtime and report a timed-out mutation as `TimedOut` without the recovery the daemon needs; the daemon's raw adapter keeps its five-second deadline, family resolution and uncertain-mutation handling (A14) |
| No `/proc` requirement (R7, K12) | `l2tp` 0.4.1 | **shipped 2026-10-28** and pinned: namespace identity comes from `SO_NETNS_COOKIE` (`net/core/sock.c:1981-1986` in 6.8, since 5.14), a descriptor is kept only when `/proc` is readable, and `NetNs::current` falls back to `PIDFD_GET_NET_NAMESPACE` on 6.11+. The daemon never calls `setns` and creates every socket on its own threads, so the descriptor is never needed. R7 and K12 are removed from the specification; the instruction that produced the release is `../l2tp-rs/NO_PROC.md` |
| Configured resolvers and finite configured lookup bounds (V2, V4, V9, V14) | `iphost` 0.4.0 | Base APIs exist; the daemon enables `custom`, `ra`, `dhcpv6`, not `tracing` or `broadcast`. It selects `BindDevice::Interface` after its own non-VRF validation; upstream VRF support is unaffected. `System.max_lookup_time()` is `None`. Single-source discovery is bounded at 33 s; the requested opt-in dual-source fallback needs up to 63 s. V10/V14 corrections below remain open |
| `ClientId::None`, `DuidLl([u8; 6])`, `RandomDuidLl`, `Raw(Vec<u8>)` with the 3–130 byte check (V12, C16) | `iphost` | present: `duid.rs` |
| RA raw socket, validation, solicitation and netlink fallback (V10) | `iphost` 0.4.0 | Socket mechanisms exist. **Protocol correction pending:** `State::apply` clears omitted live servers and groups netlink updates by a time window. Require bounded incremental per-address updates with explicit withdrawal; preserve the documented stale-server fallback. See [upstream instruction](upstream-iphost.md#1-correct-rdnss-repository-updates) |
| DHCPv6: one wildcard socket per interface with `IPV6_V6ONLY`, `SO_REUSEADDR` and `SO_BINDTODEVICE` before `bind`; RFC 8415 retransmission and refresh timing; transaction and client-id checks (V12) | `iphost` | present: `dhcpv6.rs:225-236`, `338-399`. `EADDRINUSE` reaches the daemon as `io::ErrorKind::AddrInUse` from `Dhcpv6ResolverConfig::new`; the daemon's retry every thirty seconds is a new config |
| Answer selection and retention (V5, V6) | `iphost` | **done by the daemon**: `IpHostResolver::resolve` returns the lookup's addresses in the resolver's order and does not filter multicast, unspecified or mapped addresses; the daemon selects (previous while present, else first usable) and keeps the answer in force itself, so `retain_stale_values` is irrelevant to it. `Resolver::System` carries no per-family failure flags, which V6 tolerates |
| Refresh and bounded worker lifecycle (V3, V4, V15) | daemon | **Pending implementation:** fair scheduling, separate process-wide budgets of eight system/eight configured calls, permits retained until calls return, coalesced current jobs/results, no shutdown join on libc. A per-host refresh thread alone does not bound obsolete calls across reloads; `AutoIpHostResolver` is not used |
| Failure-driven unified IPv6 fallback (V14) | `iphost`, additive API requested | **Not provided by pinned 0.4.0:** its preferred nonempty DHCPv6 list masks RA on query failure. Request optional per-family fallback with negative-answer finality and truthful bounds; keep the general-purpose selection-only default unless upstream's current public contract requires otherwise. [Instruction and tests](upstream-iphost.md#2-add-optional-per-family-failure-fallback) |
| A zone in a literal (`fe80::1%eth0`, C7, T27) | `iphost` | `IpHost::from_str` has no zone syntax; the daemon parses the zone itself and hands `IpHost` the bare address |

## Build

Rust 1.89; `cargo build --release --locked --target x86_64-unknown-linux-musl`
for a static binary; `build-release.sh` builds the musl targets with
`cross`. Publishing uses `--registry crates-io`.
