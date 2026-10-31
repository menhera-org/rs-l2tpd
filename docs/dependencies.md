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
| `iphost` 0.4.1 | General-purpose system/configured DNS and discovery, with the incremental RDNSS updates of V10 and the opt-in failure fallback of V14; daemon scheduling and retention stay here | V1–V15 |
| `netlink-sys`, `netlink-packet-core`, `netlink-packet-route`, `netlink-packet-generic`, `netlink-packet-l2tp` | Bounded generic-netlink requests and events, the rtnetlink request socket, event monitor and lifetime subscription: raw sockets on `AsyncFd`, so that the kernel's buffer and `ENOBUFS` are seen (already dependencies of `l2tp`) | A5, A7, E20, E21, K29 |
| `socket2` | `SO_BINDTOIFINDEX`, `SO_ATTACH_FILTER`, `IPV6_V6ONLY` read-back, `SO_RCVBUF`, socket type and protocol queries for adopted descriptors | T10, K10, T26, R10, P14 |
| `libc` (via `nix::libc` in the library) | The one `setsockopt` no safe crate exposes: `IP_MTU_DISCOVER` on an `AF_INET6` tunnel socket, under L2's bounded exception; `l2tp`'s `set_pmtu_discovery` and `set_ipv6_dontfrag` cover the other T5 options | T5, K44, L2 |
| `nix` (`socket`, `process`, `signal`, `fs`, `poll`) | `SO_RCVBUFFORCE`, process/signal/filesystem wrappers; the `bin` feature adds `uio` for `sendmsg` with `SCM_RIGHTS` | R10, P14 |
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
| `libc` | Capability, fork, descriptor-relative PID-file and exec handover operations; `unshare(CLONE_FILES)` isolates exec descriptor remapping from live threads. The library's sole exception is L2's socket-option call | R49, P4, P10, P26, L2 |

The `setup-systemd` feature ([packaging](packaging.md)) adds no crate:
the unit is embedded with `include_str!`, the copy is `std`, and
`systemctl` is run as a child process.

Nothing else: the command line (P27) is parsed by hand,
the logger is thirty lines over `log::Log` (O1), the PID file, signals,
`setsid` and the store protocol are `std` and `nix` calls.

## CI analysis

| Tool | For |
|---|---|
| `github/codeql-action` v4, pinned by commit in [the workflow](../.github/workflows/codeql.yml) | Rust and Actions security analysis; [the configuration](../.github/codeql-config.yml) retains the extended suite and excludes `rust/cleartext-logging`, which mistakes public tunnel/session identifiers for credentials |
| `actions/upload-artifact` v4, pinned by commit in [CI](../.github/workflows/ci.yml) | Retains each determinism repetition's fake-suite, kernel-package and guest logs for 14 days, including failed runs |

## Removed

| Crate | Why it goes |
|---|---|
| `rtnetlink`, `netlink-proto`, `futures-util`, `async-trait` | `netlink-proto`'s connection drains the socket into an unbounded queue (the A6 known gap); the handful of requests the daemon makes are shorter to write directly than to adapt |
| `clap` | 70 crates for nine options |
| `env_logger` | Its format and its environment variable contradict O1 |
| Legacy `setup` feature | Removed in Phase 0; Phase 5 implements the bounded installer under `setup-systemd`, without an additional dependency |

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
| Configured resolvers and finite configured lookup bounds (V2, V4, V9, V14) | `iphost` 0.4.1 | present; the daemon enables `custom`, `ra`, `dhcpv6`, not `tracing` or `broadcast`. It selects `BindDevice::Interface` after its own non-VRF validation; upstream VRF support is unaffected. `System.max_lookup_time()` is `None`. Single-source discovery is bounded at 33 s; unified `ipv6` with the fallback on reports 63 s through `max_lookup_time` (`resolver.rs:60`). 0.4.1 also gives UDP sends and partial TCP writes the query's absolute deadline |
| `ClientId::None`, `DuidLl([u8; 6])`, `RandomDuidLl`, `Raw(Vec<u8>)` with the 3–130 byte check (V12, C16) | `iphost` | present: `duid.rs` |
| RA raw socket, validation, solicitation and netlink fallback (V10) | `iphost` 0.4.1 | **published 2026-10-29 and pinned**: `State::apply` (`ra.rs:175-203`) updates addresses individually, with no merge window, a 64-address repository (`REPOSITORY_CAPACITY`) evicting omitted entries only, and withdrawn entries never returning through the stale fallback. 0.4.0 replaced the list on most advertisements; the instruction that produced the fix is [upstream-iphost.md](upstream-iphost.md) |
| DHCPv6: one wildcard socket per interface and network namespace with `IPV6_V6ONLY`, `SO_REUSEADDR` and `SO_BINDTODEVICE` before `bind`; RFC 8415 timing; transaction and client-id checks (V12) | `iphost` 0.4.2 | **published 2026-10-31 and pinned**: equally named interfaces in different namespaces get separate listeners; clients in one namespace still share. `EADDRINUSE` reaches the caller as `AddrInUse`; the daemon retries after thirty seconds. Namespace cookies avoid procfs and extra privileges on the required kernels; older kernels without that option use `/proc/thread-self/ns/net`. Dead listener cache records are removed on drop; receiver-spawn failure releases the cache lock and socket. Repository record `audit/phase6/upstream-netns-20261031/` retains baseline failures and verification |
| DHCPv6 subscriber cleanup and finite pending datagrams (G23) | `iphost` | **Open upstream:** 1,000 removed subscribers leave 1,001 records with one survivor; a stalled receiver queues all 1,024 injected datagrams. Focused failures and the follow-up are under repository path `audit/phase6/upstream-dhcp-queues-20261031/`. No daemon workaround |
| Answer selection and retention (V5, V6) | `iphost` | **done by the daemon**: `IpHostResolver::resolve` returns the lookup's addresses in the resolver's order and does not filter multicast, unspecified or mapped addresses; the daemon selects (previous while present, else first usable) and keeps the answer in force itself, so `retain_stale_values` is irrelevant to it. `Resolver::System` carries no per-family failure flags, which V6 tolerates |
| Refresh and bounded worker lifecycle (V3, V4, V15) | daemon | **Implemented:** fair scheduling, separate process-wide budgets of eight system/eight configured calls, permits retained until calls return, coalesced current jobs/results, no shutdown join on libc. Each instance dispatches in its own network namespace; unused discovery and dispatcher state is released. `AutoIpHostResolver` is not used |
| Failure-driven unified IPv6 fallback (V14) | `iphost` 0.4.1 | **published 2026-10-29 and pinned**: `Ipv6ResolverConfig::with_failure_fallback(true)` (`ipv6.rs:92`), off by default upstream; the daemon turns it on in `reconciler/resolvers.rs`. Per family, DHCPv6 servers first, RA only after DHCPv6 fails; a definitive negative answer never falls through; the bound is 63 s with both sources, 33 s otherwise |
| A zone in a literal (`fe80::1%eth0`, C7, T27) | `iphost` | `IpHost::from_str` has no zone syntax; the daemon parses the zone itself and hands `IpHost` the bare address |

## Build

Rust 1.89; `cargo build --release --locked --target x86_64-unknown-linux-musl`
for a static binary; `build-release.sh` builds the musl targets with
`cross` and enables `setup-systemd` by default. Ordinary Cargo builds
default to `bin`, without the optional installer. Publishing uses
`--registry crates-io`.

## Verification tools

| Tool | For |
|---|---|
| `cargo-llvm-cov` 0.9.1 | Phase 6 combined line/branch coverage; no daemon dependency |
| Rust `nightly-2026-10-28`, `llvm-tools-preview` | Branch instrumentation for coverage only; shipped builds remain on stable |
| Archived `rs-l2tpd` v0.1.5 and its own lockfile | G11/G22 peer interoperability only; isolated build cache, no dependency added to the current daemon |
| QEMU TCG, cpio, binutils | Disposable kernel guests, initramfs creation and stripping only; not linked into the daemon |
| curl, xz, tar | Published kernel/package metadata and source archives for the matrix |
| Docker; Debian kernel build toolchain (build-essential, flex, bison, bc, libelf/libssl headers); kmod/libkmod2 | Kernel builds and package extraction in networkless containers, module loading inside guests; recipes and package digests recorded with runs |
| Alpine apk-tools and signed v3.22 indexes | Resolve and verify the amd64 review image's existing package set; downloads use host curl, Docker resolution and installation use `--network none` |
| Incus/LXD, systemd, iproute2, BusyBox, util-linux | Disposable system-container and host-condition fixtures; no daemon dependency |
| GNU libc and libgcc from Ubuntu 24.04 | GNU coverage executables in the review image; shipped binaries remain musl |
| dnsmasq and radvd from signed Alpine indexes | Existing upstream `iphost` DNS, VRF, RA and DHCPv6 live fixtures in a disposable networkless container; no daemon dependency |
