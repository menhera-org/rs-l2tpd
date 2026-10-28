# Dependencies

[Documentation index](README.md)

The supply chain after the rewrite, with the reason for each crate, and
what the rewrite removes. The rule: a dependency stays when it replaces
more code than it adds risk, and when its maintainer is reachable (the
first two are the maintainer's own). Today the tree has 199 crates; the
target is under 120, most of them `tokio` and the netlink packet
crates the `l2tp` crate already pulls.

## Library

| Crate | For | Spec |
|---|---|---|
| `l2tp` 0.4 | Tunnel sockets (bind, connect, disconnect, descriptors), L2TP generic netlink (create, delete by id and by name, get, list, cookies), the `l2tp` multicast events | T6, T21, K16, K41, L13 |
| `iphost` 0.4 | The system resolver and the four configured resolver kinds, retention, threads | V1–V15 |
| `netlink-sys`, `netlink-packet-core`, `netlink-packet-route` | The request socket, the event monitor and the lifetime subscription: raw sockets on `AsyncFd`, so that the kernel's buffer and `ENOBUFS` are seen (already dependencies of `l2tp`) | A5, A7, E20, E21, K29 |
| `socket2` | `SO_BINDTOIFINDEX`, `SO_ATTACH_FILTER`, `IPV6_V6ONLY` read-back, `SO_RCVBUF`, socket type and protocol queries for adopted descriptors | T10, K10, T26, R10, P14 |
| `nix` (`socket` feature only) | `SO_RCVBUFFORCE`, `sendmsg` with `SCM_RIGHTS` (the latter used by the binary) | R10, P14 |
| `tokio` (`rt`, `sync`, `time`, `net`) | The loop, the bounded channel, timers, `AsyncFd` | A6, M14 |
| `log` | The facade | O1 |
| `serde` (optional) | The `serde` feature | L1 |

## Binary (`bin` feature)

| Crate | For | Spec |
|---|---|---|
| `toml` | Parsing the documents | C1 |
| `serde` | With it | C5 |

Nothing else: the command line (nine options, P27) is parsed by hand,
the logger is thirty lines over `log::Log` (O1), daemonisation, the PID
file, signals and the store protocol are `std` and `nix` calls.

## Removed

| Crate | Why it goes |
|---|---|
| `rtnetlink`, `netlink-proto`, `futures-util`, `async-trait` | `netlink-proto`'s connection drains the socket into an unbounded queue (the A6 known gap); the handful of requests the daemon makes are shorter to write directly than to adapt |
| `clap` | 70 crates for nine options |
| `env_logger` | Its format and its environment variable contradict O1 |
| `libc` (direct) | Everything needed is in `socket2`, `nix` or `std` |
| `setup` feature | The installer is gone (plan, phase 0) |

## Upstream needs

What the specification needs of the maintainer's own crates, checked
at phase 0; a missing item stops the rewrite until it ships upstream
(`CONTRIBUTING.md`, step 5).

| Need | Crate | Status |
|---|---|---|
| `TunnelSocket::disconnect`, `from_fd`, `into_fd`, `local_addr_ip` | `l2tp` | in 0.4.0 |
| `delete_session_by_ifname`, `get_session_by_ifname` (S22, one operation) | `l2tp` | in 0.4.0 |
| `SessionInfo` reports cookies and peer identifiers (S28) | `l2tp` | in 0.4.0 |
| `L2tpHandle::events` on the `l2tp` group (K41, E27) | `l2tp` | in 0.4.0 |
| Session creation with an explicit name and no sublayer (S3) | `l2tp` | in 0.4.0 |
| A way to open the genl handle without `netlink-proto`'s unbounded queue for the event stream, or a bounded one | `l2tp` | **to check**: if the events stream buffers without bound, the K41 subscription is opened on a `netlink-sys` socket of the daemon's own instead |
| The namespace identity without `/proc` (R7) | `l2tp` | deferred; accepted by the specification |
| Configured resolvers by address with a bind device, `ra`, `dhcpv6`, `ipv6`, `retain_stale_values`, change notification, bounded lookups (V2, V4, V6) | `iphost` | 0.4.0 per the specification; **to check**: the current manifest pins 0.3.3 |
| DUID choice: link-layer from a given address, anonymous, random, exact (V12) | `iphost` | **to check** |
| Raw ICMPv6 socket with `ICMP6_FILTER`, `SO_BINDTODEVICE`, hop limit and interface from ancillary data; `RTNLGRP_ND_USEROPT` fallback (V10) | `iphost` | **to check** |
| DHCPv6 socket with `SO_REUSEADDR` and `SO_BINDTODEVICE` before `bind`, `EADDRINUSE` surfaced distinctly (V12) | `iphost` | **to check** |

## Build

Rust 1.89; `cargo build --release --locked --target x86_64-unknown-linux-musl`
for a static binary; `build-release.sh` builds the musl targets with
`cross`. Publishing uses `--registry crates-io`.
