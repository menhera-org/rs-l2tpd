# Contracts

[Documentation index](README.md)

The rules every change to rs-l2tpd must keep. They are the decisions the
rest of the documentation describes the consequences of; a change that
breaks one is a bug even if every test passes. Each section names the tests
that guard it. The [specification](spec/README.md) spells the rules out
condition by condition.

## The two hard rules

1. **Run degraded rather than fail.** A mistake, a missing peer, a missing
   route, a missing device, a refused identifier or a lost notification
   never stops the daemon, never takes a working tunnel or session down and
   never keeps another entry from being applied. Whatever can be applied is
   applied; the rest is reported and retried.
2. **Never change an `l2tpeth` interface's identity unnecessarily.** A
   session interface is re-created only when its kernel session has to be
   (peer identifier, cookies, or its tunnel's identifiers or bind device).
   Every other change, including a mistake and its correction, keeps the
   interface, its index, its addresses and its children. A running session
   interface is never taken down; a MAC change on an up interface waits
   until it is down.

Guards: `tests/docker/degraded-start.sh`, `session-children.sh`,
`session-identity.sh`, `address-changes.sh`, the runtime reconcile tests.

## Compatibility

- The configuration format of 0.1.5 keeps working unchanged, and 0.1.5
  peers interoperate: every security feature, cookies first of all, is off
  unless configured, because L2TPv3/IP data frames are demuxed by the
  kernel on the session identifier alone and a cookie mismatch drops them.
- Readiness keeps its meaning: the parent exits, the PID file appears and
  `network-online.target` is released only once every tunnel and session
  of the applied configuration exists, discard peers included. Readiness
  never depends on DNS, on a route to a peer, on an absent bind device or
  on `network-online.target` ([early-start contract](operation.md#early-start-contract)).
- A correctness fix must not introduce a connectivity failure that 0.1.5
  did not have.

Guards: `tests/docker/network.sh` (current against 0.1.5), the
`systemd_unit_keeps_its_contract_and_is_hardened` test, the
[startup invariants](testing.md#startup-invariants).

## Configuration handling

- Start-up is lenient: unusable entries are left out, with a warning, and
  an empty result is a valid configuration. `--check` prints what would be
  applied and exits 1 on any problem.
- Only connectivity-level mistakes keep their entry: an unusable endpoint
  gives the tunnel the discard address of its family, an unusable hardware
  address gives the session the kernel's. Both are corrected in place.
- A reload never takes a running entry down: an entry with a hard mistake
  keeps the values in force, a new broken entry is left out, and only an
  unparsable file, an unlistable directory or previous values that no
  longer fit keep the whole previous configuration.
- `ip_version` is optional for a literal address and required for a host
  name. Tunnel identifiers, session identifiers and interface names are
  unique on the host; session identifiers cannot repeat across tunnels.

Guards: the `config` serde tests, the binary's configuration tests,
`degraded-start.sh`. Details in [configuration](configuration.md).

## Peers, discard addresses and routes

- A tunnel without a usable peer connects to the discard address of its
  family: `100::` for IPv6, `192.0.0.8` for IPv4. The other family's is
  used when the first cannot be connected to. Nothing else is ever used:
  blackhole, unreachable and prohibit routes refuse connections, and
  loopback routes loop frames under IPv6 forwarding.
- A route to a discard address is provided only as a last resort: after a
  ten-second grace per family, through an owned `dummy` device named
  `rsl2tpnull0` (or the next free `rsl2tpnullN`). Existing devices and
  routes are never adopted or replaced; only routes the daemon installed are
  repaired; shutdown removes only owned devices whose ownership still
  matches.
- A peer that cannot be reached is retried every second while the tunnel
  sits on a discard address. A tunnel never stays with a peer the
  configuration no longer names.
- Identifiers refused by the kernel are retried ten times, then the entry is
  left out and retried every thirty seconds and on reload.
- Do not externally delete or replace a managed tunnel; see
  [ownership of kernel tunnels](operation.md#ownership-of-kernel-tunnels).

Guards: `degraded-start.sh`, `discard-recovery.sh`, `networkd-routes.sh`,
`source-and-peers.sh`, `ipv6-disabled.sh`, the privileged discard-route
tests.

## Sockets and address families

- Each tunnel has one `AF_INET6` L2TP/IP socket bound to `::`, carrying
  IPv4 peers as IPv4-mapped addresses, so that a peer can change family in
  place. This is used whenever the kernel can open such a socket, even on a
  host without IPv6 addresses or routes.
- `AF_INET` sockets are used only when the kernel refuses an `AF_INET6`
  one, as with `ipv6.disable=1`. Everything under `AF_INET` uses the IPv4
  forms: `sockaddr_l2tpip`, the `IP_*` socket options, the `L2TP_ATTR_IP_*`
  attributes, native endpoints. Such a tunnel can have no IPv6 peer; one is
  treated as unreachable, never handed to the kernel.
- A selected source is kept by the kernel until a reconnect. Bound tunnels
  reconnect on address changes of their device or VRF; unbound tunnels
  reconnect when the address they selected is removed, and all of them on a
  monitor resync. Tunnels on a discard address are not reconnected for
  address events.

Guards: the privileged socket tests, `address-changes.sh`,
`source-and-peers.sh`, `ipv6-disabled.sh`, `monitor-resync.sh`.

## Interface identity

- Session interfaces are addressed by index, never by a possibly stale
  name; the kernel records a session's interface name only at creation.
  Configured names are resolved only when a binding is made or checked.
- A separate link-lifetime subscription proves, before every change, that
  the index still belongs to the device created. Two outcomes end that
  proof: an observed removal from the namespace (deleted, or moved by a
  container manager), after which the session is forgotten and never
  deleted through its identifiers; and a loss of notifications, after which
  the kernel's own record decides: a session still reported under its
  creation-time interface name is the daemon's and may be deleted or
  re-created.
- A name or hardware-address change for a device that can no longer be
  proved is skipped and reported once; it never fails the reload.

Guards: `session-identity.sh`, `link-monitor-burst.sh` (both modes),
`staging-loss.sh`, `tunnel-ownership.sh`, the `link_identity` tests.

## Netlink monitors

- Both monitors request 8 MiB receive buffers and never change a global
  kernel setting or need an extra capability. The event monitor attaches a
  classic BPF filter so that route notifications other than the removal of
  a discard route are dropped in the kernel.
- A reopened monitor requests a resync; the first one does not.
- Only the kernel's notifications (port 0) drive the reconciler; this is
  defence in depth, as unprivileged processes cannot unicast to another
  `NETLINK_ROUTE` or `NETLINK_GENERIC` socket anyway.

Guards: `monitor-resync.sh`, `link-monitor-burst.sh`, the netlink filter
tests.

## Library API

- The library reads no files, writes to no terminal, installs no signal
  handlers and assumes no serialisation format: serde support is an
  optional feature, and TOML, clap and env_logger belong to the binary.
- The library logs through the `log` facade; the binary hosts env_logger
  and drives reloads and shutdowns from signals through `Control`.
- Consumers must not need Tokio: `blocking::Service` runs its own runtime
  on its own thread, usable from inside another runtime.
- Types keep private fields with builders and getters; enums are
  `#[non_exhaustive]`; every foreign type in the public API is re-exported
  next to its use, so that no dependency of a matching version is needed to
  name it.
- Unsafe code is denied in the library.

Guards: the `library` doc tests, `cargo build --no-default-features` with
and without `serde`, `cargo doc -D warnings`.

## Security

- Nothing that changes the wire format or the kernel's acceptance of
  frames is on by default.
- Hosts, routes and devices the daemon does not own are never modified:
  foreign routes at the same prefix win, foreign devices under an owned
  name are left alone, foreign sessions reusing freed identifiers survive.
- The daemon needs `CAP_NET_ADMIN` and, for device binding, `CAP_NET_RAW`,
  and nothing more; panics are avoided as denial of service.
