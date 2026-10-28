# Target architecture

[Documentation index](README.md)

The shape the rewrite builds, within the structure the specification's
[architecture page](spec/architecture.md) prescribes (A1–A22). That page
says what the layers are and why; this one says which modules, types,
tasks and channels realise them, and what each specification page maps
to. Rule numbers in parentheses are the rules a piece of code exists for.

## Module map

```
src/
  lib.rs            crate root: re-exports, features, deny(unsafe_code)
  error.rs          Error, Result (L11)
  config/
    mod.rs          Config, TunnelConfig, SessionConfig, ResolverConfig, HostConfig,
                    TunnelIdentity, SessionIdentity (C7–C9, C14, C17, L4)
    partial.rs      PartialConfig, merge, strict/lenient conversions, Problem (C2, C5, C6, C10, C12, C15)
    text.rs         parsers for addresses, host names, interface names, hardware addresses, cookies (C7, C8, K32)
    serde.rs        feature "serde": Deserialize/Serialize with unknown-key collection (C6, O8)
  kernel/
    mod.rs          trait Kernel and its associated types; Family, ConnectOutcome, LinkEvent, AddrEvent, L2tpEvent
    fake.rs         the in-memory kernel for tests (K5–K41 as rules), behind cfg(any(test, feature = "fake-kernel"))
    linux/
      mod.rs        LinuxKernel: owns the request socket, the genl handle, the subscriptions
      socket.rs     tunnel sockets over l2tp::TunnelSocket + socket2 (T3–T6, T10, T21, T26, K22–K26)
      l2tp.rs       generic netlink over l2tp::L2tpHandle (K16–K20, K35, K41)
      rtnl.rs       rtnetlink requests over netlink-sys (K32, A5)
      monitor.rs    the event monitor: groups, cBPF filter, ENOBUFS (A5, K10, K29, E20–E22)
      lifetime.rs   the link-lifetime subscription and ordered lookups (A7, S8, S9, M18)
      bpf.rs        the classic BPF program (A5)
  reconciler/
    mod.rs          Reconciler: accepted config, records, reconcile(), handle(event) (M1–M6, A3)
    records.rs      TunnelRecord, SessionRecord, ResolverRecord, identity and enforced-field states (A11, M19, S19–S23)
    plan.rs         the planner: right state per entry, operation list in M6 order, identity matching (M1, M6, M17, C14)
    ladder.rs       the degradation ladder: which substitute, when to promote (M7, M8)
    tunnels.rs      tunnel operations (T1–T29, H1–H8)
    sessions.rs     session operations (S1–S29)
    resolvers.rs    resolver adapters over iphost, answers, selection (V1–V15)
    events.rs       the handlers of E1–E27
    timers.rs       the tick and the per-device, left-out and resolver timers (M14, M15)
    report.rs       episodes and messages (O2–O6)
  runtime.rs        Runtime, ControlEvent, the channel and the tasks (L9, L10, L12, L13, A6, A7, A13, A14)
  service.rs        Service, Control (L5, L6, L7)
  blocking.rs       blocking::Service (L8)
  bin/
    main.rs         entry: command line, modes (P27)
    args.rs         option parsing (P27)
    files.rs        reading and merging configuration files (C1–C4)
    check.rs        --check rendering (P3, O8)
    logger.rs       the log::Log implementation (O1)
    daemon.rs       double fork, setsid, umask, readiness pipe, --foreground (P2, P4)
    pidfile.rs      publication and removal rules (P10, P11)
    signals.rs      the signal thread and SIGPIPE (P12)
    tunable.rs      the bindv6only write (P25)
    fdstore.rs      NOTIFY_SOCKET and LISTEN_FDS (P14)
    restart.rs      the --adopt-version probe and the execve (P26)
    caps.rs         the capability report (R49)
contrib/
  rs-l2tpd.service  the supplied unit (P21)
```

Sizes aimed at: `config` 1,200 lines, `kernel` 1,800 (of which `fake`
600), `reconciler` 2,800, `runtime` plus services 700, binary 1,400.

## The kernel boundary

Everything the reconciler does to the host goes through one trait, so
that the behavioural rules can be tested without a kernel and the kernel
facts can be tested without the reconciler (plan, phase 2).

```rust
pub trait Kernel {
    // Time (M14): the real kernel reads CLOCK_MONOTONIC, the fake a counter the test advances
    fn now(&self) -> Instant;

    // Tunnel sockets (T1, T3–T6, T10, T21, T26)
    fn create_socket(&mut self, family: Family, tunnel_id: u32, peer_tunnel_id: u32) -> Result<SocketId>;
                                                                         // socket + bind of the connection id in one call, as
                                                                         // l2tp::TunnelSocket::ip_unconnected does; EAFNOSUPPORT,
                                                                         // EPROTONOSUPPORT (T4), EADDRINUSE (T7)
    fn only_v6(&self, s: SocketId) -> Result<bool>;                      // IPV6_V6ONLY read-back (K23, T26)
    fn bind_index(&mut self, s: SocketId, index: u32) -> Result<()>;     // SO_BINDTOIFINDEX (K22)
    fn connect(&mut self, s: SocketId, peer: Peer) -> Result<SourceAddr>; // the T16 outcome table (K24–K27, K34);
                                                                         // an IPv4 peer on an AF_INET6 socket is passed IPv4-mapped
    fn disconnect(&mut self, s: SocketId) -> Result<()>;                 // connect(AF_UNSPEC) (K22, K24, K25)
    fn close(&mut self, s: SocketId);                                    // deletion queued (K17)
    fn into_fd(&mut self, s: SocketId) -> OwnedFd;  fn from_fd(&mut self, fd: OwnedFd) -> Result<SocketId>; // P14, P26, K37

    // L2TP generic netlink (K16–K20, K35, K41)
    fn register_tunnel(&mut self, s: SocketId, tunnel_id: u32, peer_tunnel_id: u32) -> Result<()>; // EEXIST (K19)
    fn tunnel(&self, tunnel_id: u32) -> Result<Option<TunnelInfo>>;
    fn create_session(&mut self, c: &SessionCreate) -> Result<()>;       // name taken: refused (K20); EEXIST (K19)
    fn session(&self, tunnel_id: u32, session_id: u32) -> Result<Option<SessionInfo>>; // ifname, cookies
    fn sessions_of(&self, tunnel_id: u32) -> Result<Vec<SessionInfo>>;   // S28
    fn delete_session(&mut self, tunnel_id: u32, session_id: u32) -> Result<()>;
    fn delete_session_by_name(&mut self, ifname: &IfName) -> Result<()>; // S22, one operation (K16)

    // rtnetlink requests, on the request socket (A5)
    fn link_by_name(&self, name: &IfName) -> Result<Option<LinkInfo>>;   // index, kind, flags, master
    fn rename(&mut self, index: u32, name: &IfName) -> Result<()>;       // EEXIST when taken
    fn set_hwaddr(&mut self, index: u32, addr: HwAddr) -> Result<()>;    // EBUSY while up (K31)
    fn ether_addr(&self, index: u32) -> Result<Option<HwAddr>>;          // DUID-LL (V12)
    fn dump_links(&self) -> Result<Vec<LinkInfo>>;  fn dump_addrs(&self) -> Result<Vec<AddrInfo>>; // resync (E20)

    // Subscriptions: streams the runtime drives (A5–A7)
    fn monitor(&mut self) -> Result<Box<dyn Subscription<Item = MonitorEvent>>>;   // links + addresses, filtered
    fn lifetime(&mut self) -> Result<Box<dyn Lifetime>>;                          // links, unfiltered, ordered lookups
    fn l2tp_events(&mut self) -> Result<Box<dyn Subscription<Item = L2tpEvent>>>; // the l2tp group (K41)
}
```

`Lifetime` adds `fn lookup(&mut self, index: u32) -> Proof`, answered
after every notification queued before it (A7), and `fn generation(&self)
-> Generation` (M18). A `Subscription` yields events and, as its own
items, `Loss` (`ENOBUFS`, a timeout, a socket error: E21), so that loss is
data the reconciler handles like any event, never an error that
unwinds (A13).

The trait is object-safe and synchronous, and the reconciler that uses
it runs on **a thread of its own**, not on a Tokio task: the real
implementation makes blocking round trips (`l2tp::blocking::L2tpHandle`,
which hosts the crate's own runtime on a worker thread, and
`netlink-sys` request sockets with a five-second `SO_RCVTIMEO`, the
backstop of E21), and a blocking call on a Tokio worker would stall the
subscriptions. A request on a netlink socket is answered in microseconds
by a healthy kernel; the one slow operation, waiting for a deleted
tunnel to leave, is a timer, not a wait (A14). The Tokio runtime hosts
only what must be asynchronous: the three subscriptions on `AsyncFd`,
the timers, the resolver polling, and the control handle; they send
into the reconciler thread's channel, and the thread answers the
services over oneshots. This is the "one task" of A6 realised as one
thread.

### The fake kernel

`kernel::fake::FakeKernel` is a namespace in memory: devices with
indexes allocated cyclically (D4 of the review), names, flags, masters,
addresses and hardware addresses; tunnels keyed by identifier with their
socket, family, binding, peer, source and connected state; sessions
keyed by identifier with their creation-time name (K16) and device;
routing as a table of `(family, prefix) -> outcome` the test fills, so
that `connect` returns the T16 errno the test wants; and a notification
queue per subscription with a capacity the test sets, so that overflow
(E20) and dropped replies (E21, K29) are reproducible. Deletion of a
closed socket's sessions is applied at the next `tick` (K17, K18), so a
test can hold the identifiers for as long as it likes (T8, T25). Time
is a counter the test advances (M14, H16). The random source is a
seeded generator (S4). Every rule of the fake carries the K number it
implements, and the conformance suite ([testing](testing.md#the-conformance-suite))
proves the fake against the kernel.

## Records and identities

`records.rs` holds exactly what A11 lists. The pieces that carry the
specification's subtleties:

```rust
enum Binding { None, Index { index: u32, name: IfName }, Invalid { name: IfName } } // T10–T13
enum Connection { Disconnected { pending: Option<Peer> }, Connected { peer: Peer, source: SourceAddr } } // T1, T16–T20
enum Identity {                       // S8, S9, S19–S23, S28
    Proved { index: u32, generation: Generation, created_as: IfName },
    Staged { index: u32, generation: Generation, temp: IfName },
    Removed,                          // observed removal: forgotten, never deleted by id
    Lost { created_as: IfName },      // loss of notifications: the kernel's record decides (S22)
    Adopted,                          // S28: identifiers only
}
enum Enforced<T> { Configured(T), Deferred(T), Skipped(T), Overridden { kept: T } } // M19
```

Each tunnel record carries `conflicts: u8` and `left_out: bool` (T25);
each session `name: Enforced<IfName>` and `hwaddr: Enforced<HwAddr>`.
Records change only after the kernel confirmed an operation, and every
partial state above (a tunnel bound but not connected, a session staged
but not published) is a state the next reconcile continues from (A12).

## The planner

`plan.rs` is a pure function: `(accepted: &Config, records: &Records,
host: &HostView) -> Plan`. It never touches the kernel. It:

1. Matches entries of the configuration to records by kernel identity
   (`TunnelIdentity` = tunnel and peer identifiers; `SessionIdentity` =
   the tunnel's identity plus session and peer identifiers and both
   cookies), so that a renamed entry keeps its objects (C14, M17).
2. Derives the right state of every entry (T1, S1, V1–V2) from the
   configuration and the host view (which devices exist, their
   addresses, resolver answers in force).
3. Emits operations in M6 order: proved deletions first, children before
   parents; then renames to temporary names for swaps (S11); then
   creations (tunnels before their sessions); then final renames,
   hardware-address changes and reconnects. Operations on different
   tunnels carry no ordering edge (A8); a failed operation marks its
   entry incomplete and the plan continues (M3, M4).

`Reconciler::reconcile` runs the plan against the kernel, updates the
records from each confirmed operation, classifies each failure (M13) and
returns whether anything is incomplete, which arms the tick (E12).

## The degradation ladder

`ladder.rs` is the one place that answers "what state does this entry
get now": given the configured state and what the host allows, it
returns the rung of M7 and the substitute. Promotion is the same
function run again at an event (M8); nothing else decides substitutes,
so the matrix of M17 is enforced by construction: a rung change never
emits a re-creating operation.

## Tasks and channels

```
            ┌──────────────┐  MonitorEvent | Loss     ┌───────────────────────────┐
 kernel ───▶│ monitor task │ ───────────────────────▶ │                           │
            └──────────────┘                          │   reconciler loop (A6)    │
            ┌──────────────┐  L2tpEvent               │   owns Reconciler         │
 kernel ───▶│ l2tp task    │ ───────────────────────▶ │   reads one bounded mpsc  │
            └──────────────┘                          │   + shutdown AtomicBool   │
            ┌──────────────┐  Tick                    │                           │
            │ timers       │ ───────────────────────▶ │                           │◀── Control (reload, restart, shutdown)
            └──────────────┘                          │                           │
            ┌──────────────┐  Answer                  │                           │
            │ resolvers    │ ───────────────────────▶ │                           │
            └──────────────┘                          └──────────┬────────────────┘
            ┌──────────────┐  lookup(index) ─▶ Proof             │ Kernel trait (sync)
 kernel ───▶│ lifetime task│ ◀────────────── request-reply ──────┘
            └──────────────┘
```

- The reconciler loop is a `std::thread` that owns the `Reconciler` and
  the `Kernel` and reads the channel with `blocking_recv`; the services
  spawn it and join it at shutdown.
- The channel is a `tokio::sync::mpsc` of capacity 1,024. The monitor
  and `l2tp` tasks use `try_send`; on a full channel the monitor sets its
  resync flag and drops the event (A6, E20). Timers and resolvers keep
  state and send again next tick. `Control::reload` is `try_send`,
  `reload_wait` is `send`, and shutdown is an `AtomicBool` plus a
  `Notify` the loop checks before every event (A6, L6, P12).
- The lifetime task owns its socket and the set of live indexes per
  generation (A7). Proofs go through a `oneshot` request-reply: the
  reconciler sends `(index, reply)`, the task sends `RTM_GETLINK` on the
  lifetime socket, reads until the reply arrives (handling the
  notifications it passes on the way), and answers `Proved`, `Removed`
  or `Lost(generation)`; a two-second deadline is a loss (E21).
- The resolvers are `iphost` resolvers on their own threads (V15); the
  runtime polls their answers once a second from the tick and forwards
  changes as `Answer` events (V4, A9).
- Shutdown is one iteration away from anything (A14): every wait in the
  loop is a `select!` with the shutdown notify.

## Runtime, services, binary

`Runtime` (L9) is the loop above as a struct the program drives:
`new(kernel, adopted)` opens the subscriptions and verifies the adopted
descriptors (P14); `reconcile(config)` and `handle_event(event)` are the
two entry points; `shutdown()` applies the empty configuration in order
(P16) and withdraws stored sockets first (L13). `Service` (L5) runs the
loop on the caller's Tokio runtime with a reload callback on a blocking
thread (L7) and a restart callback (L6); `blocking::Service` (L8) hosts a
current-thread runtime on a thread of its own and implements `Drop` as a
shutdown.

The binary (A1) owns nothing kernel-related. Its modules are the list in
the map; the only state it keeps is the published PID-file inode (P10),
the stored descriptors' names (P14) and the path it was started with
(P26). It answers the runtime's three requests, `WriteTunable` (P25),
`StoreSocket` and `ForgetSocket` (P14), and otherwise forwards signals to
`Control`.

## How the pages map

| Specification page | Where it lives |
|---|---|
| [Requirements](spec/requirements.md) | `caps.rs` reports R49; the rest is what `kernel::linux` needs and `tests/kernel` proves |
| [Promises](spec/promises.md) | Property tests over the fake kernel ([testing](testing.md#properties)); G10 by the dependency list; G11 by `report.rs` and the cookie `Debug` |
| [Kernel](spec/kernel.md) | `kernel::linux` citations and `kernel::fake` rules; `tests/kernel` conformance |
| [Architecture](spec/architecture.md) | This page |
| [Model](spec/model.md) | `plan.rs`, `ladder.rs`, `records.rs`, `timers.rs` |
| [Process](spec/process.md) | `bin/` |
| [Configuration](spec/configuration.md) | `config/`, `bin/files.rs`, `bin/check.rs` |
| [Tunnels](spec/tunnels.md) | `reconciler/tunnels.rs`, `kernel/linux/socket.rs` |
| [Resolvers](spec/resolvers.md) | `reconciler/resolvers.rs` over `iphost` |
| [Sessions](spec/sessions.md) | `reconciler/sessions.rs`, `kernel/linux/lifetime.rs`, `l2tp.rs` |
| [Events](spec/events.md) | `reconciler/events.rs`, `runtime.rs`, `kernel/linux/monitor.rs` |
| [Hosts](spec/hosts.md) | No code of its own: the scenario suite ([testing](testing.md#the-scenario-suite)) |
| [Observability](spec/observability.md) | `reconciler/report.rs`, `bin/logger.rs`, `bin/check.rs` |
| [Library](spec/library.md) | `runtime.rs`, `service.rs`, `blocking.rs`, `lib.rs` |

## Decisions recorded here

- **Synchronous kernel trait, asynchronous subscriptions.** Requests are
  fast and few; making them `async` would spread the runtime into the
  reconciler and double the fake. Subscriptions must be read continuously
  (A7), so they are tasks.
- **No `netlink-proto` for the subscriptions.** Its connection drains the
  kernel socket into an unbounded queue, which is the A6 defect of the
  known gaps; `netlink-sys` on `AsyncFd` gives the kernel's own buffer and
  `ENOBUFS` back.
- **`l2tp` crate kept for sockets and generic netlink.** It already
  implements the attributes, the deletion wait and the descriptor
  conversions, and its `L2tpHandle::events` is the K41 subscription.
  Three details of its use: a tunnel is created on
  `TunnelSocket::ip_unconnected` (0.4.2, `../l2tp-rs/UNCONNECTED.md`)
  with a `TunnelConfig` whose addresses are the unspecified address of
  the family, which the kernel ignores for a descriptor-backed tunnel
  (`l2tp_core.c`, `l2tp_tunnel_create`); the device binding is set by
  index with `socket2::SockRef::bind_device_by_index_v6` on the
  socket's descriptor (or `bind_to_device_index` once 0.4.2 has it);
  an adopted IPv4 L2TP/IP socket is taken with `from_fd_with_peer`,
  because the kernel reports no peer connection id for it. IPv4 peers
  on an `AF_INET6` socket are passed to `reconnect_ip` as IPv4-mapped
  `IpEndpoint::V6`.
- **Random names from the `getrandom` crate.** S4 wants the kernel's
  random source; the library may neither read `/dev/urandom` (L1) nor
  call `getrandom(2)` through `libc` (L2), and `std` exposes no stable
  API for it. The crate is small and pure.
- **A `Clock` behind `Kernel::now`.** The reconciler never reads the
  clock itself, so the rules tests advance time deterministically.
- **`iphost` kept for every resolver, used through `IpHostResolver::resolve`.**
  The four kinds, the DUIDs, the RA and DHCPv6 sources and their threads
  are what V9–V15 describe. The reconciler's `resolvers.rs` runs one
  refresh thread per host name, takes the address list each `resolve`
  returns, selects and retains by V5–V6 itself, and parses zones itself;
  `iphost`'s own cache, `AutoIpHostResolver` and the `broadcast` and
  `tracing` features are not used.
- **The fake kernel is not a mock.** It is a model of the kernel facts,
  shared by every behavioural test, and itself tested against the
  kernel; a test never scripts kernel replies by hand.
