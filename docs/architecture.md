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
    fake.rs         the in-memory kernel for tests (K5–K42 as rules), behind cfg(any(test, feature = "fake-kernel"))
    linux/
      mod.rs        LinuxKernel: owns the request socket, the genl handle, the subscriptions
      socket.rs     tunnel sockets over l2tp::TunnelSocket + socket2 (T3–T6, T10, T21, T26, K22–K26)
      l2tp.rs       bounded raw generic-netlink requests and K41 events over netlink-sys; l2tp::KernelMessage reply decoding (K16–K20, K35, K41)
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
  bin/rs-l2tpd/     (one directory, so that Cargo sees one binary, not one per module)
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
  rs-l2tpd.service.in  unit template rendered per installation path (P21)
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
    fn create_session(&mut self, c: &SessionCreate) -> Result<Registration>;       // name taken: refused (K20); EEXIST (K19)
    fn session(&self, tunnel_id: u32, session_id: u32) -> Result<Option<SessionInfo>>; // ifname, cookies
    fn scan_sessions(&self, tunnel_id: Option<u32>, visit: &mut dyn FnMut(&SessionInfo)) -> Result<()>; // S4, S22, S28; streamed complete dump
    fn delete_session(&mut self, tunnel_id: u32, session_id: u32) -> Result<()>;
    fn delete_session_by_name(&mut self, ifname: &IfName) -> Result<()>; // raw name-only primitive; S22 requires prior uniqueness/identity checks

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

A `Registration` contains the index, lifetime generation and a unique
registration incarnation captured from the registration broadcast (S8).
Before sending a create request, arm capture for the reserved temporary
name on the continuously read lifetime subscription; completion correlates
the broadcast with the acknowledged session creation. If capture or the
reply is lost, return an uncertain creation outcome and reconcile the
stored record; never guess an index by current name.

`Lifetime::lookup(registration)` verifies that exact incarnation after
draining notifications preceding its ordered lookup reply (A7). A removed
index reappearing in the same generation never revives the old proof.
Retain proofs only for armed captures and tracked dependencies, not every
foreign index. Session dumps stream into bounded checks/reservations;
never collect all foreign sessions into a namespace-sized `Vec`. A failed
or interrupted dump cannot establish uniqueness or absence.
A `Subscription` exposes loss separately from its bounded event queue,
so a full queue cannot drop the loss marker (E20). Loss is handled as
state, never an error that unwinds the reconciler (A13).

The trait is object-safe and synchronous, and the reconciler that uses
it runs on **a thread of its own**, not on a Tokio task: the real
implementation makes bounded round trips. Both rtnetlink and generic
netlink must have a five-second total request deadline, including family
resolution, multipart responses and acknowledgements. A receive timeout
alone is insufficient if unrelated traffic keeps arriving. The existing
`l2tp::blocking::L2tpHandle` has no such contract and cannot be used
unchanged for these requests. Phase 2 uses the daemon's bounded raw-netlink adapter, reusing the
`netlink-packet-generic` and `netlink-packet-l2tp` codecs already in the
lockfile. This keeps upstream's existing default contracts unchanged.
It must not abandon one blocked worker per timeout.

After a timed-out mutation, the outcome is unknown: retain socket
ownership and name reservations, reopen the failed request transport, and
query local state before retrying or releasing identifiers. Never assume
timeout means no mutation occurred or delete a replacement by ID.
Waiting for a deleted tunnel to leave is a timer, not a nested wait (A14). The Tokio runtime hosts
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
// Track configured bind and effective zone devices separately, including membership (T27).
struct Binding { configured: Option<DeviceDependency>, zone: Option<DeviceDependency>, effective: Option<Registration> }
enum Connection { Disconnected { pending: Option<Peer> }, Connected { peer: Peer, source: SourceAddr } } // T1, T16–T20
enum Identity {                       // S8, S9, S19–S23, S28
    Proved { registration: Registration, created_as: IfName },
    Staged { registration: Registration, temp: IfName },
    Removed,                          // observed removal: forgotten, never deleted by id
    Lost { created_as: IfName },      // loss of notifications: the kernel's record decides (S22)
    Adopted,                          // S28: identifiers only
}
enum Enforced<T> { Configured(T), Deferred(T), Skipped(T), Overridden { kept: T } } // M19
```

Each tunnel record carries `conflicts: u8` and `left_out: bool` (T25);
each session `name: Enforced<IfName>` and `hwaddr: Enforced<HwAddr>`.
Applied state changes only after kernel confirmation. Record in-flight
intent before sending a mutation and retain it as uncertain on timeout;
that uncertainty must survive to the next local verification rather than
being recorded as either success or no change. Every partial state above
(a tunnel bound but not connected, a session staged but not published) is a state the next reconcile continues from (A12).

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
   tunnels carry an edge when they share a namespace-wide session ID or
   device name (A8). A release-before-claim edge remains pending until
   asynchronous deletion is confirmed, not merely requested. Unrelated
   entries proceed after a failure (M3, M4).

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
  `Kernel`. A small current-thread Tokio runtime on that thread uses
  `block_on` only for the idle `select!` between `rx.recv()` and the
  shutdown notification. Kernel operations run outside that wait.
  Subscriptions stay on the service runtime and continue reading during
  those operations. Services spawn and join the reconciler thread.
- The channel is a `tokio::sync::mpsc` of capacity 1,024. Monitor and
  L2TP tasks use `try_send`; each has a persistent atomic loss flag
  outside the queue. They wake the loop when setting it. The loop
  consumes flags before waiting and after every operation; a loss during
  a resync remains pending. Timers and resolvers retain latest state.
  `Control::reload` is `try_send`, `reload_wait` is `send`.
- Shutdown sets an `AtomicBool` before `Notify::notify_one`. The loop
  creates its notified future before checking the flag, then selects
  it alongside receive. The stored notification permit covers the
  check/wait race. Check shutdown before dequeuing more work.
  Signal collection coalesces reload/restart in separate pending flags
  and wakes a forwarding task; it never blocks on channel capacity.
- The lifetime task owns its socket and registration incarnations, not
  merely a set of live indexes. Capture is armed before session creation.
  Proof requests carry a complete `Registration` and answer
  `Proved`, `Removed` or `Lost(generation)` after ordered lookups.
  The deadline is five seconds (E21), independent of the two-second
  tunnel-deletion retry window.
- Resolver jobs and results carry their configuration incarnation (V7);
  V15's permits outlive cancellation of interest. Validate bind and zone
  devices before queries/discovery and after replacement or monitor loss
  (V9, V11). New configurations replace queued work, not running workers.
- `WriteTunable` carries a request incarnation and deadline; affected
  creations wait unregistered for at most five seconds (L12). Success
  retries socket creation once with read-back. Late replies cannot replace
  registered sockets. Shutdown and unrelated operations continue.
- Adopted descriptors retain their original store names. Uncertain
  verification keeps the descriptor; rejection creates a retirement record
  before any local close. `ForgetSocket` carries that exact name and a
  request incarnation; withdrawal, close and absence verification follow
  L13. Serialize removal and replacement storage under a reused name.
- Shutdown wakes an idle loop immediately; an in-flight synchronous
  request may consume its remaining five-second deadline (A14).

## Runtime, services, binary

`Runtime` (L9) is the loop above as a struct the program drives:
`new(kernel, adopted)` opens the subscriptions and retains the adopted
descriptors with their store names for verification or retirement (P14); `reconcile(config)` and `handle_event(event)` are the
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
- **`l2tp` 0.5 for socket operations, reply decoding and shared types.**
  The daemon uses its raw `netlink-sys` adapter for generic-netlink
  requests and the K41 subscription. Upstream handles now offer timeouts,
  but require a runtime and do not implement the daemon's uncertain-mutation
  recovery. The request socket has one request in flight, an absolute
  five-second deadline and sequence/sender validation; it reopens after
  failure. Replies decode through `l2tp::KernelMessage` to accept foreign
  cookie lengths. Events use the same bounded `Feed` as rtnetlink:
  kernel receive buffers, port-0 validation before decoding, and persistent
  loss state on `ENOBUFS` or forwarding overflow. Upstream
  `events_bounded` and runtime-free `EventSocket` are available
  alternatives, not the selected production path.
  Three details of its use: a tunnel is created on
  `TunnelSocket::ip_unconnected` (0.4.2) with the `TunnelConfig` that
  `TunnelConfig::for_socket` derives from it (the unspecified remote,
  which the kernel ignores for a descriptor-backed tunnel,
  `l2tp_core.c`, `l2tp_tunnel_create`); the device binding is set by
  index with `TunnelSocket::bind_to_device_index` (0.4.2);
  an adopted IPv4 L2TP/IP socket is taken with `from_fd_with_peer`,
  because the kernel reports no peer connection id for it. IPv4 peers
  on an `AF_INET6` socket are passed to `reconnect_ip` as IPv4-mapped
  `IpEndpoint::V6`. The daemon owns the socket directly; deletion closes
  it and schedules the two-second T8 verification window. If an upstream
  `TunnelHandle` or `SessionHandle` is used in a fixture or alternative
  adapter, call `set_auto_delete(false)` immediately: its default drop
  deletes by identifier, which is not the daemon's ownership policy.
  Session devices' indexes come from the daemon's lifetime subscription
  (S8), not from `SessionHandle::ifindex`, whose own monitor is opened
  per creation and falls back to a lookup by name. The raw K41 path is
  bounded from the socket reader onward; unbounded `events`/`EventIter`
  remains fixture-only. A bounded forwarding queue behind an unbounded
  upstream queue would not meet G23. All request paths obey the total
  deadline and uncertain-mutation rules above.
- **Random names from the `getrandom` crate.** S4 wants the kernel's
  random source; the library may neither read `/dev/urandom` (L1) nor
  call `getrandom(2)` through `libc` (L2), and `std` exposes no stable
  API for it. The crate is small and pure.
- **A `Clock` behind `Kernel::now`.** The reconciler never reads the
  clock itself, so the rules tests advance time deterministically.
- **`iphost` kept for every resolver, used through `IpHostResolver::resolve`.**
  It is a general-purpose library: protocol corrections go upstream;
  daemon policy stays here. Required fixes and additive capabilities are
  specified in [the upstream instruction](upstream-iphost.md).
  The daemon schedules refreshes itself and admits calls through V15's
  separate process-wide budgets of eight system and eight configured
  lookups. A permit stays with a running call until return, including
  across reload and service drop. Pending work/results coalesce by current
  key; old generations cannot allocate replacement workers or accumulate
  results. Configured jobs use finite V4 deadlines; libc remains unbounded.
  Keep each worker in its originating namespace; a shared budget does not
  authorize sharing a socket or worker across network namespaces.
  The daemon selects and retains answers by V5–V7, parses zones, validates
  non-VRF dependencies and releases unused discovery configurations.
  It enables upstream failure fallback for unified IPv6 explicitly;
  `iphost`'s own cache, `AutoIpHostResolver`, `broadcast` and `tracing`
  are not used.
- **The fake kernel is not a mock.** It is a model of the kernel facts,
  shared by every behavioural test, and itself tested against the
  kernel; a test never scripts kernel replies by hand.
