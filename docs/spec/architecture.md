# Architecture

[Specification index](README.md)

The structure the [promises](promises.md) need. It prescribes components,
their responsibilities and the interfaces between them, not their code.

## Layers

```
 operator ──signals, files──▶ ┌──────────────────────────────────────┐
                              │ binary: process, files, PID file,    │
                              │ logging sink, signals, host tunables,│
                              │ descriptor hand-over                 │
                              └──────────────┬───────────────────────┘
                                             │ Config, Control
                              ┌──────────────▼───────────────────────┐
 embedding program ─────────▶ │ services: Service, blocking::Service │
                              │ (converge, run, reload, shutdown)    │
                              └──────────────┬───────────────────────┘
                                             │ reconcile, handle_event
                              ┌──────────────▼───────────────────────┐
                              │ reconciler: plan and apply, event    │
                              │ handlers, timers, accepted config    │
                              └──────────────┬───────────────────────┘
                                             │ operations on records
                              ┌──────────────▼───────────────────────┐
                              │ state: tunnel sockets, session       │
                              │ identities, resolver answers         │
                              └───┬──────────┬──────────┬────────────┘
                                  │          │          │
                         L2TP/IP sockets  L2TP genl  rtnetlink ◀── link-lifetime
                                                               ◀── event monitor (filtered)
                                  resolvers ────────────────────▶ reconciler (answers)
                                                       kernel
```

A1. The **binary** owns everything that is a process concern: command
line, configuration files and their merging, the logging sink,
daemonisation, the readiness pipe, the PID file, signal handling, the
writing of the host tunable of [P25](process.md#host-tunables) when the
service asks for it, the descriptor hand-over of
[P14](process.md#restart) where the init system offers one. It contains
no kernel logic; it hands a configuration and a
reload callback to the service and drives it through the control handle
([library](library.md#boundaries)). None of this depends on systemd or on
a particular libc ([P22–P24](process.md#the-process-contract)).

A2. The **services** turn the reconciler into something a program can
run: `converge` until applied, `run` until shutdown, reloads through a
callback, shutdown that removes everything. The blocking variant hosts a
runtime on a thread of its own.

A3. The **reconciler** owns the accepted configuration and the policy:
which changes are in place and which re-create, the degradation ladder,
retries, conflicts, disconnected tunnels, timers, and the handling of
every event ([model](model.md), [events](events.md)). It is the only
writer of state, with the one exception of [A7](#concurrency).

A4. The **state layer** owns the kernel-facing records and the operations
on them: one record per tunnel holding the socket, the family, the
binding, the peer and whether the socket is connected; one per session
holding its identity and pending changes; one per resolver holding its
servers and answers. It performs the ownership proofs
([M10](model.md#ownership)) and knows nothing about policy.

A5. The **kernel interfaces**, each used for what only it can give:

| Interface | Use |
|---|---|
| L2TP/IP socket, one per tunnel | Ownership and automatic cleanup; bind to a device; connect to the peer, which selects the source; disconnect to stop sending and to reselect |
| L2TP generic netlink | Create, delete and query tunnels and sessions; the creation-time interface name as ownership proof and as the key of a deletion ([K16](kernel.md#facts)) |
| rtnetlink requests, on a socket of their own | Resolve names to indexes, rename, set hardware addresses, read a device's Ethernet address for a DHCPv6 resolver's DUID ([V12](resolvers.md#dhcpv6-information-request)), dump for resync. Never on the filtered monitor ([K29](kernel.md#facts)) |
| Link-lifetime subscription | A dedicated `RTNLGRP_LINK` socket whose sole job is to prove identities: opened before the first session, read continuously, consulted with ordered lookups, never filtered |
| Event monitor | One subscription to the link and address groups, filtered in the kernel when the host allows a filter ([K10](kernel.md#requirements)): the classic BPF program passes `RTM_NEWLINK` and `RTM_DELLINK` whose `ifi_family` is `AF_UNSPEC` ([E5](events.md#link-events)) and `RTM_NEWADDR` and `RTM_DELADDR`, and drops every other message type and every link message of another family; matching by name or index stays in the loop. No route group ([K7](kernel.md#requirements)) and no `RTNLGRP_ND_USEROPT`: a resolver's advertisements arrive on its own sockets ([E23](events.md#resolver-events)) |
| L2TP event subscription | The generic-netlink socket joins the `l2tp` multicast group ([K41](kernel.md#facts)) and delivers tunnel and session deletions commanded over netlink to the reconciler by identifiers ([E27](events.md#l2tp-events)) |
| Resolvers | The system resolver and the configured resolvers ([resolvers](resolvers.md)), in the background on threads of their own ([V15](resolvers.md#resources)), answers polled by the reconciler; a router-advertisement resolver owns a raw ICMPv6 socket on its bind interface ([K39](kernel.md#requirements)) or, without `CAP_NET_RAW`, a netlink socket of its own ([K14](kernel.md#requirements)); a DHCPv6 one a UDP socket on port 546 |

## Concurrency

A6. All state is owned by one task, the reconciler loop. Every other task
(the event monitor, the resolvers, the timers, the signal thread) only
sends messages into one bounded channel the loop reads, so that no lock
orders state changes and every event is applied in arrival order against
a consistent record. The channel has a fixed capacity. The kernel-facing
and timer producers never block on it: when the channel is full, the
kernel event producer drops the event and sets its own persistent loss
flag outside the channel, which the loop consumes before waiting
([E20](events.md#monitor-loss)); resolvers and timers keep their latest
state and send it again at their next tick. Operator calls to `reload_wait` ([L6](library.md#the-service)) may wait
for room; `reload` fails instead. The signal collector never waits for
queue capacity: it coalesces pending reload/restart requests separately
and keeps receiving shutdown signals (P12). The control
handle sends into the same channel plus one persistent shutdown flag, so
that a shutdown is never lost to a full queue and never waits behind a
reload.

A7. The link-lifetime subscription has its own socket and its own task
because its ordering guarantee is what makes identities provable: a
lookup sent on that socket is answered after every notification the
kernel queued before it, and a subscription that is read continuously is
never starved by a busy reconciler. It MUST NOT share a socket with
requests that could delay its reading. It keeps the identity proofs
itself (each registration's distinct incarnation, even when an index is
reused within one generation, and the loss generation, [M18](model.md#monitor-generations)) and answers the
reconciler's identity questions through a dedicated request-reply path
that does not pass through the event channel, so that a full channel can
neither block a proof nor silently retain a stale one. This is the one
piece of state the reconciler does not own.

A8. Kernel operations in a reconcile run in the dependency order of
[M6](model.md#reconciliation). Operations on different tunnels MAY run
concurrently where they share no identifier and no name; a session's
operations always follow its tunnel's.

A9. A resolver never blocks the loop: answers are polled every second
and queries become eligible thirty seconds after the previous one
returned. Configured lookups have finite execution bounds; libc system
lookups do not. Separate fixed worker budgets and coalesced pending work
bound resources even across reloads (V3–V4, V15). A stalled system lookup
may delay other system lookups when that budget is exhausted, but never
configured DNS, kernel work, readiness or shutdown.

## State

A10. The daemon keeps no state on disk except the PID file. Everything it
knows is rebuilt at start-up from the configuration and the kernel; this
is why a restart re-creates the interfaces unless the init system handed
the sockets over ([P14](process.md#restart)), and why nothing can go
stale across restarts.

A11. The reconciler holds, per tunnel: the configuration in force, the
socket's family, the binding (name, and index or invalid), the real peer
if any and whether the socket is connected to it. Per session: the
configuration in force, the identity (index and whether it is live,
removed or lost), the current name as far as known, deferred, skipped and
acknowledged changes ([M19](model.md#enforced-fields)). Per resolver:
its servers and the answers in force. Globally: conflict counters, timer
deadlines, the subscriptions' health and generations, and whether the
host tunable of [P25](process.md#host-tunables) was found set, pending
write request incarnations/deadlines, and exact descriptor-store names
awaiting retirement (L12, L13).

A12. Records are updated only after the kernel confirmed an operation,
and in a way that a failure between two steps leaves a record the next
reconcile can continue from (a session created but not yet published, a
tunnel bound but not connected).

## Failure containment

A13. A subscription that fails or overflows reopens itself and reports a
resync; it never takes the loop down. A kernel operation that fails
returns an error to the reconciler, which classifies it
([M13](model.md#failure-classes)); it never aborts the reconcile for other
entries. A resolver that fails keeps its last answer. The signal thread is
independent of the loop and cannot be blocked by it.

A14. Every retry is a message or a timer in the loop, never a nested wait,
so shutdown is observed before the next operation and wakes an idle
receiver independently of queue capacity. A synchronous in-flight kernel
request has a five-second total deadline; shutdown responsiveness is
bounded by that remaining deadline, not instantaneous interruption.
Cleanup may require multiple operations, each bounded; failed cleanup is
reported and cannot cause an unbounded wait.

## Why this shape

A15. Sockets rather than unmanaged tunnels, for two reasons. An
unmanaged tunnel fixes its local and remote addresses at creation: it
cannot follow a host name whose answer changes (a dynamic DNS peer), cannot
be bound to a device or a VRF, and cannot have its source reselected when
addresses change; a socket can be reconnected to a new peer, bound with
`SO_BINDTOIFINDEX`, and reconnected so that the kernel selects the source
and the output device through the binding and the routing context, which
is what makes [T14–T21](tunnels.md#peers) possible in place. And a socket
is an ownership proof the kernel enforces and a cleanup the kernel
performs at process death; an unmanaged tunnel would survive a crash and
could be deleted by anyone.

A16. Indexes rather than names: names are reusable and changed by others;
an index is unique for a device's lifetime, and a lifetime subscription
can prove it still refers to the same device.

A17. The kernel's record rather than a database: the creation-time name
the kernel stores is the only ownership proof that survives a loss of
notifications and needs nothing on disk, within the limit stated in
[S22](sessions.md#identity-loss).

A18. A filter in the kernel rather than in the loop, where the host allows
one: unrelated link and address churn would otherwise fill the monitor's
buffer and cost a resync per burst. The filter is an optimisation, not a
correctness requirement, because no route event is subscribed to at all.

A19. A disconnected socket rather than a substitute peer: a tunnel must
exist for its interfaces to exist, and the kernel registers a tunnel on a
socket that is not connected and drops the frames of such a tunnel itself
([K5](kernel.md#requirements)). Nothing is sent, no route is consulted,
no device is created, and a peer that becomes reachable is applied by one
connect ([K6](kernel.md#requirements)).

A20. A reconciler rather than event-driven mutations: the right state is a
function of the configuration and the host, so deriving it anew on every
event cannot drift, and every retry is just another reconcile.

## Extension

A21. New events are new variants of the non-exhaustive event type,
dispatched by the runtime's own `handle_event`, so that an embedding
program written against an older version forwards them unchanged
([L10](library.md#the-reconciler)); new entry fields are builder methods
with defaults that keep the old behaviour; new substitutes go into the
degradation ladder below the configured state and above "left out". A
change that moves a kind of change from in place to re-creation needs a
reason the kernel imposes, recorded in the [identity matrix](model.md#identity-matrix).

## Names

A22. Names that the kernel or the filesystem defines as nul-terminated
byte strings (file names, paths, interface names) are handled as byte
strings (OS strings, C strings) wherever no text format requires UTF-8;
they are never required to be valid UTF-8 for that reason alone. TOML
documents and the values in them are UTF-8 because the format is
([C1](configuration.md#files)).
