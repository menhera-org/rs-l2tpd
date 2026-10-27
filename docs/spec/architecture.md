# Architecture

[Specification index](README.md)

The structure the [promises](promises.md) need. It prescribes components,
their responsibilities and the interfaces between them, not their code.

## Layers

```
 operator ──signals, files──▶ ┌──────────────────────────────────────┐
                              │ binary: process, files, PID file,    │
                              │ logging sink, signals, installer     │
                              └──────────────┬───────────────────────┘
                                             │ Config, Control
                              ┌──────────────▼───────────────────────┐
 embedding program ─────────▶ │ services: Service, blocking::Service │
                              │ (converge, run, reload, shutdown)    │
                              └──────────────┬───────────────────────┘
                                             │ reconcile, handle_*
                              ┌──────────────▼───────────────────────┐
                              │ reconciler: plan and apply, event    │
                              │ handlers, timers, applied config     │
                              └──────────────┬───────────────────────┘
                                             │ operations on records
                              ┌──────────────▼───────────────────────┐
                              │ state: tunnel sockets, session       │
                              │ identities, null devices, routes     │
                              └───┬──────────┬──────────┬────────────┘
                                  │          │          │
                         L2TP/IP sockets  L2TP genl  rtnetlink ◀── link-lifetime
                                                               ◀── event monitor (filtered)
                                  resolver ─────────────────────▶ reconciler (answers)
                                                       kernel
```

A1. The **binary** owns everything that is a process concern: command
line, configuration files and their merging, the logging sink,
daemonisation, the readiness pipe, the PID file, signal handling and the
installer. It contains no kernel logic; it hands a configuration and a
reload callback to the service and drives it through the control handle
([library](library.md#boundaries)).

A2. The **services** turn the reconciler into something a program can
run: `converge` until applied, `run` until shutdown, reloads through a
callback, shutdown that removes everything. The blocking variant hosts a
runtime on a thread of its own.

A3. The **reconciler** owns the applied configuration and the policy:
which changes are in place and which re-create, the degradation ladder,
retries, conflicts, pending peers, timers, and the handling of every
event ([model](model.md), [events](events.md)). It is the only writer of
state.

A4. The **state layer** owns the kernel-facing records and the operations
on them: one record per tunnel holding the socket, the family, the
binding, the peer kind and the source; one per session holding its
identity and pending changes; the null devices and the discard routes. It
performs the ownership proofs ([M10](model.md#ownership)) and knows
nothing about policy.

A5. The **kernel interfaces**, each used for what only it can give:

| Interface | Use |
|---|---|
| L2TP/IP socket, one per tunnel | Ownership and automatic cleanup; bind to a device; connect to the peer, which selects the source; disconnect to reselect |
| L2TP generic netlink | Create, delete and query tunnels and sessions; the creation-time interface name as ownership proof |
| rtnetlink requests | Resolve names to indexes, rename, set hardware addresses, create and delete dummy devices, look up and install routes, dump for resync |
| Link-lifetime subscription | A dedicated `RTNLGRP_LINK` socket whose sole job is to prove identities: opened before the first session, read continuously, consulted with ordered lookups |
| Event monitor | One subscription to link, address and route groups, filtered in the kernel to the events the reconciler needs |
| Resolver | The host's resolver, in the background, one task per configured host name, answers polled by the reconciler |

## Concurrency

A6. All state is owned by one task, the reconciler loop. Every other task
(the event monitor, the link-lifetime subscription, the resolvers, the
timers, the signal thread) only sends messages into one channel the loop
reads, so that no lock orders state changes and every event is applied in
arrival order against a consistent record. The control handle sends into
the same channel plus one persistent shutdown flag, so that a shutdown is
never lost to a full queue.

A7. The link-lifetime subscription has its own socket and its own task
because its ordering guarantee is what makes identities provable: a
lookup sent on that socket is answered after every notification the
kernel queued before it, and a subscription that is read continuously is
never starved by a busy reconciler. It MUST NOT share a socket with
requests that could delay its reading.

A8. Kernel operations in a reconcile run sequentially in the order of
[M6](model.md#reconciliation). Operations on different tunnels MAY run
concurrently where they share no identifier and no name; a session's
operations always follow its tunnel's.

A9. The resolver never blocks the loop: answers are polled every second
and refreshed every thirty, and a resolver that hangs costs nothing but a
stale answer.

## State

A10. The daemon keeps no state on disk except the PID file. Everything it
knows is rebuilt at start-up from the configuration and the kernel; this
is why a restart re-creates the interfaces ([P14](process.md#restart))
and why nothing can go stale across restarts.

A11. The reconciler holds, per tunnel: the configuration in force, the
socket's family, the binding (name, and index or invalid), the current
peer and whether it is real, pending or a discard address, and whether
the socket is connected. Per session: the configuration in force, the
identity (index and whether it is live, removed or lost), the current
name as far as known, deferred and skipped changes. Globally: null
devices by index and hardware address, installed discard routes by
context, pending peers, conflict counters, timer deadlines, and the
subscriptions' health.

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
so that shutdown can interrupt anything within one iteration.

## Why this shape

A15. Sockets rather than unmanaged tunnels, for two reasons. An
unmanaged tunnel fixes its local and remote addresses at creation: it
cannot follow a host name whose answer changes (a dynamic DNS peer), cannot
be bound to a device or a VRF, and cannot have its source reselected when
addresses change; a socket can be reconnected to a new peer, bound with
`SO_BINDTODEVICE`, and reconnected so that the kernel selects the source
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
notifications and needs nothing on disk.

A18. A filter in the kernel rather than in the loop: a router's routing
churn would otherwise fill the monitor's buffer and cost a resync per
burst, which reconnects every tunnel.

A19. Discard addresses rather than waiting: a tunnel must exist for its
interfaces to exist, and a connected L2TP/IP socket needs a peer and a
route; the discard addresses are the only peers that are always correct
to send to and never answer.

A20. A reconciler rather than event-driven mutations: the right state is a
function of the configuration and the host, so deriving it anew on every
event cannot drift, and every retry is just another reconcile.

## Extension

A21. New events are new variants of the non-exhaustive event type and new
handlers; new entry fields are builder methods with defaults that keep
the old behaviour; new substitutes go into the degradation ladder below
the configured state and above "left out". A change that moves a kind of
change from in place to re-creation needs a reason the kernel imposes.
