# Model

[Specification index](README.md)

## Terms

- **Configuration**: the `tunnels` and `sessions` maps, keyed by
  configuration name, after the files were merged and converted. The
  **applied configuration** is the one in force: the last one the daemon
  accepted, at start-up or from a reload.
- **Entry**: one tunnel or one session of the configuration.
- **Kernel state**: the L2TP tunnels and sessions the kernel holds, the
  session devices (`l2tpeth`), the tunnel sockets, the daemon's null
  devices and discard routes.
- **Owned object**: a kernel object the daemon created and can still prove
  it created. A tunnel is owned through the socket the daemon holds; a
  session device through its tracked link lifetime; a session through the
  kernel's own record of its creation-time interface name; a null device
  through the hardware address the daemon gave it at creation.
- **Foreign object**: anything else, including an object that reuses a name
  or an identifier of an owned object that no longer exists.
- **Peer**: the address a tunnel socket is connected to. A **real peer** is
  the configured literal or the resolved address of the configured host
  name; a **discard address** is where a tunnel goes while it has no real
  peer ([discard](discard.md)).
- **Ready**: every tunnel and session of the applied configuration exists
  in the kernel ([P6](process.md#readiness)).

## Reconciliation

M1. The daemon is a reconciler. At every reconcile it derives, for every
entry of the applied configuration, the **right kernel state** from the
configuration and the current host state, compares it with the state it
holds, and applies the difference. The right state of a tunnel is defined
in [T1](tunnels.md#the-right-state-of-a-tunnel) and that of a session in
[S1](sessions.md#the-right-state-of-a-session).

M2. A reconcile MUST be idempotent: run twice on the same inputs, the
second run changes nothing in the kernel. An unchanged configuration
reloaded MUST cause no kernel change at all.

M3. A reconcile MUST keep partial progress. When applying an entry fails,
everything applied before stays applied and recorded, and the next
reconcile continues from there. Nothing is rolled back to make a failure
look clean.

M4. Entries are independent. A failure of one entry MUST NOT keep another
entry from being applied in the same reconcile, with one exception: a
session cannot be applied before its tunnel. A tunnel that cannot be
applied takes its sessions with it, and only them.

M5. A reconcile is triggered by: start-up, a reload, the retry timer while
an earlier reconcile left something unapplied, and the periodic retry of
entries left out for a conflict ([T25](tunnels.md#identifier-conflicts)).
Kernel and DNS events do not run a full reconcile; they run the handler of
the entries they concern ([events](events.md)).

M6. Operations on the kernel are ordered so that no step depends on a step
that can still fail: tunnel deletions, then tunnel creations and peer
changes, then session renames, hardware-address changes, deletions and
creations. Deleting precedes creating so that identifiers and names freed
by the former are available to the latter.

## The degradation ladder

M7. Every entry is applied in the most useful state the host allows right
now, in this order of preference, and promoted as soon as a better state
becomes possible:

1. The configured state: the real peer, the configured name and hardware
   address.
2. The same entry with a tolerated mistake corrected by the daemon: the
   kernel's hardware address instead of an unusable one, the discard
   address instead of an unusable endpoint.
3. The entry with a working but temporary substitute: a discard address of
   the entry's family while the real peer cannot be reached, resolved or
   routed; the other family's discard address when the first cannot be
   connected to.
4. The entry kept as it is, with a requested change skipped, when the
   change cannot be made safely (an interface whose identity cannot be
   proved).
5. The entry left out for now, with a bounded retry, when the kernel
   refuses its identifiers.
6. The entry retried every second, with readiness withheld, when the
   kernel cannot create it at all (missing support, missing privilege).

M8. Moving down the ladder MUST NOT change an interface's identity
([M11](#identity)), and moving up MUST happen in place as soon as the
obstacle is gone, without waiting for a reload.

## Ownership

M9. The daemon MUST NOT modify, delete or adopt a foreign object, whatever
name or identifier it carries. It MUST NOT remove a foreign route, even at
the prefix of its own discard route, and MUST NOT change a foreign device,
even one that reuses the index or the name of a former owned device.

M10. Before every change to an owned object the daemon MUST have proof,
obtained after the last event that could have replaced the object, that
the object is still its own. Where Linux cannot make the proof and the
change atomic, the interval between them MUST be as short as possible and
the residual risk is accepted and documented.

## Identity

M11. A session interface's identity is its link index for the lifetime of
the device. The daemon MUST NOT re-create a session, and so its interface,
unless the kernel cannot change the session in place: its session
identifier, peer session identifier or cookies change, or its tunnel's
identifiers change. Every other change, including a configuration mistake
and its correction, a rename, a hardware-address change, a peer change, a
bind-device change and a reconnection, keeps the interface.

M12. A tunnel socket's identity is the socket. The daemon MUST NOT replace
it unless the kernel cannot change the tunnel in place: its tunnel
identifier or peer tunnel identifier change. Peers, families, bind devices
and source addresses change on the same socket.

## Failure classes

M13. Every failure the daemon meets is one of:

- **Transient**: a route, address, device or kernel object not there yet,
  a kernel still finishing a deletion. Retried, every second while a
  reconcile is incomplete and otherwise by the handler's own timer. Never
  reported more than once per episode at warning level.
- **Lasting conflict**: identifiers held by another tunnel or session.
  Retried a bounded number of times, then the entry is left out and tried
  again slowly and on every reload ([T25](tunnels.md#identifier-conflicts)).
- **Unmanageable**: an owned object whose ownership can no longer be
  proved. The change is skipped and reported once; the object is left
  alone ([S20](sessions.md#identity-loss)).
- **Host defect**: no L2TP support, no privilege, no netlink. Retried every
  second, reported once, readiness withheld because the interfaces the
  network depends on cannot exist.
- **Configuration mistake**: handled at load time, never at apply time
  ([configuration](configuration.md)).

## Timing

M14. Intervals are fixed and documented, measured on a monotonic clock, and
unaffected by wall-clock changes:

| Interval | Value |
|---|---|
| Reconcile retry while incomplete | 1 s |
| Reconnect retry after a failed source reselection | 1 s per bound device, one timer per device |
| Pending peer retry | 1 s |
| Conflict retries before an entry is left out | 10, a second apart |
| Retry of left-out entries | 30 s, and every reload |
| Discard-route grace before the null device | 10 s per address family |
| Discard-route repair retry | 1 s |
| Host name refresh | 30 s |
| Wait for a deleted tunnel to leave the kernel | up to 2 s |

M15. The daemon MUST NOT poll where it can be notified, and MUST NOT loop
without delay. Every timer is bounded in number: one per bound device, one
for pending peers and left-out entries, one for route repair.

## Scale

M16. The cost of handling an event MUST be bounded by the number of
entries it concerns, not by the number of events on the host. Events that
concern no entry (an address change on a device no tunnel is bound to, a
route change that is not the removal of a discard route, a link change of
an unrelated device) MUST cost at most a comparison against the daemon's
own records, without a kernel query, and SHOULD be dropped before they
reach the daemon where the kernel can do so.
