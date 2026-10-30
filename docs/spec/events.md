# Events

[Specification index](README.md)

Every event that can change the right state of an entry
([M1](model.md#reconciliation)) MUST cause the daemon to converge that entry
again, and every event that cannot MUST cost nothing more than telling it
apart. Events arrive from the kernel through netlink subscriptions, from
the resolvers, from timers and from the operator.

## Link events

E1. **A device appears** (new link, or a link event for a name a tunnel
waits for): every tunnel whose configured bind device has that name and
is not bound to it is reconnected ([T21](tunnels.md#source-addresses)) and
so bound to it ([T12](tunnels.md#bind-devices)); a tunnel that was
disconnected because its device was absent gets its real peer
([T13](tunnels.md#bind-devices)). A resolver whose bind device has that
name is revalidated as a non-VRF link before its lookups or discovery
sockets start ([V9](resolvers.md#binding)).

For zoned peers, E1–E4 track both the configured bind name and the zone
name and their registration lifetimes (T27). Changes revalidate both
and VRF membership before reconnecting. A zone-only peer is tracked even
without an explicit bind interface. Resolver bind names and explicit server zone names are also tracked;
a replacement or rename requires V9 validation before further queries.

E2. **A device is renamed**: the daemon looks the old and the new name up
among the configured bind names and the owned indexes: a tunnel bound to
the renamed device, now not bearing its configured name, is disconnected
and waits ([T11](tunnels.md#bind-devices)); a device that took a
configured name becomes the bind device of the tunnels configured for it,
by a reconnect. Session devices follow their index: a rename of a session
device is an acknowledged override ([S10](sessions.md#names)) and changes
nothing else, except that pending hardware-address changes are tried
again ([E4](#link-events)).

E3. **A device disappears**: tunnels bound to it are disconnected and wait
for a device of the configured name; a VRF that disappears is treated
like any device. A session device that disappears ends its identity proof
as an observed removal ([S19](sessions.md#identity-loss)) and, when the
kernel no longer has the session, the session is created again
([S27](sessions.md#external-deletion)). A resolver whose bind device
disappears stops lookups and discovery, retains its answers, and waits
for a non-VRF link of the name ([V9](resolvers.md#binding)).

E4. **A device changes state** (up, down, flags, MTU, controller): a
session device seen down gets its deferred hardware-address change
applied. A change of a device's controller (`IFLA_MASTER`) reconnects
tunnels in two cases: the tunnels bound to that device itself, when its
controller becomes or stops being a VRF, because the device's L3 domain
and so its source selection changed ([K28](kernel.md#facts)); and the
tunnels bound to a VRF, when any device's controller becomes or stops
being that VRF, because the VRF's set of addresses changed. A controller
change to or from a bridge or bond reconnects nothing. Nothing else is
done, and nothing is looked up in the kernel for a device no tunnel is
bound to, no zone depends on, no resolver uses and no session owns.

E5. Link events carry the protocol family `AF_UNSPEC` when they describe a
device's lifetime; events of other families (`AF_BRIDGE`, `AF_INET6`)
describe protocol state and MUST NOT be taken as creations or removals.

## Address events

E6. **An address is added** to a device: every connected tunnel bound to
that device or to its VRF whose current family is the address's family is
reconnected for a fresh source selection. Disconnected tunnels, unbound
tunnels and tunnels of the other family are not touched. No kernel query
is made unless some tunnel is bound to a device.

E7. **An address is removed** from a device: as for an addition for bound
tunnels; in addition, every unbound connected tunnel whose selected source
is the removed address is reconnected, whatever device the address was on
([T19](tunnels.md#source-addresses)). The daemon identifies the source by
the address it read from its own socket after the last reconnect
([T28](tunnels.md#peer-changes)), not from the kernel's address tables.

E8. A reconnect that fails queues one retry for that tunnel a second
later; an event of the other family MUST NOT postpone a queued retry. A retry resolves the configured bind name
again. Retries stop once the reconnect succeeds.

## Route events

E9. Removed. No route event concerns the daemon: the event monitor does
not subscribe to the route groups ([K7](kernel.md#requirements)), so a
router's full table changing costs the daemon nothing and cannot overflow
its buffer. Routes to a pending peer are found by the pending-peer retry
([E13](#timers)).

## Resolver events

E10. **An answer in force changes** for the family a tunnel uses
([V6](resolvers.md#queries-and-answers)): the tunnel is reconnected to the
selected address ([T28](tunnels.md#peer-changes)); an address that cannot
be connected to leaves the tunnel disconnected with the address pending
and retried every second ([T15](tunnels.md#peers)). An answer for a host
name, family, resolver or resolver configuration incarnation no longer
in force is discarded, including a late result from before reload.

E11. Queries become eligible thirty seconds after the previous lookup
returned, with admission and execution limits of V3, V4 and V15
(configured queries bounded, libc calls unbounded), and their results
are polled every second; a failed query and a negative
answer keep the answer in force ([V6](resolvers.md#queries-and-answers)). Replacing a tunnel's host
name, family, resolver or that resolver's configuration discards its
answers and invalidates outstanding lookup results (V7).

E23. **A router advertisement with RDNSS options** arrives on a
router-advertisement resolver's own socket: its raw ICMPv6 socket, or its
`RTNLGRP_ND_USEROPT` socket when the raw one could not be opened
([V10](resolvers.md#router-advertisements)). The resolver records the
servers with their lifetimes and drops advertisements for other
interfaces and other user options; the daemon's event monitor neither
receives nor needs the advertisement, and does nothing.

E24. Removed: the event monitor does not subscribe to
`RTNLGRP_ND_USEROPT`; a resolver's netlink fallback is a socket of its
own ([V10](resolvers.md#router-advertisements), [K14](kernel.md#requirements)).
The monitor's filter never applies to the sockets requests are sent on
([K29](kernel.md#facts), [A5](architecture.md#layers)).

## L2TP events

E27. **A session or tunnel deletion is announced** on the `l2tp`
multicast group ([K41](kernel.md#facts)): match its identifiers to the
configuration, then query the current local namespace. Announcements
are advisory: they may come from another namespace (kernels before 7.3,
[K41](kernel.md#facts)), be delayed from an older incarnation, or
precede actual removal (every kernel). A local session confirmed
absent is re-created (S27, S29); a local tunnel confirmed absent is
reported as T9 requires. A still-present object is preserved. While a
suspected deletion is pending, retain one coalesced verification task per
configured identity and retry local queries on the one-second timer until
absence or a different incarnation is confirmed, or that configuration
identity is removed. A present record alone cannot distinguish a foreign
announcement from a local deletion still queued in the kernel. This may
keep verification queries pending after a foreign same-ID event; it must
not withhold readiness, mutate the live object, or run a full reconcile.
The number of pending tasks is bounded by configured identities.
Unmatched announcements cost only a comparison. Accept only kernel
senders (E22); sender validation does not establish namespace identity.

## Timers

E12. **Reconcile retry** (every second while a reconcile is incomplete):
the accepted configuration is reconciled again from where it stopped.

E13. **Pending peer retry** (every second while any tunnel has a real peer
it is not connected to): every such tunnel is reconnected
([T21](tunnels.md#source-addresses)); success is applied in place and
reported once.

E14. **Left-out entry retry** (every thirty seconds while any entry is
left out for a conflict): a reconcile of the accepted configuration is
requested, which tries the left-out entries again.

E15. Removed (there is no grace period).

E16. Removed (there is no route to repair).

## Operator events

E17. **Reload** (`SIGHUP` or the control handle): the configuration is
read again and reconciled ([P13](process.md#signals-and-requests),
[C12](configuration.md#reload)). For converged entries an unchanged
configuration changes nothing in the kernel ([G18](promises.md#conditional-promises)):
it never reconnects a connected tunnel, renames a published device or
re-applies a hardware address; entries with pending work are retried.

E18. **Shutdown** (`SIGTERM`, `SIGINT` or the control handle): everything
owned is removed ([P16](process.md#shutdown)); a shutdown during a slow
start-up removes what was created so far.

E19. **A reload while a reload is incomplete** replaces it; the last
configuration received wins. A reload callback already running is not
cancelled: it completes, its result is discarded, and the latest request
runs next ([P13](process.md#signals-and-requests)).

E26. **Restart** (`SIGUSR2` or the control handle): the daemon finishes
the operation in progress, hands its tunnel sockets to the binary on disk
by executing it in the same process ([P26](process.md#restart)), and the
new instance adopts them and reconciles; before readiness or during a
shutdown the request is ignored with a report.

## Monitor loss

E20. The netlink subscriptions have finite buffers (8 MiB requested for
each of the three, 16 MiB after the kernel's doubling, obtained with
`SO_RCVBUFFORCE`, [R10](requirements.md#the-host)). Loss is handled per
subscription ([M18](model.md#monitor-generations)). When the **event
monitor** overflows or its socket fails, the daemon reopens it, seeds it
from the kernel through the request socket, and treats everything that
could have been missed as possibly changed: every binding is checked by
name, every connected tunnel is reconnected for a fresh source, every
deferred hardware-address change is re-checked against the device's
state, and every resolver bind/zone dependency is revalidated. Unchanged
resolver dependencies keep discovery state and its V10 lifetime policy;
replaced or invalid dependencies follow V9 and V11. When the **lifetime
subscription** overflows or fails, its generation ends: it is reopened
and seeded, and session identities captured in the old generation are
marked as lost ([S19](sessions.md#identity-loss)); the event monitor is
not resynced for that. The first subscription of the daemon's life,
opened before anything exists, misses nothing and causes no resync. The
event channel of [A6](architecture.md#concurrency) overflowing records a
persistent loss flag for the producer that dropped the event.

Loss on the **L2TP subscription** reopens that subscription and queries
all configured tunnels and sessions in the local namespace, including
adopted and unmanageable sessions without a device proof. Confirmed
missing sessions enter S27 recovery; missing tunnels enter T9 reporting.
A failed or incomplete scan stays pending and retries; clear the loss flag
only after a complete scan, retaining any loss that occurred during it.
This is recovery triggered by loss, not periodic reconciliation of a
converged configuration. Separate persistent monitor and L2TP loss flags
cannot themselves be dropped when the event queue is full.

E21. A loss shows in three ways, and each is treated as a loss of
notifications on that socket: a receive that fails with `ENOBUFS`
([K29](kernel.md#facts)), which is the detector, because the kernel raises
it for every message it could not queue, a dropped reply as much as a
dropped notification; a lookup whose reply does not arrive within its
timeout of five seconds, with or without an acknowledgement, which is a
backstop for a kernel that never answers and not a second detector (a
short timeout would only make false losses, and a loss is permanent for
published sessions, [S20](sessions.md#identity-loss)); and an explicit
socket error. A lookup on a socket known to have lost notifications is
not repeated once per retry: the socket is reopened first.
`NETLINK_NO_ENOBUFS` is never set on the subscriptions, so that the error
is seen.

E22. Only the kernel's notifications (sender port 0) are acted on. This is
defence in depth: no process without `CAP_NET_ADMIN` can unicast to the
daemon's sockets ([K30](kernel.md#facts)), but a message from another
port is ignored all the same.

## Host tunables

E25. **`bindv6only` found set**: a freshly created `AF_INET6` socket that
reports `IPV6_V6ONLY=1`, or the scratch check at a reconcile, is the
event that the tunable flipped ([T26](tunnels.md#hosts-with-bindv6only));
with `host.fix_bindv6only` on, the tunable is set back to 0 and logged
([P25](process.md#host-tunables)); sockets created before the flip are
unaffected ([K23](kernel.md#facts)). A scratch socket the kernel refuses
(`EAFNOSUPPORT`, `EPROTONOSUPPORT`) means the host has no `AF_INET6`
sockets ([T4](tunnels.md#address-families)); the tunable is then
irrelevant and nothing is reported.
