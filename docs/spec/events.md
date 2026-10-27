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
name starts querying ([V9](resolvers.md#binding)).

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
disappears stops querying.

E4. **A device changes state** (up, down, flags, MTU, controller): a
session device seen down gets its deferred hardware-address change
applied; a bind device's VRF membership change, or a VRF slave's,
reconnects the tunnels bound to the VRF. Nothing else is done, and nothing
is looked up in the kernel for a device no tunnel is bound to and no
session owns.

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

E8. A reconnect that fails queues one retry per bound device, or one for
all unbound tunnels, a second later; an event of the other family MUST
NOT postpone a queued retry. A retry resolves the configured bind name
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
name, family or resolver the configuration no longer names is discarded.

E11. Queries are refreshed every thirty seconds and their results polled
every second; a failed query and a negative answer keep the answer in
force ([V6](resolvers.md#queries-and-answers)). Replacing a tunnel's host
name, family or resolver discards its answers, so an old answer can
never be applied to a new name.

E23. **A router advertisement with RDNSS options** arrives on
`RTNLGRP_ND_USEROPT` for the bind interface of a router-advertisement
resolver: its servers are recorded with their lifetimes
([V10](resolvers.md#router-advertisements)); advertisements for other
interfaces, and other user options, are dropped by comparison.

E24. The event monitor's filter MUST pass `RTM_NEWNDUSEROPT` messages
whenever a resolver using router advertisements (`ra` or `ipv6`) is configured, and MAY drop them
otherwise; the filter never applies to the sockets requests are sent on
([K29](kernel.md#facts), [A5](architecture.md#layers)).

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
configuration received wins.

E26. **Restart** (`SIGUSR2` or the control handle): the daemon finishes
the operation in progress, hands its tunnel sockets to the binary on disk
by executing it in the same process ([P26](process.md#restart)), and the
new instance adopts them and reconciles; before readiness or during a
shutdown the request is ignored with a report.

## Monitor loss

E20. The netlink subscriptions have finite buffers (8 MiB, obtained with
`SO_RCVBUFFORCE`, [R10](requirements.md#the-host)). Loss is handled per
subscription ([M18](model.md#monitor-generations)). When the **event
monitor** overflows or its socket fails, the daemon reopens it, seeds it
from the kernel through the request socket, and treats everything that
could have been missed as possibly changed: every binding is checked by
name, every connected tunnel is reconnected for a fresh source, every
deferred hardware-address change is re-checked against the device's
state, and router-advertisement servers are kept until their lifetimes
expire ([V11](resolvers.md#router-advertisements)). When the **lifetime
subscription** overflows or fails, its generation ends: it is reopened
and seeded, and session identities captured in the old generation are
marked as lost ([S19](sessions.md#identity-loss)); the event monitor is
not resynced for that. The first subscription of the daemon's life,
opened before anything exists, misses nothing and causes no resync. The
event channel of [A6](architecture.md#concurrency) overflowing is handled
as a loss on the event monitor.

E21. A loss shows in three ways, and each is treated as a loss of
notifications on that socket: a receive that fails with `ENOBUFS`
([K29](kernel.md#facts)); a lookup whose reply does not arrive within its
timeout of two seconds, with or without an acknowledgement; and an
explicit socket error. A lookup on a socket known to have lost
notifications is not repeated once per retry: the socket is reopened
first. `NETLINK_NO_ENOBUFS` is not set, so that the error is seen.

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
unaffected ([K23](kernel.md#facts)).
