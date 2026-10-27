# Events

[Specification index](README.md)

Every event that can change the right state of an entry
([M1](model.md#reconciliation)) MUST cause the daemon to converge that entry
again, and every event that cannot MUST cost nothing more than telling it
apart. Events arrive from the kernel through netlink subscriptions, from
the resolver, from timers and from the operator.

## Link events

E1. **A device appears** (new link, or a link event for a name a tunnel
waits for): every tunnel whose configured bind device has that name and
is not bound to it is bound and reconnected for a fresh source
([T12](tunnels.md#bind-devices)); a tunnel on a discard address because
its device was absent gets its real peer ([T13](tunnels.md#bind-devices)).

E2. **A device is renamed**: the daemon re-evaluates every binding by
name: a tunnel bound to the renamed device, now not bearing its configured
name, records the binding as invalid and waits ([T11](tunnels.md#bind-devices));
a device that took a configured name becomes the bind device of the
tunnels configured for it. Session devices follow their index: a rename of
a session device changes nothing except that pending hardware-address
changes are tried again ([E4](#link-events)).

E3. **A device disappears**: tunnels bound to it forget the binding and
wait for a device of the configured name; a VRF that disappears is treated
like any device. A session device that disappears ends its identity proof
as an observed removal ([S19](sessions.md#identity-loss)) and, when the
kernel no longer has the session, the session is created again
([S27](sessions.md#external-deletion)).

E4. **A device changes state** (up, down, flags, MTU, controller): a
session device seen down gets its deferred hardware-address change
applied; a bind device's VRF membership change, or a VRF slave's, refreshes
the tunnels bound to the VRF. Nothing else is done, and nothing is looked
up in the kernel for a device no tunnel is bound to and no session owns.

E5. Link events carry the protocol family `AF_UNSPEC` when they describe a
device's lifetime; events of other families (`AF_BRIDGE`, `AF_INET6`)
describe protocol state and MUST NOT be taken as creations or removals.

## Address events

E6. **An address is added** to a device: every tunnel bound to that device
or to its VRF whose current family is the address's family is reconnected
for a fresh source selection. Tunnels on a discard address, unbound
tunnels and tunnels of the other family are not touched. No kernel query
is made unless some tunnel is bound to a device.

E7. **An address is removed** from a device: as for an addition for bound
tunnels; in addition, every unbound tunnel with a real peer whose selected
source is the removed address is reconnected, whatever device the address
was on ([T19](tunnels.md#source-addresses)). The daemon identifies the
source by asking its own socket, not the kernel's address tables.

E8. A reconnect that fails queues one retry per bound device, or one for
all unbound tunnels, a second later; an event of the other family MUST
NOT postpone a queued retry. A retry resolves the configured bind name
again. Retries stop once the reconnect succeeds.

## Route events

E9. **A discard route is removed** (a host route to `100::` or `192.0.0.8`
in any table): the daemon repairs the routes it installed
([D11](discard.md#repair)) and nothing else. No other route event concerns
the daemon: route additions, including the route to a pending peer, are
not watched; pending peers are found by their retry timer. Route churn
MUST NOT reach the daemon: the subscription's filter drops everything but
the removals of discard routes in the kernel, so that a router's full
table changing costs the daemon nothing and cannot overflow its buffer.

## DNS events

E10. **A host name's answer changes** for the family the tunnel uses: the
tunnel is moved to the new address in place; an address that cannot be
connected to is kept pending and retried every second while the tunnel
keeps its previous answer ([T15](tunnels.md#peers)); an answer that cannot
be a peer is ignored with a warning. A change for the other family is
ignored. An answer for a host name the configuration no longer names, or
that was replaced, is discarded.

E11. The resolver is refreshed every thirty seconds and polled every
second for a changed answer; a failed resolution keeps the previous answer
and the tunnel's current peer. Replacing a tunnel's host name replaces its
resolver, so an old name's cached answer can never be applied to a new
name.

## Timers

E12. **Reconcile retry** (every second while a reconcile is incomplete):
the applied configuration is reconciled again from where it stopped.

E13. **Pending peer retry** (every second while any tunnel has a pending
peer): every pending peer is tried; success is applied in place and
reported once; a tunnel found disconnected is put back on a discard
address.

E14. **Left-out entry retry** (every thirty seconds while any entry is
left out for a conflict): a reconcile of the applied configuration is
requested, which tries the left-out entries again.

E15. **Discard-route grace** (ten seconds per family): the null device is
created and routed only when the grace has passed without the host routing
the address ([D6](discard.md#routes)).

E16. **Discard-route repair retry** (every second while a repair failed):
the repair is tried again ([D11](discard.md#repair)).

## Operator events

E17. **Reload** (`SIGHUP` or the control handle): the configuration is
read again and reconciled ([P13](process.md#signals-and-requests),
[C12](configuration.md#reload)). An unchanged configuration changes
nothing in the kernel; in particular it never reconnects a tunnel, renames
a device or re-applies a hardware address.

E18. **Shutdown** (`SIGTERM`, `SIGINT` or the control handle): everything
owned is removed ([P16](process.md#shutdown)); a shutdown during a slow
start-up removes what was created so far.

E19. **A reload while a reload is incomplete** replaces it; the last
configuration received wins.

## Monitor loss

E20. The netlink subscriptions have finite buffers (requested at 8 MiB,
granted as the host allows, never shrunk below the host's default). When a
subscription overflows or its socket fails, the daemon reopens it, seeds
it from the kernel, and treats everything that could have been missed as
possibly changed: every binding is checked by name, every tunnel with a
real peer is reconnected for a fresh source, the daemon's discard routes
are repaired, and session identities captured before the loss are marked
as lost ([S19](sessions.md#identity-loss)). The first subscription of the
daemon's life, opened before anything exists, misses nothing and causes no
resync.

E21. A lookup on an overflowed subscription times out rather than failing,
because the kernel drops the reply as it drops the notifications; a lookup
that gets no answer within its timeout is treated as a loss of
notifications, so that it is not repeated once per retry.

E22. Only the kernel's notifications (sender port 0) are acted on. This is
defence in depth: no unprivileged process can unicast to the daemon's
sockets, but a message from another port is ignored all the same.
