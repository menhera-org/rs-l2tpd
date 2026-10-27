# Discard addresses

[Specification index](README.md)

A tunnel must exist, so that its session interfaces exist, before it has
anything to send to. A connected L2TP/IP socket needs a peer address and a
route to it, but not reachability: the discard addresses supply exactly
that.

## Addresses

D1. The discard address of IPv6 is `100::` (RFC 6666, the discard-only
prefix); that of IPv4 is `192.0.0.8` (RFC 7600, the IPv4 dummy address).
Both are reserved for this kind of use, never answer, and are never
forwarded on the Internet. The daemon uses no other address for the
purpose.

D2. A tunnel goes to the discard address of its family, that is of its
`ip_version`, so that an IPv4 tunnel needs no IPv6 on the host and an
IPv6 tunnel no IPv4. When that address cannot be connected to (no route
after the grace period and no null device route could be installed, or no
source address of the family at all), the other family's discard address
is used; frames are dropped either way.

D3. A tunnel is on a discard address when: its host name has not resolved
yet, its endpoint is a tolerated configuration mistake, its real peer
cannot be reached ([T16](tunnels.md#peers-that-cannot-be-reached)), or
its bind device does not exist yet ([T13](tunnels.md#bind-devices)).
Frames sent into such a tunnel's sessions are dropped by the host and
MUST NOT leave it: a null device counts them as transmitted and drops
them; a route through a real device would send them to a next hop, so a
discard address MUST only ever be routed through a device that drops what
it transmits, or through a route the operator chose.

## Routes

D4. Connecting to a discard address needs a route covering it in the
routing context of the socket: the main table for an unbound socket or one
bound to an ordinary device, the VRF's table for a socket bound to a VRF.
A default route suffices. The daemon checks with the same lookup the
kernel's connect performs, with the VRF as output device where relevant.

D5. Blackhole, unreachable and prohibit routes refuse the connection
outright and MUST NOT be used or counted as a route. Loopback MUST NOT be
used: a route through loopback loops frames back into the host, and under
IPv6 forwarding can loop between devices.

D6. When the host routes the address itself, that route is used and
nothing is installed. Otherwise the daemon waits ten seconds, per address
family, counted from the first time the family's discard address was found
unrouted, for the host to get a route by itself, as it usually does
shortly after start-up at boot; connecting the tunnel is retried meanwhile.
Only after the grace does it install its own route.

## The null device

D7. The daemon's own route goes through a null device it creates: a
`dummy` link, named `rsl2tpnull0` or the next free `rsl2tpnullN` when that
name is occupied, with a locally administered unicast hardware address of
the daemon's choosing set atomically at creation, brought up. A dummy link
drops whatever it transmits: nothing is looped back, nothing leaves the
host, no neighbour discovery runs.

D8. The route is a host route, `100::/128` or `192.0.0.8/32`, through the
null device, in the main table or in the VRF's table. Both families MAY
share one null device. An existing route at the same prefix and metric,
whatever its kind, is never replaced: if it is a reject route the discard
address simply stays unrouted and the tunnel is retried.

D9. Existing devices are never adopted, whatever their name; ownership of
a null device is proved by the hardware address given at creation, not by
its name or index. A null device renamed by another manager stays owned; a
null device deleted and replaced under the same name or index is foreign.

D10. The null device is created only once a tunnel needs it, kept for the
daemon's lifetime once created, and removed at shutdown together with its
routes, only if still owned. A null device left behind by a crash is
foreign at the next start ([P18](process.md#crashes)).

## Repair

D11. A discard route the daemon installed can be removed by another
manager (systemd-networkd with `ManageForeignRoutes=yes`, a reconfiguration,
a VRF recreated). The daemon watches for the removal of such routes, and
only such routes, and reinstalls them in their current routing context: a
VRF is resolved again by its configured name and its current table, so a
recreated VRF with a new table gets the route in the new table and the old
table is left alone. A context that is temporarily absent is retried every
second. A lasting failure (a route that cannot be installed on this host at
all, as with IPv6 disabled) is reported once, not every second, and the
success afterwards once.

D12. Repair never creates a route the daemon did not install before, never
touches a foreign route, and stops at shutdown: a repair queued when
shutdown begins MUST NOT recreate a device or a route.

## Leaving the discard address

D13. When a tunnel gets a real peer, it is reconnected with a fresh source
selection through its bind device, because the source selected for the
discard address (possibly the null device's link-local address, or an
address since removed) is not the right one for the peer. The change is in
place: the socket, the tunnel and its sessions stay.
