# Tunnels

[Specification index](README.md)

## The right state of a tunnel

T1. A tunnel of the applied configuration has, at every moment, one right
kernel state, derived from the configuration and the host:

- **Socket**: one L2TP/IP socket, owned by the daemon, bound to the
  unspecified address with the tunnel identifier as its connection
  identifier, of the family [T3](#address-families) selects. The tunnel is
  registered with the kernel on this socket, with the peer tunnel
  identifier.
- **Bind device**: when `bind_interface` is configured, the socket is bound
  to the device that bears that name now ([T10](#bind-devices)).
- **Peer**: the address [T14](#peers) selects: the real peer when it can be
  connected to, else a discard address.
- **Source**: the address the kernel selects for the peer through the bind
  device, or through the routing table, at the time of the last connect,
  and which still exists on the host.
- **Connected**: the socket's last connect succeeded and left it with a
  specified source address.

T2. The daemon MUST converge the kernel state to this state at every
reconcile and at every event that changes one of its inputs
([events](events.md)), in place wherever the kernel allows
([M12](model.md#identity)).

## Address families

T3. Each tunnel uses one dual-stack `AF_INET6` L2TP/IP socket, which
carries IPv4 peers as IPv4-mapped addresses, so that a peer can move
between families on the same socket. This family MUST be used whenever
the kernel can open such a socket, including on a host without a single
IPv6 address or route.

T4. When, and only when, the kernel refuses an `AF_INET6` L2TP/IP socket
(`EAFNOSUPPORT`, as with `ipv6.disable=1`, or `EPROTONOSUPPORT`, without
the IPv6 L2TP module), every tunnel uses an `AF_INET` socket. The daemon
remembers the refusal and does not try `AF_INET6` again for later tunnels.
Under `AF_INET` everything is the IPv4 form: the `sockaddr_l2tpip` socket
address, the `IP_*` socket options, the `L2TP_ATTR_IP_*` attributes,
native IPv4 endpoints. An IPv6 peer is impossible on such a socket; it is
treated as unreachable ([T16](#peers-that-cannot-be-reached)) and never
handed to the kernel.

T5. The daemon sets no socket option the kernel does not default to,
except the device binding. MTU, path MTU discovery, hop limit and traffic
class keep the kernel's defaults; changing them is the operator's.

## Creation and identifiers

T6. A tunnel is created by binding its socket, connecting it to the
selected peer and registering it with the kernel. The socket is created
with the close-on-exec flag so that no child process can keep a tunnel
alive.

T7. The tunnel identifier is unique on the host and the kernel refuses a
second use (`EEXIST` at registration, `EADDRINUSE` at bind). Such refusals
are conflicts ([T25](#identifier-conflicts)).

T8. A tunnel is deleted by closing its socket, never by its identifier,
so that a foreign tunnel that took the identifier after an external
deletion is never removed. After a deletion the daemon waits, up to two
seconds, for the kernel to finish removing the tunnel before it creates
one with the same identifier; a creation refused meanwhile is a transient
conflict.

T9. An operator who deletes or replaces a managed tunnel in the kernel
breaks the daemon's ownership proof, which only the socket gives; this is
unsupported and documented, and the daemon's only duty then is not to
delete the replacement.

## Bind devices

T10. `bind_interface` names a device, which may be any device including a
VRF. The socket is bound to it with `SO_BINDTODEVICE` by name, and the
daemon records the index the name resolved to at that moment; the binding
is verified by resolving the name immediately before and after the bind,
and discarded if the two differ.

T11. The configured name is authoritative. The daemon follows the name,
not the device: when the device is renamed away and another device takes
the name, the socket is rebound to the latter; when the device is renamed
away and nothing takes the name, the binding is recorded as invalid, the
socket keeps its kernel binding to the old device, and nothing is
reconnected until a device of the configured name exists, because
reconnecting would strip the binding and leak frames through another path.

T12. When the bind device disappears, the daemon forgets the binding and
waits for a device of the configured name; when one appears, the socket is
bound to it and reconnected for a fresh source. A device replaced under the
same name with a new index is detected by a link event or by resync and
rebound likewise.

T13. When the bind device does not exist at creation, the tunnel is still
created, so that its sessions exist, but it MUST NOT reach its peer through
another device: it sits on a discard address until a device of the
configured name exists, is then bound and connected to its real peer.
This is a [known gap](README.md#known-gaps): today the socket is created
unbound and uses the main routing table meanwhile.

## Peers

T14. The peer a tunnel is connected to is selected as follows:

1. A configured literal address is the real peer.
2. A configured host name is resolved in the background for the family
   `ip_version` names; the first usable answer of that family is the real
   peer. Until there is one, the tunnel has no real peer. An answer that
   is not a unicast address (unspecified, multicast, broadcast) is ignored
   with a warning and the tunnel keeps its current peer.
3. Without a real peer, or while the real peer cannot be connected to, the
   peer is the discard address of the tunnel's family; if that cannot be
   connected to, the other family's ([discard](discard.md)).

T15. Host names are refreshed every thirty seconds. A changed answer is
applied as a peer change in place. An answer that changes family is
applied on the same socket. An answer that cannot be connected to keeps the
tunnel on its previous answer of the same host name, which is the same
peer host, and is retried as a pending peer. The previous answer is never
kept when the host name itself changed.

## Peers that cannot be reached

T16. A real peer that the kernel cannot
connect to now (no route: `ENETUNREACH`, `EHOSTUNREACH`; no source
address: `EADDRNOTAVAIL`; a reject route: `EACCES`; a link-local address
without a device; a device gone: `ENODEV`; an IPv6 peer on an `AF_INET`
socket) is a transient failure, never a configuration mistake. The tunnel
is connected to a discard address instead, the peer is recorded as
pending, and tried again every second until it is reached; the wait is
reported once at warning level and the success once at information level.
Readiness does not wait for it.

T17. A peer change to an address that cannot be reached moves the tunnel
to a discard address, not back to the previous peer: a tunnel never stays
with a peer the configuration no longer names.

T18. A tunnel connected to a discard address is not reconnected for
address events; it has nothing to reach. Leaving the discard address for a
real peer always selects the source address afresh.

## Source addresses

T19. The kernel fixes a socket's source address at connect time and keeps
it until the socket is disconnected, even after the address is removed
from the host. The daemon therefore reconnects (disconnect, rebind, connect)
whenever the right source may have changed:

- a bound tunnel: on every address addition or removal of its family on
  its bind device or on a member of its bind VRF, and when the bind
  device's VRF membership changes;
- an unbound tunnel: when the address it selected as its source is removed
  from the host, whatever device it was on;
- every tunnel with a real peer: on a monitor resync
  ([E20](events.md#monitor-loss)).

T20. A reconnect that leaves the socket without a specified source (the
device has no address of the family yet) is a failed reconnect: the
binding is kept, the tunnel is recorded as disconnected, and one retry per
bound device is queued a second later; unbound tunnels share one retry.
Retries continue until a reconnect succeeds, and stop then. A reconnect
MUST resolve the configured bind name again, so that it follows a
replacement device created while the retry was queued.

T21. A reconnect of a bound tunnel MUST restore the device binding before
connecting, because disconnecting clears it in the kernel. Reconnects of
tunnels on the same device are independent: a sibling that is connected is
not disturbed by another's retry.

## Changes applied in place

T22. The following configuration changes keep the socket, the tunnel and
its sessions: `remote_addr`, `ip_version`, `bind_interface`, and the
correction of an unusable endpoint. A changed `bind_interface` is applied
by rebinding the socket to the new name and reconnecting; this is a
[known gap](README.md#known-gaps): today it re-creates the tunnel.

T23. The following changes re-create the tunnel, and with it its sessions
and their interfaces, because the kernel cannot change them: `tunnel_id`
(which is a removal and an addition) and `peer_tunnel_id`.

T24. A re-creation deletes the old tunnel first, waits for the kernel to
release its identifier, then creates the new one and its sessions in the
same reconcile; interface names are reused.

## Identifier conflicts

T25. The kernel refuses a tunnel or a session whose identifiers another
tunnel or session of the host holds. A refusal is retried every second up
to ten times, which absorbs the kernel finishing a deletion of the
daemon's own. After the tenth refusal the entry is left out, with one
warning naming it and the error, and tried again every thirty seconds and
at every reload, quietly, until the identifiers are free; it is then
created and the warning is cleared by an information message. A left-out
tunnel takes its sessions with it; nothing else is affected, and readiness
is not withheld beyond the ten retries.
