# Tunnels

[Specification index](README.md)

## The right state of a tunnel

T1. A tunnel of the accepted configuration has, at every moment, one right
kernel state, derived from the configuration and the host:

- **Socket**: one L2TP/IP socket, owned by the daemon, bound to the
  unspecified address with the tunnel identifier as its connection
  identifier, of the family [T3](#address-families), [T4](#address-families)
  and [T26](#hosts-with-bindv6only) select. The tunnel is registered with
  the kernel on this socket, with the peer tunnel identifier, whether or
  not the socket is connected ([K5](kernel.md#requirements)).
- **Bind device**: when `bind_interface` is configured, the socket is bound
  by index to the device that bears that name now ([T10](#bind-devices)),
  or unbound while no device bears it ([T13](#bind-devices)).
- **Peer**: the real peer [T14](#peers) selects, when the socket can be
  connected to it; otherwise none.
- **Source**: the address the kernel selected for the peer through the
  bind device, or through the routing context, at the time of the last
  connect, and which still exists on the host.
- **Connected**: the socket is connected if and only if there is a real
  peer the kernel accepted a connect to and the bind device, when
  configured, is present. Otherwise the socket is **disconnected**: the
  tunnel and its sessions exist, the kernel drops every frame they send,
  and nothing leaves the host ([K5](kernel.md#requirements)).

T2. The daemon MUST converge the kernel state to this state at every
reconcile and at every event that changes one of its inputs
([events](events.md)), in place wherever the kernel allows
([M12](model.md#identity)).

## Address families

T3. Each tunnel uses one dual-stack `AF_INET6` L2TP/IP socket, which
carries IPv4 peers as IPv4-mapped addresses, so that a peer can move
between families on the same socket. This family is used whenever the
kernel can open such a socket and the socket is not IPv6-only
([T26](#hosts-with-bindv6only)), including on a host without a single
IPv6 address or route.

T4. When the kernel refuses an `AF_INET6` L2TP/IP socket
(`EAFNOSUPPORT`, as with `ipv6.disable=1`, or `EPROTONOSUPPORT`, without
the IPv6 L2TP module, [K4](kernel.md#requirements)), the tunnel uses an
`AF_INET` socket. The refusal is probed again at every tunnel creation,
so that a module that becomes available later serves the tunnels created
after it; an existing tunnel keeps its socket, because a change of family
is never a reason to re-create ([M17](model.md#identity-matrix)). Under
`AF_INET` everything is the IPv4 form: the `sockaddr_l2tpip` socket
address, the `IP_*` socket options, the `L2TP_ATTR_IP_*` attributes,
native IPv4 endpoints. An IPv6 peer is impossible on such a socket; the
tunnel stays disconnected ([T16](#peers-that-cannot-be-reached)) and the
condition is reported once.

T5. The daemon sets no socket option the kernel does not default to,
except the device binding. MTU, path MTU discovery, hop limit and traffic
class keep the kernel's defaults; changing them is the operator's.
`IPV6_V6ONLY` cannot be changed on an L2TP/IPv6 socket
([K23](kernel.md#facts)) and the daemon does not try.

## Creation and identifiers

T6. A tunnel is created by binding its socket to the unspecified address
with the tunnel identifier, binding it to the bind device when one is
configured and present ([T10](#bind-devices)), registering the tunnel
with the kernel on the socket, and creating its sessions. It is created
disconnected; it is connected in the same reconcile when a real peer
exists and the kernel accepts the connect ([T16](#peers-that-cannot-be-reached)),
and otherwise as soon as one does. The socket is created with the
close-on-exec flag so that no child process can keep a tunnel alive.

T7. The tunnel identifier is unique in the namespace and the kernel
refuses a second use (`EEXIST` at registration, `EADDRINUSE` at bind,
[K19](kernel.md#facts)). Such refusals are conflicts
([T25](#identifier-conflicts)).

T8. A tunnel is deleted by closing its socket, never by its identifier,
so that a foreign tunnel that took the identifier after an external
deletion is never removed. The kernel finishes the deletion
asynchronously ([K17](kernel.md#facts)): after a deletion the daemon
waits, up to two seconds, for the kernel to finish removing the tunnel
before it creates one with the same identifier; a creation refused
meanwhile is a transient conflict.

T9. An operator who deletes or replaces a managed tunnel in the kernel
breaks the daemon's ownership proof, which only the socket gives; this is
unsupported and documented, and the daemon's only duty then is not to
delete the replacement.

## Bind devices

T10. `bind_interface` names a device, which may be any device including a
VRF. The daemon resolves the name to an index when it binds and binds the
socket to that index with `SO_BINDTOIFINDEX` ([K22](kernel.md#facts)), so
that a device that takes the name between the resolution and the bind
cannot be bound to; it records the index. The binding is only ever set on
a socket that has none, because every change of binding follows a
disconnect, which clears it ([T21](#source-addresses)); no capability is
needed for it ([K22](kernel.md#facts)).

T11. The configured name is authoritative. The daemon follows the name,
not the device: when the device is renamed away and another device takes
the name, the tunnel is reconnected to the latter ([T21](#source-addresses));
when the device is renamed away and nothing takes the name, the tunnel is
disconnected at once, so that no frame leaves through the old device or
any other, the binding is recorded as invalid, and nothing is connected
until a device of the configured name exists.

T12. When the bind device disappears, the tunnel is disconnected and the
daemon waits for a device of the configured name; when one appears, the
socket is bound to it and connected for a fresh source. A device replaced
under the same name with a new index is detected by a link event or by
resync and handled likewise.

T13. When the bind device does not exist at creation, the tunnel is still
created, unbound and disconnected, so that its sessions exist and nothing
is sent; it is bound and connected to its real peer once a device of the
configured name exists ([E1](events.md#link-events)). A device-bound
tunnel is never connected while unbound.

## Peers

T14. The real peer of a tunnel is:

1. the configured literal address; or
2. for a configured host name, the selected address of the tunnel's
   resolver for the family `ip_version` names
   ([V5](resolvers.md#queries-and-answers)); until there is one, the
   tunnel has no real peer and is disconnected.

T15. A changed answer is applied as a peer change
([T28](#peer-changes)), in place on the same socket. An answer of the
other family is never applied ([V7](resolvers.md#queries-and-answers)).
A new answer that cannot be connected to leaves the tunnel disconnected
with the new address pending; the previous address is not returned to,
because the resolver no longer names it ([T17](#peers-that-cannot-be-reached)).

## Peers that cannot be reached

T16. A real peer that the kernel cannot connect to now is a transient
failure, never a configuration mistake. The tunnel is left or made
disconnected, the peer is recorded as pending, and the connect is tried
again every second until it succeeds; the wait is reported once at
warning level and the success once at information level. Readiness does
not wait for it. The outcomes of a connect and their classes
([K26](kernel.md#facts), [M13](model.md#failure-classes)):

| Outcome | Meaning | Class |
|---|---|---|
| `ENETUNREACH` | no route, or a `throw` route with nothing behind it | transient |
| `EHOSTUNREACH` | an `unreachable` route | transient |
| `EACCES` | a `prohibit` route | transient |
| `EINVAL` | a `blackhole` route | transient |
| `EADDRNOTAVAIL` | no source address of the family in the socket's L3 domain, whatever the routes | transient |
| `ENODEV`, `ENETDOWN` | the bound device is gone or down | transient; the binding is re-evaluated ([T12](#bind-devices)) |
| an IPv6 peer on an `AF_INET` socket | not attempted | transient, until the host changes ([T4](#address-families)) |
| `EINVAL` for a link-local peer without a zone or binding | prevented at load time ([C7](configuration.md#tunnel-entries)) | configuration mistake |
| `EAFNOSUPPORT`, `EPERM` | a connect without a preceding disconnect, a binding changed in place | defect of the daemon ([M13](model.md#failure-classes)) |

T17. A peer change to an address that cannot be reached leaves the tunnel
disconnected, not with the previous peer: a tunnel is never connected to
a peer the configuration or the resolver no longer names.

T18. A disconnected tunnel is not reconnected for address events; its
only path to a connection is the pending-peer retry
([E13](events.md#timers)) or a bind device appearing
([E1](events.md#link-events)). Leaving the disconnected state always
selects the source address afresh.

## Source addresses

T19. The kernel fixes a socket's source address at connect time and keeps
it until the socket is disconnected ([K24](kernel.md#facts)), even after
the address is removed from the host. The daemon therefore reconnects
([T21](#source-addresses)) whenever the right source may have changed:

- a bound tunnel: on every address addition or removal of its family on
  its bind device or on a member of its bind VRF, and when the bind
  device's VRF membership changes;
- an unbound tunnel: when the address it selected as its source is removed
  from the host, whatever device it was on;
- every connected tunnel: on a monitor resync
  ([E20](events.md#monitor-loss)).

T20. A reconnect that fails, or that leaves the socket without a specified
source (the device has no address of the family yet), leaves the tunnel
disconnected with its peer pending, and one retry per bound device is
queued a second later; unbound tunnels share one retry. Retries continue
until a reconnect succeeds, and stop then. A retry MUST resolve the
configured bind name again, so that it follows a replacement device
created while the retry was queued.

T21. A **reconnect** is always the same three steps: disconnect
(`connect(AF_UNSPEC)`), which clears the kernel's device binding and the
previous source ([K22](kernel.md#facts), [K24](kernel.md#facts)); bind to
the index the configured bind name resolves to now, when one is
configured and the device exists; connect to the real peer. The steps are
never shortened: a connect without the disconnect keeps the previous
source and fails across families ([K24](kernel.md#facts)). Reconnects of
tunnels on the same device are independent: a sibling that is connected
is not disturbed by another's retry.

## Changes applied in place

T22. The following configuration changes keep the socket, the tunnel and
its sessions: `remote_addr`, `ip_version`, `resolver_name`,
`bind_interface`, and the correction of an unusable endpoint. A changed
`bind_interface` is applied by a reconnect to the new name; this is a
[known gap](README.md#known-gaps): today it re-creates the tunnel.

T23. The following changes re-create the tunnel, and with it its sessions
and their interfaces, because the kernel cannot change them: `tunnel_id`
(which is a removal and an addition) and `peer_tunnel_id`.

T24. A re-creation deletes the old tunnel first, waits for the kernel to
release its identifier ([T8](#creation-and-identifiers)), then creates the
new one and its sessions in the same reconcile; interface names are
reused.

## Identifier conflicts

T25. The kernel refuses a tunnel or a session whose identifiers another
tunnel or session of the namespace holds ([K19](kernel.md#facts)). A
refusal is retried every second up to ten attempts in all, which absorbs
the kernel finishing a deletion of the daemon's own
([K17](kernel.md#facts), [K18](kernel.md#facts)). After the tenth refusal
the entry is left out, with one warning naming it and the error, and
tried again every thirty seconds and at every reload, quietly, until the
identifiers are free; it is then created and the warning is cleared by an
information message. A left-out tunnel takes its sessions with it;
nothing else is affected, and readiness is not withheld beyond the ten
attempts. The counter restarts when the entry's identifiers change on
reload.

## Hosts with bindv6only

T26. `net.ipv6.bindv6only=1` makes every new `AF_INET6` socket IPv6-only,
which a connect to an IPv4-mapped address refuses with `ENETUNREACH`, and
the option cannot be cleared on an L2TP/IPv6 socket
([K23](kernel.md#facts)). After creating an `AF_INET6` socket the daemon
reads `IPV6_V6ONLY` back. If it is set and `host.fix_bindv6only` is on,
the daemon has the tunable set to 0 ([P25](process.md#host-tunables)),
closes the socket and creates it again. If it is set and the option is
off, or the write failed, a tunnel whose `ip_version` is `V4` gets an
`AF_INET` socket instead and a tunnel whose `ip_version` is `V6` keeps
the `AF_INET6` socket; the loss of in-place family moves for such
tunnels is reported once. A tunnel keeps the family it was created with
until it is re-created for another reason ([M17](model.md#identity-matrix)).

## Link-local peers

T27. A link-local IPv6 peer needs an interface: the zone of the literal
(`fe80::1%eth0`), or the tunnel's `bind_interface`. The zone and the bind
device, when both are given, MUST name the same device, or the zone a
member of the bind VRF ([K27](kernel.md#facts)); otherwise the entry has
a hard mistake. Connecting to such a peer binds the socket to the zone's
device ([K27](kernel.md#facts)): on a VRF-bound tunnel the binding is
then the member device, and the daemon records that index as the
binding in force until the next reconnect restores the configured one.
An unbound tunnel with a link-local literal without a zone is a hard
mistake ([C7](configuration.md#tunnel-entries)); an answer of a resolver
that is a link-local address without a zone on an unbound tunnel is
unusable ([V5](resolvers.md#queries-and-answers)).

## Peer changes

T28. Every peer change, whatever its cause (a reload, a resolver answer,
leaving the disconnected state, a corrected endpoint), is a reconnect
([T21](#source-addresses)): never a bare connect. The source address the
daemon records for a tunnel ([E7](events.md#address-events)) is read from
the socket only after such a reconnect, because after a bare connect the
socket reports a stale source ([K24](kernel.md#facts)).

T29. The kernel's record of a disconnected tunnel shows the previous peer
and an empty source ([K25](kernel.md#facts)); the daemon's own view, not
the kernel's, says whether a tunnel is connected
([O9](observability.md#state-visible-on-the-host)).
