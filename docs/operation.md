# Readiness, reconnection and routing

[Documentation index](README.md)

## Early-start contract

Early startup is a compatibility contract. A ready network stack may depend
on the session interfaces rs-l2tpd creates. The daemon **MUST** support
starting before that stack is ready, and **MUST NOT** depend on
`network-online.target`, wait-online services, complete DNS setup or peer
reachability before creating the usable session interfaces. This requirement also applies to
packaging, service ordering and future changes to readiness.

The kernel prerequisites below still apply; they must not become a general
requirement for an already-ready network. Maintainers must preserve the
[startup invariants and checks](testing.md#startup-invariants).

The supplied systemd unit expresses this with `Before=network-online.target`,
`RequiredBy=network-online.target` and `Type=forking`. It makes the daemon's
kernel-resource readiness a prerequisite for network readiness, while
allowing the rest of network configuration to proceed.

Readiness depends on no route to any peer: a literal peer that cannot be
reached when its tunnel is created gets a discard address meanwhile and is
retried, so a routing daemon that itself waits for `network-online.target`
causes no startup cycle.

## Readiness

Readiness means that every tunnel and session of the applied configuration
exists in the kernel, including those connected to a discard address.
The daemon double-forks. The parent exits and the PID file
(`-p`, default `/run/rs-l2tpd.pid`) is published only after readiness.
With the supplied systemd unit, this also releases `network-online.target`.
Kernel creation failures are retried every second until then.

A MAC change deferred because another manager activated the interface does
not delay readiness. See the [MAC activation race](sessions.md#hardware-addresses)
when a particular MAC is required before activation.

Readiness does not wait for a host name to resolve, for an absent bind
device to appear, or for a route to a literal peer. It does wait for the
null device's grace period on a host that routes no discard address, and
for [identifiers held elsewhere](#identifiers-in-use) to be given up on.

## Peers that cannot be reached yet

A literal peer, or a resolved one, that the kernel cannot connect to, for
want of a route, a source address or a usable family, does not fail the
configuration. The tunnel is connected to the discard address of its
family instead, so that its sessions exist, and the peer is tried again
every second until it is reached; both the wait and the success are logged
once. A peer update to such an address behaves the same way: the tunnel
moves to the discard address, never staying with a peer the configuration
no longer names. A resolved address that cannot be reached keeps the
tunnel on its previous address of the same host name.

## Binding and source selection

Each tunnel uses one dual-stack socket, so its peer can change between
IPv4 and IPv6 without recreating the tunnel or its sessions. Sockets bind
to `::`; tunnels need no address of their own. On a kernel without IPv6
(`ipv6.disable=1`), where no such socket can be opened, tunnels use
`AF_INET` sockets with native IPv4 endpoints instead; they can then have
no IPv6 peer, and an IPv6 peer is treated as unreachable. A host whose IPv6
is merely unconfigured or disabled with sysctls keeps the dual-stack
socket.

A configured interface or VRF name selects the bind device. Rebinding
resolves that name immediately before use, including when the original
device was replaced under the same name. Source addresses are refreshed
after relevant IPv4 and IPv6 address changes, including changes on VRF slaves.
An unbound tunnel is reconnected when the address it selected as its source
is removed, whatever interface it was on: the kernel would otherwise keep
sending from the removed address. If the netlink monitor loses events, a
resync rereads current bindings and refreshes every tunnel's source.

Both netlink monitors request 8 MiB receive buffers before subscribing to
events. Linux accounts twice the requested size, allocated as messages
arrive. A per-socket override is attempted when the ordinary request is
clamped; if the kernel denies it, the daemon continues with the available
buffer. This changes no global kernel setting and adds no mandatory
capability. Indexed session checks also avoid repeated full-interface dumps.
The event monitor also attaches a socket filter that the kernel runs
before queueing a notification: route notifications, the bulk of what a
router produces, are dropped there unless they remove a discard route, so
routing-table churn neither fills the buffer nor costs the daemon
anything. Buffers remain finite: loss of link-lifetime notifications has
the [session-management limits](sessions.md#child-interfaces-and-other-managers)
described separately from source-address resynchronization.

When a tunnel gets a real peer after a discard peer, its source is selected
again through its configured bind device, including when both peers use
IPv6.

## Discard peers and last-resort routes

A tunnel without a peer yet, because its host name has not resolved, its
endpoint is unusable or its peer cannot be reached, connects to the discard
address of its family: `100::` for IPv6, `192.0.0.8` (the IPv4 dummy
address of RFC 7600) for IPv4. Its frames are discarded until it gets a
peer. Connecting there needs a route, but no reachability. When the
family's discard address cannot be connected to, as `100::` cannot on a
host with IPv6 disabled, the other family's is used instead.

When the host already routes the address, for example through a default
route, that route is used. Otherwise, as on an IPv4-only host or in a VRF
with an unreachable default route, the daemon waits ten seconds, per
address family, for a route to appear. Only then does it create a null
device, a `dummy` link that drops whatever it transmits, and route
`100::/128` or `192.0.0.8/32` to it in the relevant table. Blackhole and unreachable routes refuse the
connection outright and cannot serve this purpose. Nothing is routed
through loopback.

The null device is created only when needed. Its name is `rsl2tpnull0`,
or another unused `rsl2tpnullN` if that name is occupied. Existing devices
are not adopted.

The daemon monitors removal of these fallback routes and restores them,
including after systemd-networkd reloads or restarts with
`ManageForeignRoutes=yes`. It retries while a routing context is unavailable
and resolves a recreated VRF by its configured name and current table; a
lasting failure is reported once, not every second. Installation and
restoration preserve existing routes at the same prefix and metric,
including reject routes.

Only fallback `100::/128` and `192.0.0.8/32` routes through the daemon's
own last-resort dummy devices are managed. Shutdown stops restoration and
removes only null devices created by this daemon whose ownership still
matches, and their routes. Existing devices and replacements under the
same name are left alone.

## Identifiers in use

The kernel refuses a tunnel or session whose identifiers another tunnel or
session on the host holds (`EEXIST`, or `EADDRINUSE` for the tunnel's
connection identifier). A refusal is retried every second ten times, which
covers a session deleted a moment ago, then the entry is left out, with a
warning, so that readiness and every other entry are not held up by it.
A left-out tunnel takes its sessions with it. Left-out entries are tried
again every thirty seconds and on every reload, and created as soon as
their identifiers are free.

## Reload and shutdown

`SIGHUP` reloads configuration. `SIGTERM` and `SIGINT` request shutdown,
which removes the daemon's tunnels and sessions and cleans up its owned
null devices. See [configuration](configuration.md#mistakes) for what a
failed reload preserves.

## Ownership of kernel tunnels

Do not externally delete or replace a tunnel while rs-l2tpd manages it.
Stop the daemon before such administrative changes. The kernel creates a
session using only its parent's numeric tunnel ID and exposes no reliable
way to verify that the current tunnel still belongs to the daemon's
original socket. If another process deletes that tunnel and reuses its ID,
a later reload adding sessions can attach them to the replacement. This
case is unsupported; closing the daemon's own socket protects shutdown
cleanup but cannot protect a subsequent ID-based creation request.

This restriction concerns kernel tunnel objects. Supported interface
renames, child interfaces and child namespace moves are described under
[session lifecycles](sessions.md#child-interfaces-and-other-managers).

## PID files

The PID file is published as a fresh inode owned by the daemon user,
replacing a legacy file atomically. Its directories must be owned by root
or the daemon user. The daemon never changes their permissions and only
warns when other users could replace the file.

In a directory it cannot write to, a precreated file is updated in place
if the daemon user owns it and it has one link and no group or other write
permission. This supports capability-based services with a file in `/run`.
