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

Readiness depends on no route, address or DNS: a tunnel that cannot reach
its peer when it is created is created disconnected and its peer is
retried, so a routing daemon that itself waits for `network-online.target`
causes no startup cycle.

## Readiness

Readiness means that every tunnel and session of the applied configuration
exists in the kernel: tunnels connected or not, sessions under their
configured name or still under their temporary name. The daemon
double-forks. The parent exits 0 and the PID file (`-p`, default
`/run/rs-l2tpd.pid`) is published only after readiness. With the supplied
systemd unit, this also releases `network-online.target`. Kernel creation
failures are retried every second until then. Readiness is reported once
and never revoked.

Readiness does not wait for a host name to resolve, a route to a peer, a
source address, an absent bind device, IPv6, a session's publication under
its configured name, or a MAC change deferred because another manager
activated the interface (see the
[MAC activation race](sessions.md#hardware-addresses)). It may wait for
the bounded retries of [identifiers held elsewhere](#identifiers-in-use),
at most ten seconds, run alongside everything else, and for a kernel that
cannot create the objects at all.

## Peers that cannot be reached yet

A tunnel without a peer it can reach is **disconnected**: its socket is
bound but not connected, the tunnel and its sessions exist, and the kernel
drops whatever the sessions send. No discard address, device or route is
involved. This covers a host name that has not resolved, an unusable
endpoint, an absent bind device, and a peer the kernel refuses to connect
to for want of a route or a source address. The peer is tried again every
second until it is reached; the wait and the success are each logged once.

A peer change, by reload or by a new resolver answer, to an address that
cannot be reached leaves the tunnel disconnected with the new peer
pending, never connected to a peer the configuration or the resolver no
longer names. An answer of the other family than `ip_version` is never
used.

Host names are looked up every thirty seconds, and at once when the
tunnel's or its resolver's configuration changes, by the system resolver
or by the tunnel's configured resolver (`resolver_name`). A resolver that
fails keeps the last answer in force: a resolver outage never disconnects
a working tunnel.

## Binding and source selection

Each tunnel uses one dual-stack socket, so its peer can change between
IPv4 and IPv6 without recreating the tunnel or its sessions. Sockets bind
to `::`; tunnels need no address of their own. On a kernel without IPv6
(`ipv6.disable=1`), where no such socket can be opened, tunnels use
`AF_INET` sockets with native IPv4 endpoints instead; they can then have
no IPv6 peer. The choice is made again at every tunnel creation. A host
whose IPv6 is merely unconfigured or disabled with sysctls keeps the
dual-stack socket.

A configured interface or VRF name selects the bind device; the name is
authoritative. The daemon resolves it to an index and binds the socket to
that index. When the device is renamed away, removed, or not created yet,
the tunnel is disconnected, so that nothing leaves through another device,
and it is bound and connected again once a device of the configured name
exists, including a replacement under the same name. A changed
`bind_interface` is applied by a reconnect, keeping the tunnel and its
sessions.

The kernel keeps a socket's source address from the connect until a
disconnect, even after the address is removed. The daemon therefore
reconnects (disconnect, bind, connect: never a bare connect) whenever the
right source may have changed: a bound tunnel on address changes of its
device or of a member of its VRF and on VRF membership changes; an unbound
tunnel when the address it selected is removed, whatever interface it was
on; every connected tunnel when the netlink monitor lost events. A
reconnect that fails, or leaves the socket without a source, leaves the
tunnel disconnected and is retried a second later.

The event monitor subscribes to link and address notifications only,
never to route notifications, and attaches a socket filter that the kernel
runs before queueing a notification, so that unrelated churn neither
fills the buffer nor costs the daemon anything. Both netlink monitors
request 8 MiB receive buffers before subscribing. Linux accounts twice the
requested size, allocated as messages arrive. A per-socket override is
attempted when the ordinary request is clamped; if the kernel denies it,
the daemon continues with the available buffer. This changes no global
kernel setting. Buffers remain finite: a lost notification causes a
resync, and loss of link-lifetime notifications has the
[session-management limits](sessions.md#child-interfaces-and-other-managers)
described separately.

## Hosts with bindv6only

With `net.ipv6.bindv6only=1`, every new IPv6 socket is IPv6-only, which
silently stops IPv4 peers on dual-stack sockets. By default
(`[host] fix_bindv6only = true`) the daemon keeps the setting at 0 in its
own network namespace for its lifetime: it reads `IPV6_V6ONLY` back from
every new socket, and when it finds it set, logs a warning with the
previous value, writes 0 and creates the socket again. This is the only
kernel setting the daemon changes. With `fix_bindv6only = false`, or when
the write fails, IPv4 tunnels get `AF_INET` sockets instead and cannot
move to IPv6 in place.

## Identifiers in use

The kernel refuses a tunnel or session whose identifiers another tunnel or
session on the host holds (`EEXIST`, or `EADDRINUSE` for the tunnel's
connection identifier). A refusal is retried every second up to ten
attempts, which covers a session or tunnel deleted a moment ago; every
other entry is applied meanwhile. Then the entry is left out, with a
warning, so that readiness is not held up by it. A left-out tunnel takes
its sessions with it. Left-out entries are tried again every thirty
seconds and on every reload, and created as soon as their identifiers are
free, which is logged.

## Reload and shutdown

`SIGHUP` reloads the configuration; several `SIGHUP`s before the daemon
acts cause one reload. `SIGTERM` and `SIGINT` request shutdown, which
deletes the sessions the daemon can prove it owns, then closes each
tunnel's socket and waits up to two seconds for the tunnel to leave the
kernel, then removes the PID file. See
[configuration](configuration.md#mistakes) for what a failed reload
preserves.

## Restart

`SIGUSR2` restarts the daemon without re-creating its tunnels: it executes
the binary on disk again in the same process, with the same PID and PID
file, handing its tunnel sockets to the new program, which verifies and
adopts them and reads the configuration afresh. If the new binary cannot
be executed, the old one keeps running. Under systemd the daemon can also
keep its sockets in the service's descriptor store, so that tunnels
survive an unplanned exit too; it speaks that protocol itself and needs
no systemd library. An ordinary stop still removes everything.

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
warns when other users could replace the file. It remembers the inode it
published and, at shutdown, removes the file only if it is still that
inode. If the file cannot be published, the daemon reports it and keeps
running; readiness is still reported.

In a directory it cannot write to, a precreated file is updated in place
if the daemon user owns it and it has one link and no group or other write
permission. This supports capability-based services with a file in `/run`.
