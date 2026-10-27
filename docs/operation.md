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

A literal peer still needs an underlay route when its tunnel is created.
Providers of that required route must run concurrently or independently of
rs-l2tpd readiness; making them wait for `network-online.target` would create
a startup cycle.

## Readiness

Readiness means that every tunnel and session of the applied configuration
exists in the kernel, including those connected to the discard address
`100::`. The daemon double-forks. The parent exits and the PID file
(`-p`, default `/run/rs-l2tpd.pid`) is published only after readiness.
With the supplied systemd unit, this also releases `network-online.target`.
Kernel creation failures are retried every second until then.

Readiness does not wait for a host name to resolve or for an absent bind
device to appear. A literal address needs a route when its tunnel is
created, as in 0.1.5, so a literal peer without one delays readiness.

## Binding and source selection

Each tunnel uses one dual-stack socket, so its peer can change between
IPv4 and IPv6 without recreating the tunnel or its sessions. Sockets bind
to `::`; tunnels need no address of their own.

A configured interface or VRF name selects the bind device. Rebinding
resolves that name immediately before use, including when the original
device was replaced under the same name. Source addresses are refreshed
after relevant IPv4 and IPv6 address changes, including changes on VRF slaves.
If the netlink monitor loses events, a resync rereads current bindings and
refreshes bound tunnel sources.

When a tunnel gets a real peer after a discard peer, its source is selected
again through its configured bind device, including when both peers use
IPv6.

## Discard peers and last-resort routes

A tunnel without a peer yet, because its host name has not resolved or its
endpoint is unusable, connects to `100::`. Its frames are discarded until
it gets a peer. Connecting there needs a route, but no reachability.

When the host already routes `100::`, for example through a default route,
that route is used. Otherwise, as on an IPv4-only host or in a VRF with an
unreachable default route, the daemon waits ten seconds for a route to
appear. Only then does it create a null device, a `dummy` link that drops
whatever it transmits, and route `100::/128` to it in the relevant table.
Blackhole and unreachable routes refuse the connection outright and cannot
serve this purpose. Nothing is routed through loopback.

The null device is created only when needed. Its name is `rsl2tpnull0`,
or another unused `rsl2tpnullN` if that name is occupied. Existing devices
are not adopted.

The daemon monitors removal of these fallback routes and restores them,
including after systemd-networkd reloads or restarts with
`ManageForeignRoutes=yes`. It retries while a routing context is unavailable
and resolves a recreated VRF by its configured name and current table.
Installation and restoration preserve existing routes at the same prefix
and metric, including reject routes.

Only fallback `100::/128` routes through the daemon's own last-resort dummy
devices are managed. Shutdown stops restoration and removes only null
devices created by this daemon whose ownership still matches, and their
routes. Existing devices and replacements under the same name are left
alone.

## Reload and shutdown

`SIGHUP` reloads configuration. `SIGTERM` and `SIGINT` request shutdown,
which removes the daemon's tunnels and sessions and cleans up its owned
null devices. See [configuration](configuration.md#mistakes) for what a
failed reload preserves.

## PID files

The PID file is published as a fresh inode owned by the daemon user,
replacing a legacy file atomically. Its directories must be owned by root
or the daemon user. The daemon never changes their permissions and only
warns when other users could replace the file.

In a directory it cannot write to, a precreated file is updated in place
if the daemon user owns it and it has one link and no group or other write
permission. This supports capability-based services with a file in `/run`.
