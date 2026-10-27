# Hosts

[Specification index](README.md)

What the daemon must do on hosts that differ from the simple dual-stack
server with a default route. Each condition is a combination of the rules
of the other pages; this page states the outcome the operator can expect.

## Address families

H1. **A dual-stack host**: every tunnel on an `AF_INET6` socket; IPv4
peers as mapped addresses; discard addresses routed by the default routes.

H2. **An IPv4-only host** (IPv6 stack present, no IPv6 address or route):
`AF_INET6` sockets still; IPv4 tunnels work as usual and use `192.0.0.8`
when they need a discard address; an IPv6 tunnel cannot reach any peer,
sits on a discard address (its own family's after the grace through the
null device, which gets a link-local address and so a source, or the IPv4
one), and its sessions exist. No IPv6 configuration is required of the
operator.

H3. **IPv6 disabled by sysctl** (`disable_ipv6=1` on all and default):
`AF_INET6` sockets can still be opened and carry IPv4; no IPv6 route can be
installed on any device and no IPv6 source exists, so `100::` cannot be
used: every tunnel without a peer uses `192.0.0.8`, IPv6 peers are pending
forever and reported once. The failure to install the IPv6 discard route
is reported once, never retried loudly. Everything IPv4 works.

H4. **IPv6 absent from the kernel** (`ipv6.disable=1`, or built without
IPv6): `AF_INET` sockets with IPv4 forms throughout ([T4](tunnels.md#address-families));
IPv6 peers are impossible, treated as unreachable, never given to the
kernel; everything IPv4 works.

H5. **An IPv6-only host**: the mirror image of H2; `192.0.0.8` is routed
through the null device when needed and a tunnel on it has an unspecified
IPv4 source, which suffices for frames that are dropped.

H6. **A host without any route** (an isolated namespace, a host at boot
before routing is configured): every tunnel is created on a discard
address once the grace period has passed and the null device routes it;
real peers are pending and connected as soon as routes appear; readiness
is reached after at most ten seconds per family in use.

## VRFs

H7. A tunnel bound to a VRF sends and receives through the VRF's table.
Its source is selected from the VRF's members; a member's address change
or a membership change refreshes it. A VRF replaced under the same name
with another index or table is rebound to and its discard route moved to
the new table. A VRF with an unreachable default route, the usual setup,
gets its discard route in its own table through the null device, which
need not be a member. Controllers that are not VRFs (bridges, bonds) do not
select a table and are never mistaken for one.

## Routers

H8. A router with large routing tables, or with routes that change
constantly, MUST NOT cost the daemon anything: route notifications other
than the removal of a discard route are dropped in the kernel before they
reach the daemon's buffer. A router whose own discard route (through a
default route) comes and goes causes no reconnection: only the daemon's
installed routes are repaired.

## Containers and namespaces

H9. The daemon works in a network namespace that is not the initial one
(a system container such as Incus, LXD or a Docker container), with the
L2TP modules loaded by the host, `CAP_NET_ADMIN` and `CAP_NET_RAW`, and
procfs mounted. The socket filter needs no capability and no `bpf()`
syscall, so it works under the containers' seccomp and user namespaces.
In a user namespace the kernel autoloads no module; the modules are the
host's to load.

H10. Session devices may have children moved into other namespaces by a
container manager; every in-place operation keeps them, and only an
explicit removal, a necessary re-creation or a shutdown removes them with
the parent ([S18](sessions.md#children-and-other-managers)). A session
device itself moved out of the daemon's namespace is an observed removal:
the daemon leaves it alone, skips changes to it, and never deletes it
through its identifiers.

## Other network managers

H11. **systemd-networkd and udev** may rename session devices, match them
by type or hardware address, bring them up, assign addresses and routes,
attach children and remove the daemon's discard routes. The daemon follows
devices by index, never lowers a device another manager brought up, defers
hardware-address changes until the device is down, publishes a staged
device under its configured name even when a manager already configured
it, and repairs its discard routes. A manager that needs a particular
hardware address before activation must match the configured name, not
the temporary device; the race is the kernel's and documented.

H12. **Another L2TP user** (a second daemon, `ip l2tp`, a tool holding a
tunnel or session identifier) makes the daemon's entries conflicts
([T25](tunnels.md#identifier-conflicts)); the foreign objects are never
modified. A foreign device holding a configured interface name delays
publication of the daemon's session, which keeps its temporary name
meanwhile; the foreign device is never touched.

H13. **Hot-plugged and replaced devices** (a USB NIC, a recreated bridge or
VRF) are followed by name: unplugging forgets the binding, plugging binds
and reconnects, a replacement under the same name is rebound to.

## Address churn

H14. Router advertisements, privacy addresses, DHCP renewals and temporary
addresses change addresses often. Only tunnels bound to the device
concerned, of the family concerned, are reconnected; unbound tunnels only
when their own source goes; tunnels without a peer never. A reconnect is a
disconnect and a connect on the same socket, which loses no session and
no interface, and a failed one is retried once a second until it succeeds.

## Missing kernel support and privilege

H15. Without the L2TP modules, without `CAP_NET_ADMIN`, or without netlink,
the daemon cannot create the interfaces the network depends on: it reports
the condition once, retries every second, and withholds readiness, because
readiness would be a lie; it never exits. Without `CAP_NET_RAW` device
binding fails; the tunnel is created unbound and the failure reported.
Without procfs the current library dependency cannot determine the
namespace and the daemon reports it at start-up.

## Clocks

H16. Nothing depends on the wall clock. Timers use a monotonic clock and
survive clock jumps, suspend and resume; a resume is followed by the
host's own link and address events, which the daemon handles as usual, and
by a resync if the subscriptions overflowed meanwhile.

## Scale

H17. Hundreds of tunnels and sessions MUST work. The cost of a kernel
event is bounded by the entries it concerns ([M16](model.md#scale)); the
cost of a reconcile is linear in the configuration; no operation dumps all
interfaces except seeding a reopened subscription.
