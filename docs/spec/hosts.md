# Hosts

[Specification index](README.md)

What the daemon must do on hosts that differ from the simple dual-stack
server with a default route. Each condition is a combination of the rules
of the other pages; this page states the outcome the operator can expect.

## Address families

H1. **A dual-stack host**: every tunnel on an `AF_INET6` socket; IPv4
peers as mapped addresses; a tunnel without a reachable peer is
disconnected and nothing else exists for it.

H2. **An IPv4-only host** (IPv6 stack present, no IPv6 address or route):
`AF_INET6` sockets still; IPv4 tunnels work as usual; an IPv6 tunnel
cannot reach any peer (`EADDRNOTAVAIL`, [K34](kernel.md#facts)), stays
disconnected, reported once, and its sessions exist. No IPv6
configuration is required of the operator.

H3. **IPv6 disabled by sysctl** (`disable_ipv6=1` on `all` and
`default`): `AF_INET6` sockets can still be opened and carry IPv4; no
IPv6 source exists, so an IPv6 peer fails `EADDRNOTAVAIL` and its tunnel
stays disconnected, reported once. Everything IPv4 works.

H4. **IPv6 absent from the kernel** (`ipv6.disable=1`, or built without
IPv6): `AF_INET` sockets with IPv4 forms throughout
([T4](tunnels.md#address-families)); IPv6 peers are impossible, their
tunnels stay disconnected, reported once; everything IPv4 works.

H5. **An IPv6-only host**: the mirror image of H2. The kernel would
connect an IPv4 peer with the unspecified source `0.0.0.0`
([K34](kernel.md#facts)); such a connect is treated as failed
([T20](tunnels.md#source-addresses)) and the tunnel stays disconnected
until an IPv4 address exists.

H6. **A host without any route** (an isolated namespace, a host at boot
before routing is configured): every tunnel is created disconnected and
every session exists; readiness is reached as soon as the kernel has
created them; real peers are connected as soon as routes appear, by the
one-second retry ([E13](events.md#timers)).

## VRFs

H7. A tunnel bound to a VRF sends and receives through the VRF's table.
Its source is selected from the VRF domain ([K28](kernel.md#facts),
[K34](kernel.md#facts)); a member's address change or a membership change
reconnects it. A VRF replaced under the same name with another index is
rebound to. A VRF with an unreachable default route, the usual setup,
leaves a tunnel whose peer it does not route disconnected. Controllers
that are not VRFs (bridges, bonds) do not select a table and are never
mistaken for one. A tunnel bound to an ordinary device that is a VRF
member is routed in the VRF's table by the kernel ([K28](kernel.md#facts)).

## Routers

H8. A router with large routing tables, or with routes that change
constantly, MUST NOT cost the daemon anything: route notifications are
not subscribed to ([K7](kernel.md#requirements)).

## Containers and namespaces

H9. The daemon works in a network namespace that is not the initial one
(a system container such as Incus, LXD or a Docker container), with the
L2TP modules loaded by the host or loadable on demand, `CAP_NET_ADMIN`,
and procfs mounted. The socket filter needs no capability and no `bpf()`
syscall, so it works under the containers' seccomp and user namespaces.
Module autoload has no namespace gate in the kernel
([K21](kernel.md#facts)); a host may restrict it by policy, in which case
the modules are the host's to load ([R1](requirements.md#the-host)).

H10. Session devices may have children moved into other namespaces by a
container manager; every in-place operation keeps them, and only an
explicit removal, a necessary re-creation or a shutdown removes them with
the parent ([S18](sessions.md#children-and-other-managers)). A session
device itself moved out of the daemon's namespace is an observed removal:
the daemon leaves it alone, skips changes to it, and never deletes it
through its identifiers.

## Other network managers

H11. **systemd-networkd and udev** may rename session devices, match them
by type or hardware address, bring them up, assign addresses and routes
and attach children. The daemon follows devices by index, never lowers a
device another manager brought up, defers hardware-address changes until
the device is down, and publishes a staged device under its configured
name even when a manager already configured it. A manager that needs a
particular hardware address before activation must match the configured
name, not the temporary device; the race is the kernel's and documented.

H12. **Another L2TP user** (a second daemon, `ip l2tp`, a tool holding a
tunnel or session identifier) makes the daemon's entries conflicts
([T25](tunnels.md#identifier-conflicts)); the foreign objects are never
modified. A foreign device holding a configured interface name delays
publication of the daemon's session, which keeps its temporary name
meanwhile; the foreign device is never touched.

H13. **Hot-plugged and replaced devices** (a USB NIC, a recreated bridge or
VRF) are followed by name: unplugging disconnects the tunnels bound to
the device, plugging binds and connects them, a replacement under the
same name is rebound to.

## Address churn

H14. Router advertisements, privacy addresses, DHCP renewals and temporary
addresses change addresses often. Only connected tunnels bound to the
device concerned, of the family concerned, are reconnected; unbound
tunnels only when their own source goes; disconnected tunnels never. A
reconnect is a disconnect and a connect on the same socket, which loses
no session and no interface, and a failed one is retried once a second
until it succeeds.

## Missing kernel support and privilege

H15. Without the L2TP modules, without `CAP_NET_ADMIN`, or without
netlink, the daemon cannot create the interfaces the network depends on:
it reports the condition once, retries every second, and withholds
readiness, because readiness would be a lie; it never exits. No other
capability is needed ([K8](kernel.md#requirements)); a DHCPv6 resolver
without its port permission is reported once and withholds nothing
([V12](resolvers.md#dhcpv6-information-request)). Without procfs the
current library dependency cannot determine the namespace and the daemon
reports it as a host defect.

## Clocks

H16. Nothing depends on the wall clock. Timers use `CLOCK_MONOTONIC`,
survive clock jumps, and do not run while the host is suspended; a resume
is followed by the host's own link and address events, which the daemon
handles as usual, and by a resync if the subscriptions overflowed
meanwhile.

## Scale

H17. Hundreds of tunnels and sessions MUST work. The cost of a kernel
event is bounded by the entries it concerns ([M16](model.md#scale)); the
cost of a reconcile is linear in the configuration; no operation dumps all
interfaces except seeding a reopened subscription.

## Hosts with bindv6only set

H18. On a host with `net.ipv6.bindv6only=1` the daemon sets it to 0 in its
own namespace at start-up and whenever it finds it set again, unless the
operator turned `host.fix_bindv6only` off ([P25](process.md#host-tunables)).
With the option off, IPv4 tunnels get `AF_INET` sockets and IPv6 tunnels
`AF_INET6` ones ([T26](tunnels.md#hosts-with-bindv6only)); every peer
works, and only in-place family moves are lost.

## Non-systemd hosts

H19. The daemon runs under any init system through the process contract
([P22](process.md#the-process-contract)): OpenRC, busybox init, sysvinit,
runit, s6, or a container entry point that starts it and watches the
parent's exit. It needs nothing of the freedesktop.org layout and builds
against musl as well as glibc ([P23–P24](process.md#the-process-contract));
with musl the system resolver reads `/etc/resolv.conf` and `/etc/hosts`
only ([V3](resolvers.md#model)).
