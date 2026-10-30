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

H7. A tunnel bound to a VRF sends through the VRF's table.
This does not isolate received L2TP/IP data: delivery follows session
identifiers and cookies, not the tunnel's binding ([K15](kernel.md#facts)).
Its source is selected from the VRF domain ([K28](kernel.md#facts),
[K34](kernel.md#facts)); a member's address change or a membership change
reconnects it. A VRF replaced under the same name with another index is
rebound to. A VRF with an unreachable default route, the usual setup,
leaves a tunnel whose peer it does not route disconnected. Controllers
that are not VRFs (bridges, bonds) do not select a table and are never
mistaken for one. A tunnel bound to an ordinary device that is a VRF
member is routed in the VRF's table by the kernel ([K28](kernel.md#facts)).

## Routers

H8. The daemon MUST NOT assume a host whose routing is a default route.
No default route, a default route only, specific routes only, policy
routing over several tables and VRFs, and a router in the default-free
zone (DFZ: the full Internet table in each family and no default route)
are all supported alike, because routing
is the kernel's decision at connect time: a peer is reachable exactly
when the kernel accepts the connect ([T16](tunnels.md#peers-that-cannot-be-reached)).
The daemon never reads, dumps, looks up, installs or repairs a route
([kernel](kernel.md#requirements)). A router with large routing tables,
or with routes that change constantly, MUST NOT cost the daemon anything:
route notifications are not subscribed to ([K7](kernel.md#requirements)),
and no cost of the daemon depends on the size of a routing table.

## Containers and namespaces

H9. The daemon works in a network namespace that is not the initial one
(a system container such as Incus, LXD or a Docker container), with the
L2TP modules loaded by the host or loadable on demand and
`CAP_NET_ADMIN`; `/proc` need not be mounted. The socket filter needs no capability and no `bpf()`
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
name, not the temporary device. Matching the name does not order MAC
assignment before activation; the limitation below applies to direct
creation as well.
systemd-networkd processes router advertisements itself and usually
disables `accept_ra` on the interfaces it manages, so the kernel forwards
no RDNSS option for them ([K40](kernel.md#facts)); a resolver using router
advertisements on such an interface receives them from its own raw socket
([V10](resolvers.md#router-advertisements)).

Known limitation of **staged** sessions ([S4](sessions.md#creation): a
configured hardware address, or a configured name held by a foreign
device), verified on 2026-10-30 against systemd 249, 252, 255 and 259:
systemd-networkd before v253 does not re-match `.network` files when a
device is renamed, so where udev is not running (a container whose
`/sys` is read-only, as Docker mounts it; a stock Incus system container
mounts `/sys` read-write and runs udev, verified on Incus 6.0) a
`[Match] Name=` file for the configured name never applies to a staged
device; with udev running, every version re-matches on the `move`
uevent. Hosts with networkd v253
or later (Ubuntu 24.04 and later) are not affected. udev's
`MACAddressPolicy=persistent` derives the address from the name the
device had at its `add` uevent, so a staged device would get an address
derived from its temporary name; staging happens only when a hardware
address is configured, which takes precedence, or when the name is
occupied. Direct creation avoids these temporary-name and rename-rematching
limitations.

**Persistent MAC assignment and activation are separate operations.**
Even for a session created directly under its configured name, networkd
may match its `.network` file and bring it up before udev applies
`MACAddressPolicy=persistent`. The kernel refuses a changed MAC on an
already-up L2TP session with `EBUSY` ([K31](kernel.md#facts)). udev may
therefore leave the kernel-assigned random MAC in place. This outcome
does not prevent networkd from addressing or activating the interface.
The daemon preserves its index, UP state, addresses and manager changes
([G4](promises.md#unconditional-promises)); it neither lowers the device
nor retries udev's MAC policy on udev's behalf.

Where the persistent MAC must be installed before activation, the
operator must arrange for udev to finish while the interface is down,
then allow networkd or another manager to activate it. A configured-name
match alone does not provide that ordering. Successful persistent
assignment is stable for the same machine identity, stable device
identifier (the interface name for these virtual devices) and policy.
Direct creation alone does not guarantee that assignment succeeds, nor
that a kernel-random MAC retained after a race will survive deletion and
re-creation. A temporary creation name or a changed machine identity can
also change the generated persistent value. These are udev policy
limitations; the daemon's separately configured `interface_hwaddr`
continues to follow [S12](sessions.md#hardware-addresses), including
deferral while a manager keeps the device up.

The live acceptance cases cover both contracts: concurrent managers may
produce either successful persistent assignment or the documented
MAC-while-up refusal, with the active interface preserved in either
case; a separately ordered case requires successful persistent
assignment and the same MAC across clean re-creation before subsequent
networkd activation. A passing ordered case is not evidence of an
unconditional persistent-MAC guarantee under concurrent activation.

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

## MTU and fragmentation

H20. **A session device with an MTU equal to or larger than the
underlay's** (an `l2tpeth` at 1500 over a 1500-byte path, or at 9000
over 1500) MUST carry frames in both directions, over IPv4 and over
IPv6 underlays. The kernel fragments every L2TP data frame that exceeds
the path MTU at the sending host and reassembles it at the receiving
host ([K43](kernel.md#facts)); the daemon neither prevents nor helps
this: it sets no MTU on any device and no path-MTU or
don't-fragment option on any socket ([T5](tunnels.md#address-families), the
MTU is the operator's, [R29](requirements.md#the-operator)). 0.1.5
installations run such setups, and a release is accepted only when
this scenario passes on every required kernel
([G22](promises.md#conditional-promises)). Fragmented frames need the
underlay to deliver IP fragments ([R26](requirements.md#the-peers)); a
path that drops them is invisible to the daemon, like any other path
failure.

## Missing kernel support and privilege

H15. Without the L2TP modules, without `CAP_NET_ADMIN`, or without
netlink, the daemon cannot create the interfaces the network depends on:
it reports the condition once, retries every second, and withholds
readiness, because readiness would be a lie; it never exits. The other
required capabilities ([R49](requirements.md#the-host)) degrade rather
than stop, and each missing one is reported once at start-up: without
`CAP_NET_RAW` ([R4](requirements.md#the-host)) a router-advertisement
resolver learns servers only where `accept_ra` is enabled, and a binding
is changed only after a disconnect; without `CAP_NET_BIND_SERVICE`
([R46](requirements.md#the-host)), where the unprivileged port range does
not reach 546, a `dhcpv6` resolver is reported once and withholds
nothing, and an `ipv6` resolver falls back to router advertisements
([V12](resolvers.md#dhcpv6-information-request), [V14](resolvers.md#the-unified-ipv6-method)).
These fallbacks are not guaranteed to work in every case. Without `/proc`
only the tunable write of [P25](process.md#host-tunables) is affected.

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
New tunnels wait at most five seconds for the coalesced correction
handshake before registration; success opens a fresh socket and verifies
the option. With the option off or the correction unsuccessful, IPv4
tunnels get `AF_INET` sockets and IPv6 tunnels `AF_INET6` ones
([T26](tunnels.md#hosts-with-bindv6only)); only in-place family moves are
lost. A late write success does not replace an already registered socket.

## Non-systemd hosts

H19. The daemon runs under any init system through the process contract
([P22](process.md#the-process-contract)): OpenRC, busybox init, sysvinit,
runit, s6, or a container entry point that starts it and watches the
parent's exit. It needs nothing of the freedesktop.org layout and builds
against musl as well as glibc ([P23–P24](process.md#the-process-contract));
with musl the system resolver reads `/etc/resolv.conf` and `/etc/hosts`
only ([V3](resolvers.md#model)).
