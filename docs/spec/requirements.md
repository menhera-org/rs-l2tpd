# Requirements

[Specification index](README.md)

What the daemon requires of its host, its operator, its peers, the other
network managers on the host and the programs that embed the library.
The [promises](promises.md) hold when these requirements are met. When one
is not met, the daemon keeps its unconditional promises all the same
([G1–G14](promises.md#unconditional-promises)) and behaves as the last
column of each table says; nothing here is a condition it may crash,
exit or misbehave under. The kernel requirements are stated precisely on
the [kernel page](kernel.md#requirements); the rows below summarise them.

## The host

| | Requirement | When not met |
|---|---|---|
| R1 | Linux with L2TPv3 over IP and Ethernet pseudowires: `l2tp_core`, `l2tp_netlink`, `l2tp_ip`, `l2tp_eth`, loaded or loadable on demand ([K1–K3](kernel.md#requirements)); `l2tp_ip6` as well whenever a tunnel has an IPv6 peer or IPv4 peers ride on `AF_INET6` sockets ([K4](kernel.md#requirements)). A kernel of the verified range ([kernel](kernel.md)). | Host defect: reported once, retried every second, readiness withheld ([H15](hosts.md#missing-kernel-support-and-privilege)). Without `l2tp_ip6` only, `AF_INET` sockets are used ([T4](tunnels.md#address-families)). |
| R2 | Removed. No null device, no `dummy` driver and no route is needed ([discard](discard.md)). | — |
| R3 | `CAP_NET_ADMIN` in the daemon's network namespace ([K8](kernel.md#requirements)). | Host defect, as R1. |
| R4 | `CAP_NET_RAW` in the daemon's network namespace, always ([R49](#the-host), [K39](kernel.md#requirements)). The daemon uses it: a resolver with `method = "ra"` or `"ipv6"` receives and solicits router advertisements from a raw ICMPv6 socket ([V10](resolvers.md#router-advertisements)), and the kernel accepts a device binding on a socket that already has one ([K22](kernel.md#facts)). | Reported at start-up ([R49](#the-host)). Fallbacks, not guaranteed to work in every case: a router-advertisement resolver learns servers only through `RTNLGRP_ND_USEROPT`, which works only where `accept_ra` is enabled ([K40](kernel.md#facts)), and its tunnels stay disconnected otherwise; a binding is changed only after the disconnect that clears it ([T21](tunnels.md#source-addresses)). Readiness is not withheld. |
| R5 | `NETLINK_ROUTE` and `NETLINK_GENERIC` sockets, with the link and address multicast groups ([K7](kernel.md#requirements)) and the `l2tp` generic-netlink group ([K41](kernel.md#facts)); the `RTNLGRP_ND_USEROPT` group only for the fallback of a resolver using router advertisements (`ra` or `ipv6`) without `CAP_NET_RAW`, on a socket of the resolver's own ([K14](kernel.md#requirements)). No route group. | Host defect, as R1. |
| R6 | Permission to attach a classic BPF socket filter (`SO_ATTACH_FILTER`, [K10](kernel.md#requirements)). | The monitor runs without the filter, with a warning; unrelated link and address events then cost buffer space and may cause resyncs, never failures ([E20](events.md#monitor-loss)). |
| R7 | Removed. `l2tp` 0.4.1 identifies namespaces by `SO_NETNS_COOKIE` and needs no `/proc`; the daemon reads `/proc` only for the host tunable write of [P25](process.md#host-tunables), whose failure is handled there. | — |
| R8 | A monotonic clock. | Not met on no supported host. |
| R9 | One socket descriptor per tunnel plus a constant, within the process limit. | Tunnel creation fails with `EMFILE`; transient, retried. |
| R10 | Receive-buffer memory for three netlink subscriptions (the event monitor, the lifetime subscription and the `l2tp` group): 8 MiB requested for each, which the kernel doubles to 16 MiB ([K36](kernel.md#facts)), requested with `SO_RCVBUFFORCE` and, when that is refused (it needs `CAP_NET_ADMIN` in the initial user namespace, [K36](kernel.md#facts)), with `SO_RCVBUF`, which the host caps at `net.core.rmem_max`; inside a user-namespaced container the cap is what the daemon gets. | Smaller buffers overflow sooner under bursts, which costs a resync ([E20](events.md#monitor-loss)), never a failure. |
| R11 | The daemon's own network namespace holds the bind devices, the session devices and the resolvers' bind devices it is configured for. | Objects in other namespaces are out of reach: a device moved out is an observed removal ([S19](sessions.md#identity-loss)). |
| R12 | An init system that treats the parent's exit as readiness and starts the daemon before anything that needs its interfaces, through the [process contract](process.md#the-process-contract); with systemd, the supplied unit ([P21](process.md#the-supplied-systemd-unit)). | Readiness means nothing to the rest of the boot; the daemon still works. |
| R43 | Nothing of the filesystem layout besides the daemon's own files is needed (`/sys` is never read; `/proc/sys` only for the tunable write of [P25](process.md#host-tunables), [P23](process.md#the-process-contract)); no systemd, no freedesktop.org layout, no particular libc ([P22–P24](process.md#the-process-contract)). | Not a condition: the daemon does not depend on any of them. |
| R44 | `net.ipv6.bindv6only = 0` in the daemon's namespace, while IPv4 peers ride on `AF_INET6` sockets ([K11](kernel.md#requirements)); the daemon sets it itself unless the operator opted out ([T26](tunnels.md#hosts-with-bindv6only), [P25](process.md#host-tunables)). | With the opt-out, IPv4 peers get `AF_INET` sockets ([T26](tunnels.md#hosts-with-bindv6only)). |
| R45 | VRF support in the kernel, when a tunnel's `bind_interface` names a VRF ([K9](kernel.md#requirements)). | The name is an ordinary device to the kernel: the binding applies, the VRF semantics of [H7](hosts.md#vrfs) do not. |
| R46 | `CAP_NET_BIND_SERVICE` in the daemon's network namespace, always ([R49](#the-host), [K13](kernel.md#requirements)): a `dhcpv6` resolver, and an `ipv6` one for its DHCPv6 half, binds UDP port 546. | Reported at start-up ([R49](#the-host)). Fallback, not guaranteed to work in every case: the port can be bound only where `ip_unprivileged_port_start` is at or below 546; where it is not, a `dhcpv6` resolver is reported once as a host defect and its tunnels stay disconnected, and an `ipv6` resolver uses its router-advertisement servers ([V12](resolvers.md#dhcpv6-information-request), [V14](resolvers.md#the-unified-ipv6-method)). Readiness is not withheld. |
| R49 | Every capability the daemon needs for healthy operation is required: `CAP_NET_ADMIN` ([R3](#the-host)), `CAP_NET_RAW` ([R4](#the-host)) and `CAP_NET_BIND_SERVICE` ([R46](#the-host)). What the daemon does without one is a fallback: available, but not guaranteed to work correctly in every case. | At start-up, before readiness, the daemon determines which required capabilities its process holds and reports each missing one prominently: once, at warning level, naming the capability and what degrades without it ([O2](observability.md#logging)). It then runs with the fallbacks and never fails or exits because of a missing capability ([G1](promises.md#unconditional-promises)); without `CAP_NET_ADMIN` that is the host defect of [H15](hosts.md#missing-kernel-support-and-privilege). |

Nothing else is required of the host at start-up: no address, no route,
no DNS, no IPv6, no bind device, no peer.

## The operator

| | Requirement | When not met |
|---|---|---|
| R13 | Configuration files in UTF-8 TOML at the documented paths, readable by the daemon user. | Lenient handling: the file is left out at start-up, the previous configuration kept on reload ([C3](configuration.md#files)). |
| R14 | Tunnel identifiers unique in the namespace, session identifiers unique in the namespace across all tunnels, interface names unique in the namespace, all agreed with the peer ([K19](kernel.md#facts)). | Within the configuration: the later entry is left out ([C9](configuration.md#tunnel-entries)). Against the namespace: a conflict, retried and then left out ([T25](tunnels.md#identifier-conflicts)). Against the peer: frames are silently dropped by the kernel; the daemon cannot tell. |
| R15 | Cookies set on both ends when wanted, this end's `cookie` being the peer's `peer_cookie`. Cookies are the only admission control the kernel offers for data ([K15](kernel.md#facts)); anything else is the host's packet filter. | Frames dropped by the kernel; not detectable by the daemon. |
| R16 | Host names resolvable eventually from the daemon's namespace. For system DNS, libc calls eventually return so V15's bounded workers can admit new work; configured DNS has its own budget. | A tunnel without an answer stays disconnected; an existing answer is retained (V6). Stalled libc calls may exhaust the system budget, reported once; they do not block configured DNS, readiness or shutdown. |
| R17 | Managed tunnels are never deleted or replaced in the kernel by hand. | Unsupported: the daemon's only duty is not to delete the replacement ([T9](tunnels.md#creation-and-identifiers)). |
| R18 | Managed sessions are removed through the configuration, not by hand. | The session is created again ([S27](sessions.md#external-deletion)). |
| R19 | No foreign device is named `rsl2tp-t*` or `rsl2tp-r*`. | The daemon picks the next free name; a foreign device under such a name is never touched. |
| R20 | Removed (there is no discard address to route). | — |
| R21 | One instance per network namespace for a given set of identifiers, each with its own PID file path ([P20](process.md#concurrent-instances)). | Conflicts, as R14. |
| R22 | The daemon is stopped through its signals or control handle. | A kill leaves nothing behind: the kernel removes tunnels and sessions with the sockets ([P18](process.md#crashes)). |
| R23 | The daemon is not expected to re-assert a hardware address another manager changed afterwards, nor to bring a device up, nor to address it. | Not a failure: those are the manager's and the operator's ([S2](sessions.md#the-right-state-of-a-session), [S12](sessions.md#hardware-addresses)). |
| R47 | A link-local IPv6 peer is configured on a tunnel with a `bind_interface`, or with a zone (`fe80::1%eth0`). | A hard mistake of the entry ([C7](configuration.md#tunnel-entries), [T27](tunnels.md#link-local-peers)). |

## The peers

| | Requirement | When not met |
|---|---|---|
| R24 | An L2TPv3 implementation using IP encapsulation (IP protocol 115), Ethernet pseudowires, static tunnels without a control connection, no sequencing and no layer-2-specific sublayer. | Frames are not understood by one side or the other; the daemon exchanges no control messages and cannot tell. |
| R25 | Identifiers and cookies mirrored: our `tunnel_id` is their `peer_tunnel_id`, our `session_id` their `peer_session_id`, our `cookie` their `peer_cookie`, and the reverse. | As R14 and R15. |
| R26 | IP protocol 115 allowed both ways on the path, and a route with a source address of the peer's family on this host. | The tunnel stays disconnected until a route and a source exist ([T16](tunnels.md#peers-that-cannot-be-reached)); a blocked path is invisible to the daemon. |
| R27 | On a host without `AF_INET6` sockets, IPv4 peers only. | An IPv6 peer stays disconnected for as long as the host stays so, reported once ([T4](tunnels.md#address-families)). |

## Other network managers

What systemd-networkd, udev, container managers and similar tools may do
to the daemon's objects, and what the daemon then does.

| | Allowed | The daemon's response |
|---|---|---|
| R28 | Rename a session device at any time, including immediately after creation. | Follows the device by index; accepts the name ([S10](sessions.md#names)). |
| R29 | Bring a session device up or down, add addresses and routes, set its MTU, change its hardware address after the daemon's. | Never undone; a configured hardware-address change waits for the device to be down ([S12](sessions.md#hardware-addresses)). |
| R30 | Attach children of any kind, in this or another namespace; move children elsewhere. | Kept through every in-place operation ([S18](sessions.md#children-and-other-managers)). |
| R31 | Move a session device to another namespace. | Treated as an observed removal: left alone, changes to it skipped once with a report, never deleted by identifier ([S19](sessions.md#identity-loss)). |
| R32 | Removed (no routes of the daemon's exist). | — |
| R33 | Removed (no null device exists). | — |
| R34 | Create, delete, rename or replace bind devices and VRFs at any time. | Bindings follow the configured name ([T10–T13](tunnels.md#bind-devices)). |
| R35 | Flood the host with link, address and route changes. | Route changes are not subscribed to and cost nothing; link and address bursts cost at most a resync ([E20](events.md#monitor-loss)). |
| R36 | Match the temporary device of a staged session and configure it. | The device keeps the manager's state; the address change is deferred; the device is published under its name as it is ([S5](sessions.md#creation)). |
| R48 | Change `net.ipv6.bindv6only` while the daemon runs. | With the option on, the daemon sets it back to 0 when it notices ([P25](process.md#host-tunables)); with the opt-out, new IPv4 tunnels get `AF_INET` sockets ([T26](tunnels.md#hosts-with-bindv6only)). |

What they must not do is in the operator's list: delete managed sessions
or tunnels (R17, R18), take the daemon's names (R19) or its identifiers
(R14).

## Programs embedding the library

| | Requirement | When not met |
|---|---|---|
| R37 | A Tokio runtime for `Service` and `Runtime`, or `blocking::Service` without one. | The constructors fail outside a runtime. |
| R38 | The capabilities and kernel support of the host section. | As for the daemon. |
| R39 | Every `ControlEvent` handed to `Runtime::handle_event`, in order ([L10](library.md#the-reconciler)). | A dropped event leaves the kernel state stale until the next event of the same kind or a resync. |
| R40 | `shutdown` called before dropping a `Runtime` for an orderly teardown. | Dropping tears tunnels down by closing their sockets, without the ordered deletions ([L9](library.md#the-reconciler)). |
| R41 | A `log` sink, when messages are wanted. | Messages are dropped by the facade. |
| R42 | No two `Runtime`s with overlapping identifiers in one namespace. | Conflicts, as R14. |
