# Requirements

[Specification index](README.md)

What the daemon requires of its host, its operator, its peers, the other
network managers on the host and the programs that embed the library.
The [promises](promises.md) hold when these requirements are met. When one
is not met, the daemon keeps its unconditional promises all the same
([G1–G14](promises.md#unconditional-promises)) and behaves as the last
column of each table says; nothing here is a condition it may crash,
exit or misbehave under.

## The host

| | Requirement | When not met |
|---|---|---|
| R1 | Linux with L2TPv3 over IP for both families: `l2tp_core`, `l2tp_netlink`, `l2tp_ip`, `l2tp_ip6`, `l2tp_eth`, loaded or loadable on demand. | Host defect: reported once, retried every second, readiness withheld ([H15](hosts.md#missing-kernel-support-and-privilege)). Without `l2tp_ip6` only, `AF_INET` sockets are used ([T4](tunnels.md#address-families)). |
| R2 | The `dummy` driver, on a host that does not route the discard addresses itself. | Tunnels without a reachable peer cannot be created; readiness withheld, reported once. |
| R3 | `CAP_NET_ADMIN` in the daemon's network namespace. | Host defect, as R1. |
| R4 | `CAP_NET_RAW`, when any tunnel has a `bind_interface`. | The tunnel is created unbound and the failure reported; it is bound at the next attempt once the capability is there. |
| R5 | `NETLINK_ROUTE` and `NETLINK_GENERIC` sockets, with the link, address and route multicast groups. | Host defect, as R1. |
| R6 | Permission to attach a socket filter (`SO_ATTACH_FILTER`). | The monitor runs without the filter, with a warning; route churn then costs buffer space and may cause resyncs, never failures. |
| R7 | `procfs` mounted at `/proc`. | Reported at start-up; the current dependency cannot identify the namespace. |
| R8 | A monotonic clock. | Not met on no supported host. |
| R9 | One socket descriptor per tunnel plus a constant, within the process limit. | Tunnel creation fails with `EMFILE`; transient, retried. |
| R10 | Receive-buffer memory for two netlink monitors: 8 MiB each requested, whatever `net.core.rmem_max` allows granted. | Smaller buffers overflow sooner under bursts, which costs a resync ([E20](events.md#monitor-loss)), never a failure. |
| R11 | The daemon's own network namespace holds the bind devices, the session devices and the routing contexts it is configured for. | Objects in other namespaces are out of reach: a device moved out is an observed removal ([S19](sessions.md#identity-loss)). |
| R12 | An init system that treats the parent's exit as readiness and starts the daemon before anything that needs its interfaces. With systemd, the supplied unit ([P21](process.md#the-supplied-systemd-unit)). | Readiness means nothing to the rest of the boot; the daemon still works. |

Nothing else is required of the host at start-up: no address, no route,
no DNS, no IPv6, no bind device, no peer.

## The operator

| | Requirement | When not met |
|---|---|---|
| R13 | Configuration files in UTF-8 TOML at the documented paths, readable by the daemon user. | Lenient handling: the file is left out at start-up, the previous configuration kept on reload ([C3](configuration.md#files)). |
| R14 | Tunnel identifiers unique on the host, session identifiers unique on the host across all tunnels, interface names unique, all agreed with the peer. | Within the configuration: the later entry is left out ([C9](configuration.md#tunnel-entries)). Against the host: a conflict, retried and then left out ([T25](tunnels.md#identifier-conflicts)). Against the peer: frames are silently dropped by the kernel; the daemon cannot tell. |
| R15 | Cookies set on both ends when wanted, this end's `cookie` being the peer's `peer_cookie`. | Frames dropped by the kernel; not detectable by the daemon. |
| R16 | Host names resolvable by the host's resolver from the daemon's namespace, eventually. | The tunnel sits on a discard address until they resolve ([T14](tunnels.md#peers)). |
| R17 | Managed tunnels are never deleted or replaced in the kernel by hand. | Unsupported: the daemon's only duty is not to delete the replacement ([T9](tunnels.md#creation-and-identifiers)). |
| R18 | Managed sessions are removed through the configuration, not by hand. | The session is created again ([S27](sessions.md#external-deletion)). |
| R19 | No foreign device is named `rsl2tpnull*`, `rsl2tp-t*` or `rsl2tp-r*`. | The daemon picks the next free name; a foreign device under an owned name is never touched. |
| R20 | The discard addresses are not routed through a real device unless frames leaving the host that way is intended. | Frames of tunnels without a peer leave through that route; the daemon uses the host's route as it is ([D3](discard.md#addresses)). |
| R21 | One instance per network namespace for a given set of identifiers. | Conflicts, as R14. |
| R22 | The daemon is stopped through its signals or control handle. | A kill leaves null devices and discard routes, foreign at the next start ([P18](process.md#crashes)); tunnels and sessions are removed by the kernel. |
| R23 | The daemon is not expected to re-assert a hardware address another manager changed afterwards, nor to bring a device up, nor to address it. | Not a failure: those are the manager's and the operator's ([S2](sessions.md#the-right-state-of-a-session), [S12](sessions.md#hardware-addresses)). |

## The peers

| | Requirement | When not met |
|---|---|---|
| R24 | An L2TPv3 implementation using IP encapsulation (IP protocol 115), Ethernet pseudowires, static tunnels without a control connection, no sequencing and no layer-2-specific sublayer. | Frames are not understood by one side or the other; the daemon exchanges no control messages and cannot tell. |
| R25 | Identifiers and cookies mirrored: our `tunnel_id` is their `peer_tunnel_id`, our `session_id` their `peer_session_id`, our `cookie` their `peer_cookie`, and the reverse. | As R14 and R15. |
| R26 | IP protocol 115 allowed both ways on the path, and a route with a source address of the peer's family on this host. | The tunnel is pending on a discard address until a route exists ([T16](tunnels.md#peers-that-cannot-be-reached)); a blocked path is invisible to the daemon. |
| R27 | On a host without `AF_INET6` sockets, IPv4 peers only. | An IPv6 peer is pending for as long as the host stays so, reported once ([T4](tunnels.md#address-families)). |

## Other network managers

What systemd-networkd, udev, container managers and similar tools may do
to the daemon's objects, and what the daemon then does.

| | Allowed | The daemon's response |
|---|---|---|
| R28 | Rename a session device at any time, including immediately after creation. | Follows the device by index; accepts the name ([S10](sessions.md#names)). |
| R29 | Bring a session device up or down, add addresses and routes, set its MTU, change its hardware address after the daemon's. | Never undone; a configured hardware-address change waits for the device to be down ([S12](sessions.md#hardware-addresses)). |
| R30 | Attach children of any kind, in this or another namespace; move children elsewhere. | Kept through every in-place operation ([S18](sessions.md#children-and-other-managers)). |
| R31 | Move a session device to another namespace. | Treated as an observed removal: left alone, changes to it skipped once with a report, never deleted by identifier ([S19](sessions.md#identity-loss)). |
| R32 | Remove the daemon's discard routes, recreate a VRF with a new table. | The routes are repaired in the current context ([D11](discard.md#repair)). |
| R33 | Delete a null device. | A new one is created at the next repair; the old one, if it reappears, is foreign. |
| R34 | Create, delete, rename or replace bind devices and VRFs at any time. | Bindings follow the configured name ([T10–T13](tunnels.md#bind-devices)). |
| R35 | Flood the host with link, address and route changes. | Route changes cost nothing; link and address bursts cost at most a resync ([E9](events.md#route-events), [E20](events.md#monitor-loss)). |
| R36 | Match the temporary device of a staged session and configure it. | The device keeps the manager's state; the address change is deferred; the device is published under its name as it is ([S5](sessions.md#creation)). |

What they must not do is in the operator's list: delete managed sessions
or tunnels (R17, R18), take the daemon's names (R19) or its identifiers
(R14).

## Programs embedding the library

| | Requirement | When not met |
|---|---|---|
| R37 | A Tokio runtime for `Service` and `Runtime`, or `blocking::Service` without one. | The constructors fail outside a runtime. |
| R38 | The capabilities and kernel support of the host section. | As for the daemon. |
| R39 | Every `ControlEvent` forwarded, in order, to the handler of its kind ([L10](library.md#the-reconciler)). | A dropped event leaves the kernel state stale until the next event of the same kind or a resync. |
| R40 | `shutdown` called before dropping a `Runtime` for an orderly teardown. | Dropping tears tunnels down by closing their sockets, without the ordered deletions ([L9](library.md#the-reconciler)). |
| R41 | A `log` sink, when messages are wanted. | Messages are dropped by the facade. |
| R42 | No two `Runtime`s with overlapping identifiers in one namespace. | Conflicts, as R14. |
