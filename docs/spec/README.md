# Specification

[Documentation index](../README.md)

This is the normative description of rs-l2tpd: what it requires, what it
promises, how it is built, and what it must do in every condition it can
meet. It is written from the intent behind the [contracts](../contracts.md),
from the kernel's source, and from two audits
([first](../../SPEC_AUDIT_2026-10-27.md), [second](../../SPEC_AUDIT_2026-10-27_2.md)),
not from the code. The implementation is measured against it; where the two
differ the specification is right and the difference is listed under
[known gaps](#known-gaps). Where this specification and
[contracts](../contracts.md) differ, this specification is right.

The words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY have their RFC 2119
meanings. Requirements are numbered per page (R3, G5, A7, M1, T7, ...) so
that tests and changes can cite them. A number is never reused: a rule that
is withdrawn keeps its number and says "removed". Every kernel-dependent
rule cites a fact of the [kernel page](kernel.md), and every claim on every
page is meant to be tested ([contributing](../../CONTRIBUTING.md)).

## Pages

Read the first three for the contract, the rest for the details.

| Page | Letter | Covers |
|---|---|---|
| [Requirements](requirements.md) | R | The conditions under which the daemon is to behave correctly: what it requires of the host, the operator, the peers, other network managers and embedding programs, and what it does when a requirement is not met |
| [Promises](promises.md) | G | What the daemon guarantees: the unconditional safety promises that hold whatever happens, and the conditional promises with their convergence bounds |
| [Kernel](kernel.md) | K | The kernel features and configuration the daemon requires, precisely and minimally, and the kernel facts the other pages rely on, with their sources |
| [Architecture](architecture.md) | A | The components, their responsibilities, the kernel interfaces, the concurrency model and why the design has this shape |
| [Model](model.md) | M | Terms, the reconciliation model, the degradation ladder, ownership, identity, failure classes, timing |
| [Process](process.md) | P | Start-up before the network is ready, readiness, daemonisation, signals, reload, shutdown, restart, crashes, the process contract and the systemd unit |
| [Configuration](configuration.md) | C | Files, merging, every field, every mistake and its effect at start and on reload |
| [Tunnels](tunnels.md) | T | Sockets, address families, bind devices, peers, source addresses, the disconnected state, reconnection, conflicts |
| [Resolvers](resolvers.md) | V | The system resolver and configured resolvers: addresses, router advertisements, DHCPv6, binding, answers |
| [Sessions](sessions.md) | S | Session devices, staging, names, hardware addresses, cookies, children, identity and its loss |
| [Events](events.md) | E | What every kernel, resolver, timer and operator event must cause |
| [Hosts](hosts.md) | H | IPv4-only and IPv6-less hosts, VRFs, routers, containers, other network managers, missing kernel support, non-systemd hosts |
| [Observability](observability.md) | O | Logging, check mode, exit codes, what is never logged, what is visible on the host |
| [Library](library.md) | L | The embeddable services and the reconciler |
| [Discard addresses](discard.md) | D | Retired: why no discard address, null device or route exists any more |

## The one-paragraph version

The daemon turns a configuration into kernel L2TPv3 tunnels and Ethernet
pseudowire sessions and keeps them that way. It starts before the network
is ready and makes the session interfaces exist as early as possible, so
that the rest of the network can be built on them; readiness means exactly
that they exist. A tunnel is a socket the daemon owns; while the tunnel has
no peer it can reach, the socket is simply not connected, and the kernel
drops whatever the sessions send without any route, address or device
being involved. Nothing it cannot do right now (reach a peer, resolve a
name, bind a device, prove an interface's identity, use an identifier)
stops it, takes a working tunnel down, or keeps another entry from being
applied: it applies what it can, says what it could not, and keeps trying.
On every event that can change what the right kernel state is, it
re-derives that state and converges to it without changing an interface's
identity unless the kernel leaves no choice. It never touches what it did
not create.

## Known gaps

Behaviour the specification requires that the implementation does not
provide. Each is a defect of the implementation, not of the specification.
This table is provisional: it holds what the audits established without
inspecting the code, and roadmap step 2 ([contributing](../../CONTRIBUTING.md))
re-derives it from the code.

| Requirement | Specification | Current behaviour |
|---|---|---|
| [T1](tunnels.md#the-right-state-of-a-tunnel), [T16](tunnels.md#peers-that-cannot-be-reached), [K5](kernel.md#requirements) | A tunnel without a reachable peer is left disconnected; no discard address, null device or route exists. | Such tunnels are connected to a discard address (`100::` or `192.0.0.8`), a `dummy` device `rsl2tpnull0` is created and routed after a grace period, and those routes are repaired. |
| [T10](tunnels.md#bind-devices) | The socket is bound by index with `SO_BINDTOIFINDEX`. | It is bound by name with `SO_BINDTODEVICE` and a before-and-after verification. |
| [T13](tunnels.md#bind-devices) | A tunnel whose bind device is absent stays unbound and disconnected, so no frame leaves through another device. | The socket is created unbound and connects to the peer through the main table until the device appears. |
| [T22](tunnels.md#changes-applied-in-place) | A changed `bind_interface` is applied by rebinding the socket in place. | The tunnel and its sessions are re-created. |
| [T26](tunnels.md#hosts-with-bindv6only) | `bindv6only` is detected per socket and handled. | Not handled; to be determined in step 2. |
| [T28](tunnels.md#peer-changes) | Every peer change is a reconnect (disconnect, rebind, connect). | To be determined in step 2. |
| [S27](sessions.md#external-deletion) | A session the kernel no longer has (deleted by an operator) is created again. | It is noticed only at the next reload that changes it, or at restart. |
| [P14](process.md#restart) | A restart or upgrade keeps session interfaces where the init system offers a descriptor store. | Every restart tears the tunnels down and creates them again. |
| [C6](configuration.md#documents) | Unknown keys are reported. | They are ignored silently. |
| [V1–V12](resolvers.md#model) | Configured resolvers: by address, by router advertisements, by DHCPv6 Information-Request, with bind interfaces. | Only the system resolver exists. |
| [E20](events.md#monitor-loss), [K10](kernel.md#requirements) | The monitor subscribes to link and address groups only. | It also subscribes to the route groups and filters them for discard routes. |
