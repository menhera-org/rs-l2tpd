# Specification

[Documentation index](../README.md)

This is the normative description of rs-l2tpd: what it requires, what it
promises, how it is built, and what it must do in every condition it can
meet. It is written from the [contracts](../contracts.md) and the intent
behind them, not from the code. The implementation is measured against
it; where the two differ the specification is right and the difference is
listed under [known gaps](#known-gaps).

The words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY have their RFC 2119
meanings. Requirements are numbered per page (R3, G5, A7, M1, T7, ...) so
that tests and changes can cite them.

## Pages

Read the first three for the contract, the rest for the details.

| Page | Covers |
|---|---|
| [Requirements](requirements.md) | The conditions under which the daemon is to behave correctly: what it requires of the host, the operator, the peers, other network managers and embedding programs, and what it does when a requirement is not met |
| [Promises](promises.md) | What the daemon guarantees: the unconditional safety promises that hold whatever happens, and the conditional promises with their convergence bounds |
| [Architecture](architecture.md) | The components, their responsibilities, the kernel interfaces, the concurrency model and why the design has this shape |
| [Model](model.md) | Terms, the reconciliation model, the degradation ladder, ownership, identity, failure classes, timing |
| [Process](process.md) | Start-up before the network is ready, readiness, daemonisation, signals, reload, shutdown, restart, crashes, the systemd unit |
| [Configuration](configuration.md) | Files, merging, every field, every mistake and its effect at start and on reload |
| [Tunnels](tunnels.md) | Sockets, address families, bind devices, peers, DNS, source addresses, reconnection, conflicts |
| [Discard addresses](discard.md) | Where a tunnel without a peer goes, the null device, route repair |
| [Sessions](sessions.md) | Session devices, staging, names, hardware addresses, cookies, children, identity and its loss |
| [Events](events.md) | What every kernel, DNS, timer and operator event must cause |
| [Hosts](hosts.md) | IPv4-only and IPv6-less hosts, VRFs, routers, containers, other network managers, missing kernel support |
| [Observability](observability.md) | Logging, check mode, exit codes, what is never logged |
| [Library](library.md) | The embeddable services and the reconciler |

## The one-paragraph version

The daemon turns a configuration into kernel L2TPv3 tunnels and Ethernet
pseudowire sessions and keeps them that way. It starts before the network
is ready and makes the session interfaces exist as early as possible, so
that the rest of the network can be built on them; readiness means exactly
that they exist. Nothing it cannot do right now (reach a peer, resolve a
name, route a discard address, bind a device, prove an interface's
identity, use an identifier) stops it, takes a working tunnel down, or
keeps another entry from being applied: it applies what it can, says what
it could not, and keeps trying. On every event that can change what the
right kernel state is, it re-derives that state and converges to it without
changing an interface's identity unless the kernel leaves no choice. It
never touches what it did not create.

## Known gaps

Behaviour the specification requires that the current implementation does
not provide yet. Each is a defect of the implementation, not of the
specification.

| Requirement | Specification | Current behaviour |
|---|---|---|
| [T13](tunnels.md#bind-devices), [G5](promises.md#unconditional-promises) | A tunnel whose bind device is absent sits on a discard address until the device exists, so no frame leaves through another device. | The socket is created unbound and connects to the peer through the main table until the device appears. |
| [T22](tunnels.md#changes-applied-in-place) | A changed `bind_interface` is applied by rebinding the socket in place. | The tunnel and its sessions are re-created. |
| [S27](sessions.md#external-deletion) | A session the kernel no longer has (deleted by an operator) is created again. | It is noticed only at the next reload that changes it, or at restart. |
| [P14](process.md#restart) | A restart or upgrade SHOULD keep session interfaces where the platform allows. | Every restart tears the tunnels down and creates them again. |
| [C6](configuration.md#documents) | Unknown keys SHOULD be reported. | They are ignored silently. |
