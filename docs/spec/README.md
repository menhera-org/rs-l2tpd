# Specification

[Documentation index](../README.md)

This is the normative description of rs-l2tpd: what it requires, what it
promises, how it is built, and what it must do in every condition it can
meet. It is written from the intent behind the original contracts of the
project, from the kernel's source, and from contract reviews preserved in
Git history. The
implementation is measured against it; where the two differ the
specification is right. The [implementation documentation](../README.md)
describes the current tree and verification; it does not redefine these rules.

The words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY have their RFC 2119
meanings. Requirements are numbered per page (R3, G5, A7, M1, T7, ...) so
that tests and changes can cite them. A number is never reused: a rule that
is withdrawn keeps its number and says "removed". Every kernel-dependent
rule cites a fact of the [kernel page](kernel.md), and every claim on every
page is meant to be tested (`CONTRIBUTING.md` in the repository).

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

## Verification status

The v0.2.0 implementation and Phase 6 proof are complete. Strict maps cover
all 333 active rules and 43 kernel facts. Semantic clause cases, executed
live suites and coverage remain separate obligations; citations alone do
not prove them. [Developer guide](../developer.md) records current results and the
[mandatory acceptance cases](../developer.md#acceptance-cases).

Completed review diaries and comparisons with the removed implementation
are preserved in Git history. Repository file `audit/VERIFICATION.md` indexes
the current evidence. No normative rule was changed by this documentation
refresh. Version 0.2.0 remains unreleased.
