# Specification

[Documentation index](../README.md)

This is the normative description of rs-l2tpd: what it requires, what it
promises, how it is built, and what it must do in every condition it can
meet. It is written from the intent behind the [contracts](../contracts.md),
from the kernel's source, and from two audits (the reports in the
repository's `audit/` directory), not from the code. The implementation is measured against it; where the two
differ the specification is right and the difference is listed under
[known gaps](#known-gaps). Where this specification and
[contracts](../contracts.md) differ, this specification is right.

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

## Known gaps

Behaviour the specification requires that the implementation does not
provide, re-derived from the code on 2026-10-27 and checked by an
independent second pass on 2026-10-28 (roadmap step 2 of the
repository's `CONTRIBUTING.md`; the rule-by-rule comparison is the step 2
report in the repository's `audit/` directory). Each is a defect of the
implementation, not of the specification, except the last two rows, which
roadmap step 3 decides.

The design the code still implements:

| Requirement | Specification | Current behaviour |
|---|---|---|
| [T1](tunnels.md#the-right-state-of-a-tunnel), [T16](tunnels.md#peers-that-cannot-be-reached), [K5](kernel.md#requirements), [E15](events.md#timers), [E16](events.md#timers) | A tunnel without a reachable peer is left disconnected; no discard address, null device, route or grace period exists. | Such tunnels are connected to a discard address (`100::` or `192.0.0.8`); after a ten-second grace period a `dummy` device `rsl2tpnull0` is created and routed, and those routes are repaired every second while they fail. |
| [T10](tunnels.md#bind-devices) | The socket is bound by index with `SO_BINDTOIFINDEX`. | It is bound by name with `SO_BINDTODEVICE` and a before-and-after index check. |
| [T13](tunnels.md#bind-devices) | A tunnel whose bind device is absent stays unbound and disconnected. | The socket is created unbound and connected through the main table until the device appears. |
| [T22](tunnels.md#changes-applied-in-place) | A changed `bind_interface` is applied by a reconnect. | The tunnel and its sessions are re-created. |
| [T26](tunnels.md#hosts-with-bindv6only), [P25](process.md#host-tunables), [C17](configuration.md#host-settings), [R44](requirements.md#the-host) | `bindv6only` is read back per socket and set to 0 unless opted out. | Not handled: no read-back, no write, no `host` table. |
| [T28](tunnels.md#peer-changes) | Every peer change is a reconnect. | A same-family change on a connected, validly bound socket is a bare `connect`, which keeps the previous source. |
| [S27](sessions.md#external-deletion) | A session the kernel no longer has is created again. | Noticed only at the next reload that changes it, or at restart. |
| [P14](process.md#restart), [P26](process.md#restart), [E26](events.md#operator-events) | Descriptor hand-over where offered; a restart operation everywhere. | Neither exists; every restart tears the tunnels down; `SIGUSR2` is not handled. |
| [C6](configuration.md#documents), [C15](configuration.md#library-conversions) | Unknown keys are reported. | Ignored silently, by `--check` too. |
| [V1–V15](resolvers.md#model), [C5](configuration.md#documents), [C16](configuration.md#resolver-entries), [R46](requirements.md#the-host), [K13](kernel.md#requirements), [K14](kernel.md#requirements), [K39](kernel.md#requirements) | Configured resolvers by address, router advertisements, DHCPv6 or both, with bind interfaces. | Only the system resolver exists; a `resolvers` table is an unknown key. |
| [E9](events.md#route-events), [K7](kernel.md#requirements), [R5](requirements.md#the-host) | The monitor subscribes to link and address groups only. | It also subscribes to the route groups, filtered in the kernel to the removal of a discard route. |
| [L10](library.md#the-reconciler), [A21](architecture.md#extension) | One `handle_event` dispatches every variant. | Per-kind methods only. |
| [L12](library.md#the-reconciler) | The runtime asks the program to write a tunable. | No such event. |

Defects against rules that hold under either design:

| Requirement | Specification | Current behaviour |
|---|---|---|
| [C14](configuration.md#semantics-of-changes), [M6](model.md#reconciliation), [S11](sessions.md#names) | A removed session's name taken by a surviving session converges in one reload. | It never converges: final renames run before deletions, so the rename fails with `EEXIST` on every reconcile and the removed session is never deleted. |
| [M4](model.md#reconciliation), [G6](promises.md#unconditional-promises), [P8](process.md#readiness) | One entry's failure never keeps another from being applied. | The first error other than a counted conflict ends the reconcile; entries after it in identifier order wait for the next one, and a conflict does the same for its first nine attempts. |
| [P7](process.md#readiness), [G8](promises.md#unconditional-promises), [G15](promises.md#conditional-promises) | Readiness never waits for a session's publication or for a route to a peer. | It waits while a foreign device holds a configured name, and for a route to a discard address. |
| [G5](promises.md#unconditional-promises), [T15](tunnels.md#peers), [T17](tunnels.md#peers-that-cannot-be-reached) | A tunnel is never connected to a peer the configuration or the resolver no longer names. | An unreachable resolver answer leaves the previous peer connected; a reload to an unreachable peer whose discard addresses are unreachable too keeps the old peer. |
| [T11](tunnels.md#bind-devices), [E2](events.md#link-events) | A bind device renamed away disconnects the tunnel at once. | The rename is not noticed on its own event (the event carries the new name), and a later reconnect fails at the configured-name check before it disconnects: frames keep leaving through the renamed device until some device takes the configured name. |
| [S4](sessions.md#creation), [S7](sessions.md#creation), [H12](hosts.md#other-network-managers) | Every session is staged; a configured name held by a foreign device is a transient publication failure. | Sessions without a configured hardware address are created under their final name; the kernel's refusal is counted as an identifier conflict: ten retries, then left out. |
| [P5](process.md#start-up), [H15](hosts.md#missing-kernel-support-and-privilege), [M13](model.md#failure-classes), [G1](promises.md#unconditional-promises) | Kernel interfaces that cannot be opened are a host defect: retried, readiness withheld. | The daemon exits and the parent exits 1. |
| [P11](process.md#pid-file) | The PID file is removed only while it is the published inode; a publication failure keeps the daemon running and the parent exits 0. | Removed unconditionally; a failure shuts the daemon down and the parent exits 1. |
| [P16](process.md#shutdown), [P17](process.md#shutdown), [S26](sessions.md#removal), [G20](promises.md#conditional-promises) | Provable sessions are deleted before their tunnel; each tunnel deletion is waited for up to two seconds. | Tunnel sockets are closed first and the sessions go with them; nothing is waited for. |
| [S22](sessions.md#identity-loss) | Deletion after a loss names the creation-time interface name, in one operation with the check. | The check and a deletion by identifiers are two operations. |
| [T4](tunnels.md#address-families), [H4](hosts.md#address-families) | The `AF_INET6` refusal is probed at every tunnel creation. | One refusal latches every later tunnel to `AF_INET` for the daemon's life. |
| [T27](tunnels.md#link-local-peers), [C7](configuration.md#tunnel-entries), [R47](requirements.md#the-operator) | A link-local peer carries a zone or uses the bind interface. | No zone syntax exists; a link-local peer without a scope stays on the discard address for good. |
| [C7](configuration.md#tunnel-entries), [S3](sessions.md#creation), [K32](kernel.md#facts) | An interface name never contains `%`. | `%` passes validation; the kernel expands the name at creation and the daemon then forgets the session it created while it still exists. |
| [T20](tunnels.md#source-addresses), [H5](hosts.md#address-families) | A connect that leaves the source unspecified counts as failed and the tunnel is disconnected. | It counts as failed in the daemon's view, but the socket stays connected with that source. |
| [M16](model.md#scale), [G12](promises.md#unconditional-promises) | An event concerning no entry costs no kernel query. | While any tunnel is bound, every address event costs a VRF-master lookup; every link event re-installs the recorded discard routes. |
| [G13](promises.md#unconditional-promises), [O3](observability.md#logging) | Retries are silent after the first report. | Failed reconnects and incomplete reconciles are logged at warning level every second. |
| [C4](configuration.md#files) | A dangling symbolic link is an error, not a removal. | It is treated as an absent file. |
| [C12](configuration.md#reload) | Two passes: a retained entry that collides with a new valid entry refuses the reload, naming it. | One pass in name order: the retained entry wins and the later new entry is retained or rejected instead. |
| [S4](sessions.md#creation) | Temporary names come from a random source. | A counter plus the process identifier. |
| [T25](tunnels.md#identifier-conflicts) | A left-out entry's eventual creation is reported. | Created silently. |
| [E21](events.md#monitor-loss) | A lifetime lookup times out after two seconds. | Five seconds. |
| [A6](architecture.md#concurrency) | The monitor drops an event when the channel is full and marks a resync. | The monitor task waits for room while its netlink connection keeps draining the kernel socket into an unbounded queue: nothing overflows, no resync happens, and memory and latency grow. |
| [O2](observability.md#logging) | A refused reload is logged at error level. | At warning level. |
| [O4](observability.md#logging), [O6](observability.md#logging) | Messages carry the configuration name and errno names. | Runtime messages carry identifiers only, and the kernel's error text. |
| [L5](library.md#the-service) | `run` without `converge` converges first. | `run` applies nothing until a reload. |
| [L7](library.md#the-service), [L8](library.md#the-service), [P13](process.md#signals-and-requests) | A callback panic and a dropped blocking service remove everything in order. | The sockets close with the runtime; nothing is deleted in order and the null device survives. |
| [R4](requirements.md#the-host), [K22](kernel.md#facts), [T21](tunnels.md#source-addresses) | A device binding is only ever set on a socket that has none. | After a bind device is renamed away or removed, the still-bound socket is bound again without a disconnect, which fails with `EPERM` without `CAP_NET_RAW`; the tunnel stays on the old device until a peer change or restart. (Roadmap step 4 makes `CAP_NET_RAW` required; the fallback must still work.) |
| [C6](configuration.md#documents), [O5](observability.md#logging), [G11](promises.md#unconditional-promises) | Cookies never appear in logs. | A rejected cookie's text is part of the error message; the public `PartialConfig` prints cookie strings in its `Debug` output. |
| [C7](configuration.md#tunnel-entries) | An IPv4-mapped literal is an IPv4 literal; a host name is 1 to 253 ASCII bytes. | A mapped literal is treated as IPv6; `""` and `"."` are accepted as the root name and non-ASCII names are punycoded. |
| [C10](configuration.md#start-up) | An out-of-range identifier leaves out its entry. | It fails the whole document: the file's other entries are lost at start-up and a reload is refused. |
| [C8](configuration.md#session-entries) | A hardware address is six pairs of hex digits. | A `+` sign in a hardware address is accepted. |
| [V5](resolvers.md#queries-and-answers) | IPv4-mapped answers are unusable for an IPv6 tunnel; unusable addresses are skipped. | Mapped answers are used over IPv4; an answer whose first address is unusable is rejected whole. |
| [V6](resolvers.md#queries-and-answers), [V7](resolvers.md#queries-and-answers) | A resolver outage never disconnects a working tunnel; stale answers are retained. | A tunnel re-creation drops its resolver and its answer; `retain_stale_values` is off, so a transient negative answer clears the cached address. |
| [T12](tunnels.md#bind-devices), [E3](events.md#link-events) | A removed bind device disconnects its tunnels. | Only the daemon's record of the binding is forgotten; the socket stays connected with the stale binding. |
| [T13](tunnels.md#bind-devices) | (as above) | Also when the bind device vanishes between the lookup and the bind. |
| [L7](library.md#the-service), [P13](process.md#signals-and-requests) | Shutdown proceeds while a reload callback is still running. | Shutdown waits for a blocked reload callback. |
| [G1](promises.md#unconditional-promises), [P11](process.md#pid-file) | The daemon keeps running whatever happens to other processes. | If the parent dies before readiness, the readiness write fails and the converged daemon shuts down. |
| [P12](process.md#signals-and-requests) | `SIGUSR2` restarts; several `SIGHUP`s cause one reload. | `SIGUSR2`'s default action kills the daemon; each `SIGHUP` during a reload queues another reload. |
| [P21](process.md#the-supplied-systemd-unit) | A read-only system except the PID file; the bindv6only write allowed; hand-over keys present. | `ProtectSystem=full` leaves `/var` writable; `ProtectKernelTunables=yes`; no `NotifyAccess` or `FileDescriptorStoreMax`. |
| [R22](requirements.md#the-operator), [P18](process.md#crashes) | A crash leaves nothing behind. | The null device and its routes survive; the next start treats them as foreign and adds another. |
| [E20](events.md#monitor-loss), [E12](events.md#timers) | One resync per loss; at most one reconcile per second. | An overrun causes two resyncs; during start-up every event causes a reconcile. |
| [S23](sessions.md#identity-loss) | A lost proof is first re-identified. | A staging session whose captured proof is lost is deleted and re-created at once. |

For roadmap step 3 to decide:

| Requirement | Specification | Current behaviour |
|---|---|---|
| [C14](configuration.md#semantics-of-changes), [M17](model.md#identity-matrix) | A configuration entry renamed with unchanged identifiers is a removal and an addition. | The reconciler keys entries by identifier, so the kernel objects are kept. |
| [S12](sessions.md#hardware-addresses) | A deferred hardware-address change is reported once. | It is logged on every reconcile that carries it. |
| [C1](configuration.md#files) | A drop-in whose name is not UTF-8 is ignored with a warning. | It is read like any other drop-in. Decided on 2026-10-28: names are byte strings wherever UTF-8 is not required, so the specification changes. |
| [C1](configuration.md#files) | (to be added) Drop-ins whose name starts with `.` are ignored; both configuration paths can be changed at build time and at runtime. | `.foo.toml` is read; both paths can be changed at build time (`CONFIG_FILE_PATH`, `CONFIG_DIR_PATH`) but there is no runtime option. Decided on 2026-10-28. |
