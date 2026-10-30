# Specification

[Documentation index](../README.md)

This is the normative description of rs-l2tpd: what it requires, what it
promises, how it is built, and what it must do in every condition it can
meet. It is written from the intent behind the original contracts of the
project, from the kernel's source, and from the audits and reviews in
the repository's `audit/` directory, not from the code. The
implementation is measured against it; where the two differ the
specification is right. [Current contract gaps](#current-contract-gaps)
track the latest review corrections; [known gaps](#known-gaps) preserve
the explicitly historical comparison. The [documentation](../README.md) outside
this directory is the plan for building the implementation; where it
and this specification differ, this specification is right.

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

## Current contract gaps

The 2026-10-29 documentation review corrected the following contracts.
This is required implementation and acceptance work, not a declaration
that the current code passes it:

| Contract | Required correction and proof |
|---|---|
| S23, M18, S24 | Never recover a lost staging proof from an index/name match; test replacement with both values reused, verified deletion failure and absence before restaging. |
| L12, T26, P8, P25 | Finish the bounded tunable handshake before registration; test success, failure, timeout, late reply, concurrent creations and a racing sysctl writer. |
| P14, P26, L13 | Retain exact inherited store names; retry uncertain adoption and withdraw definitively rejected descriptors before reuse. Test real store references, delayed removal and shutdown failure. |
| V3–V4, V15, A9, G23 | Separate bounded worker budgets from unbounded libc execution; test stalled calls across reloads/service drops, queue coalescing and configured-DNS independence. |
| V10 | Apply bounded per-address RDNSS updates rather than replacement snapshots; shipped in `iphost` 0.4.1 (pinned), the daemon's adapter cases remain. |
| V14 | Enable general-purpose per-family DHCPv6-to-RA failure fallback with truthful bounds; shipped in `iphost` 0.4.1 and turned on by the daemon, its adapter cases remain. |

[Upstream instructions](../upstream-iphost.md) distinguish `iphost`'s own
bugs from optional features and daemon-only work.
[Acceptance cases](../testing.md#contract-correction-acceptance-cases)
close these gaps; existing citations alone do not.

## Known gaps

Historical gaps of the pre-rewrite implementation at `741117b`, removed
in Phase 0. The current rewrite has configuration, fake/real kernel,
reconciler, runtime, services and process layer.
Phase 5 evidence (repository file `audit/PHASE5_VERIFICATION_2026-10-29.md`)
records binary acceptance separately from the remaining whole-daemon gates.
Current acceptance work is in [the plan](../plan.md); the 2026-10-29
contract corrections and upstream dependencies are listed above.
The following comparison is historical:
behaviour the specification required that that implementation did not
provide, re-derived from the code on 2026-10-27, checked by an independent
second pass on 2026-10-28, and every row re-confirmed against the code at
commit `741117b` (roadmap step 2 of the repository's `CONTRIBUTING.md`;
the rule-by-rule comparison is the step 2 report in the repository's
`audit/` directory). Both tables are defects of the implementation, not
of the specification as assessed then: rows were confirmed on 2026-10-28
(roadmap steps 3 and 4), when the cases in which the implementation could
have been right were decided. The S23 finding is explicitly withdrawn
below after the 2026-10-29 review.

The design implemented by the historical baseline:

| Requirement | Specification | Current behaviour |
|---|---|---|
| [T1](tunnels.md#the-right-state-of-a-tunnel), [T16](tunnels.md#peers-that-cannot-be-reached), [K5](kernel.md#requirements), [E15](events.md#timers), [E16](events.md#timers), [H8](hosts.md#routers), [O8](observability.md#check-mode), [O9](observability.md#state-visible-on-the-host) | A tunnel without a reachable peer is left disconnected; no discard address, null device, route, route lookup or grace period exists. | Such tunnels are connected to a discard address (`100::` or `192.0.0.8`); the daemon looks up a route to it (`RTM_GETROUTE`, in a VRF's table too), and after a ten-second grace period a `dummy` device `rsl2tpnull0` is created and routed, and those routes are repaired while they fail. `--check` prints such a peer as `remote_addr = "100::"`. |
| [R22](requirements.md#the-operator), [P18](process.md#crashes) | A crash leaves nothing behind. | The null device and its routes survive a kill; the next start finds the name taken by what is now a foreign device and creates `rsl2tpnull1`, and so on. |
| [T10](tunnels.md#bind-devices) | The socket is bound by index with `SO_BINDTOIFINDEX`. | It is bound by name with `SO_BINDTODEVICE` and a before-and-after index check. |
| [T13](tunnels.md#bind-devices) | A tunnel whose bind device is absent stays unbound and disconnected. | The socket is created unbound and connected through the main table, both when the device is absent and when it vanishes between the lookup and the bind, until the device appears. |
| [T22](tunnels.md#changes-applied-in-place), [M17](model.md#identity-matrix), [S17](sessions.md#changes-applied-in-place) | A changed `bind_interface` is applied by a reconnect. | The tunnel and its sessions are re-created, and an FQDN tunnel also loses its resolver and its answer. |
| [T26](tunnels.md#hosts-with-bindv6only), [P25](process.md#host-tunables), [C17](configuration.md#host-settings), [R44](requirements.md#the-host) | `bindv6only` is read back per socket and set to 0 unless opted out. | Not handled: no read-back, no write, no `host` table. With `bindv6only=1` every IPv4 tunnel sits on the discard address and the warning names an unreachable peer, not the cause. |
| [S27](sessions.md#external-deletion), [R18](requirements.md#the-operator) | A session the kernel no longer has is created again. | It is not: its device is "left alone", renames and hardware-address changes are skipped; it comes back only when a reload changes a field that re-creates it, or at restart. |
| [P14](process.md#restart), [P26](process.md#restart), [E26](events.md#operator-events) | Descriptor hand-over where offered; a restart operation everywhere. | Neither exists; every restart tears the tunnels down. `SIGUSR2` has no handler, so its default action kills the daemon without an ordered shutdown. |
| [V1–V15](resolvers.md#model), [C5](configuration.md#documents), [C16](configuration.md#resolver-entries), [R46](requirements.md#the-host), [K13](kernel.md#requirements), [K14](kernel.md#requirements), [K39](kernel.md#requirements) | Configured resolvers by address, router advertisements, DHCPv6 or both, with bind interfaces. | Only the system resolver exists (`iphost` 0.3.3); a `resolvers` table is an unknown key. |
| [E9](events.md#route-events), [K7](kernel.md#requirements), [R5](requirements.md#the-host) | The monitor subscribes to link and address groups only. | It also subscribes to the route groups, filtered in the kernel to the removal of a discard route. |
| [L10](library.md#the-reconciler), [A21](architecture.md#extension) | One `handle_event` dispatches every variant. | Per-kind methods only. |
| [L12](library.md#the-reconciler) | The runtime asks the program to write a tunable. | No such event. |

Defects against rules that hold under either design:

| Requirement | Specification | Current behaviour |
|---|---|---|
| [C14](configuration.md#semantics-of-changes), [M6](model.md#reconciliation), [S11](sessions.md#names) | A removed session's name taken by a surviving session converges in one reload. | It never converges: final renames run before deletions, so the rename fails with `EEXIST` on every reconcile, the removed session is never deleted, and the survivor gets a new temporary name every second. |
| [M4](model.md#reconciliation), [G6](promises.md#unconditional-promises), [P8](process.md#readiness) | One entry's failure never keeps another from being applied. | The first error other than a counted conflict ends the reconcile (a staging or publication failure, a tunnel creation failure, a failed clean-up of a stale pending session, the discard-route grace period); entries after it in identifier order wait for the next one, and a conflict does the same for its first nine attempts, which includes the re-creation of any tunnel whose deleted predecessor the kernel still holds. |
| [P7](process.md#readiness), [G8](promises.md#unconditional-promises), [G15](promises.md#conditional-promises), [H2](hosts.md#address-families), [H6](hosts.md#address-families) | Readiness never waits for a session's publication or for a route to a peer. | It waits while a foreign device holds a configured name, and for a route to a discard address; where the `dummy` driver is unavailable it never comes. |
| [G5](promises.md#unconditional-promises), [T15](tunnels.md#peers), [T17](tunnels.md#peers-that-cannot-be-reached) | A tunnel is never connected to a peer the configuration or the resolver no longer names. | An unreachable resolver answer leaves the previous peer connected; a reload to an unreachable peer whose discard addresses are unreachable too keeps the old peer. |
| [T11](tunnels.md#bind-devices), [E2](events.md#link-events) | A bind device renamed away disconnects the tunnel at once. | The rename is not noticed on its own event (the event carries the new name), and a later reconnect fails at the configured-name check before it disconnects: frames keep leaving through the renamed device until some device takes the configured name. |
| [T12](tunnels.md#bind-devices), [E3](events.md#link-events), [H13](hosts.md#other-network-managers), [G17](promises.md#conditional-promises) | A removed bind device disconnects its tunnels. | Only the daemon's record of the binding is forgotten; the socket stays connected with the stale binding. |
| [R4](requirements.md#the-host), [K22](kernel.md#facts), [T21](tunnels.md#source-addresses), [E1](events.md#link-events) | A device binding is only ever set on a socket that has none. | When a device takes the configured name after the bind device was renamed away or removed, the still-bound socket is bound again without a disconnect; without `CAP_NET_RAW` the kernel refuses (`EPERM`) on every attempt and the tunnel stays on the old device until a peer change or a restart. `CAP_NET_RAW` is required, but the binding order of T10 and T21 must hold without it. |
| [S4](sessions.md#creation), [S7](sessions.md#creation), [H12](hosts.md#other-network-managers) | Every session is staged; a configured name held by a foreign device is a transient publication failure. | Sessions without a configured hardware address are created under their final name; the kernel's refusal is counted as an identifier conflict: ten retries, then left out with a wrong diagnosis, and readiness is reported without it. |
| [S4](sessions.md#creation) | Temporary names come from a random source. | A counter plus the process identifier (collisions are retried). |
| [P5](process.md#start-up), [H15](hosts.md#missing-kernel-support-and-privilege), [M13](model.md#failure-classes), [G1](promises.md#unconditional-promises) | Kernel interfaces that cannot be opened are a host defect: retried, readiness withheld. | The daemon exits and the parent exits 1. |
| [P10](process.md#pid-file), [P11](process.md#pid-file) | The PID file is removed only while it is the published inode; a publication failure keeps the daemon running and the parent exits 0. | The published inode is never recorded and the file is removed unconditionally; a publication failure shuts the daemon down and the parent exits 1. |
| [G1](promises.md#unconditional-promises), [P11](process.md#pid-file) | The daemon keeps running whatever happens to other processes. | If the parent dies before readiness, the readiness write fails (`EPIPE`) and the converged daemon shuts down. |
| [P12](process.md#signals-and-requests) | Several `SIGHUP`s before the daemon acts cause one reload. | Each `SIGHUP` that arrives while a reload runs queues another one; only signals arriving back to back are merged. |
| [P13](process.md#signals-and-requests), [L7](library.md#the-service), [L8](library.md#the-service) | Shutdown proceeds while a reload callback runs; a callback panic and a dropped blocking service remove everything in order. | Shutdown waits for a blocked reload callback; after a callback panic, or when a blocking service is dropped without running, the sockets just close with the runtime: nothing is deleted in order and the null device survives. |
| [P16](process.md#shutdown), [P17](process.md#shutdown), [S26](sessions.md#removal), [G20](promises.md#conditional-promises) | Provable sessions are deleted before their tunnel; each tunnel deletion is waited for up to two seconds. | Tunnel sockets are closed first and the sessions go with them; nothing is waited for. |
| [P21](process.md#the-supplied-systemd-unit) | A read-only system except the PID file; the `bindv6only` write allowed; hand-over keys present. | `ProtectSystem=full` leaves `/var` writable; `ProtectKernelTunables=yes` forbids the write; no `NotifyAccess` or `FileDescriptorStoreMax`. |
| [S22](sessions.md#identity-loss) | Deletion after a loss first verifies a unique matching stored creation name, then deletes by that name, accepting the documented check/delete race (S22). | The check and a deletion by identifiers are two operations, and any error of the check counts as "not ours", so the session is forgotten without being deleted. |
| [S23](sessions.md#identity-loss), historical finding withdrawn 2026-10-29 | The former instruction to re-identify a lost proof by index/name was unsafe and is replaced by verified deletion, confirmed absence and restaging. | The baseline deleted and re-created a staging session after loss; it must be assessed against the corrected verification rule, not the withdrawn re-identification requirement. |
| [T4](tunnels.md#address-families), [H4](hosts.md#address-families) | The `AF_INET6` refusal is probed at every tunnel creation. | One refusal latches every later tunnel to `AF_INET` for the daemon's life. |
| [T20](tunnels.md#source-addresses), [H5](hosts.md#address-families) | A connect that leaves the source unspecified counts as failed and the tunnel is disconnected. | After a reconnect it counts as failed in the daemon's view, but the socket stays connected with that source; a creation-time connect is not checked at all (not reproduced). |
| [T28](tunnels.md#peer-changes), [E13](events.md#timers) | Every peer change is a reconnect. | A same-family change on a connected, validly bound socket, including the peer retry, is a bare `connect`, which keeps the previous source. |
| [T25](tunnels.md#identifier-conflicts) | A left-out entry's eventual creation is reported. | Created silently. |
| [T27](tunnels.md#link-local-peers), [C7](configuration.md#tunnel-entries), [R47](requirements.md#the-operator) | A link-local peer carries a zone or uses the bind interface; without either it is a hard mistake. | No zone syntax exists (a zoned literal is an unusable endpoint); `fe80::1` on an unbound tunnel is accepted and stays on the discard address for good. |
| [C7](configuration.md#tunnel-entries), [C8](configuration.md#session-entries), [S3](sessions.md#creation), [K32](kernel.md#facts) | An interface name never contains `%`. | `%` passes validation in `interface_name` and `bind_interface`; the kernel expands it, so the device never bears the configured name and the ownership check, which compares the kernel's recorded name with it, disowns a session the daemon created. |
| [C7](configuration.md#tunnel-entries) | An IPv4-mapped literal is an IPv4 literal; a host name is 1 to 253 ASCII bytes. | A mapped literal is treated as IPv6; `""` and `"."` are accepted as the root name and non-ASCII names are punycoded. |
| [C8](configuration.md#session-entries) | A hardware address is six pairs of hex digits. | A `+` sign in a hardware address is accepted. |
| [C6](configuration.md#documents), [C15](configuration.md#library-conversions), [O7](observability.md#exit-codes) | Unknown keys are reported; `--check` exits 1. | Ignored silently, by `--check` too: a misspelt `cokie` runs the session without a cookie. |
| [O5](observability.md#logging), [G11](promises.md#unconditional-promises) | Cookies never appear in logs. | A rejected cookie's text is part of the error message; the public `PartialConfig` prints cookie strings in its `Debug` output. |
| [C10](configuration.md#start-up) | An out-of-range identifier leaves out its entry. | It fails the whole document: the file's other entries are lost at start-up and a reload is refused. |
| [C4](configuration.md#files) | A dangling symbolic link is an error, not a removal. | It is treated as an absent file, so a reload removes what the file defined. |
| [C12](configuration.md#reload) | Two passes: a retained entry that collides with a new valid entry refuses the reload, naming it. | One pass in name order: a retained entry ordered first keeps its identifiers, the later new entry is left out and the reload is accepted; with the names the other way round it is refused. |
| [V5](resolvers.md#queries-and-answers) | IPv4-mapped answers are unusable for an IPv6 tunnel; unusable addresses are skipped. | Mapped answers are used over IPv4; an answer whose first address is unusable is rejected whole. |
| [V6](resolvers.md#queries-and-answers), [V7](resolvers.md#queries-and-answers) | A resolver outage never disconnects a working tunnel; stale answers are retained. | A tunnel re-creation drops its resolver and its answer; `retain_stale_values` is off, so a transient negative answer clears the cached address. |
| [M16](model.md#scale), [G12](promises.md#unconditional-promises) | An event concerning no entry costs no kernel query. | While any tunnel is bound, every address event costs a VRF-master lookup; every link event re-installs the recorded discard routes and, for each session with a deferred hardware address, costs a lookup. |
| [G13](promises.md#unconditional-promises), [O3](observability.md#logging) | Retries are silent after the first report. | Failed reconnects and incomplete reconciles are logged at warning level every second. |
| [O2](observability.md#logging) | A refused reload is logged at error level. | At warning level. |
| [O4](observability.md#logging), [O6](observability.md#logging) | Messages carry the configuration name and errno names. | Runtime messages carry identifiers only, and the kernel's error text. |
| [A5](architecture.md#layers) | Requests go over sockets of their own, never the monitor's. | The monitor's seed dump of links is sent over the monitor's own connection. |
| [A6](architecture.md#concurrency) | The monitor drops an event when the channel is full and marks a resync. | The monitor task waits for room while its netlink connection keeps draining the kernel socket into an unbounded queue: nothing overflows, no resync happens, and memory and latency grow. |
| [E20](events.md#monitor-loss), [E12](events.md#timers) | One resync per loss; at most one reconcile per second. | An overrun causes two resyncs; during start-up every event causes a reconcile. |
| [L3](library.md#boundaries) | Public enums are `#[non_exhaustive]`. | `IpVersion` is not. |
| [L5](library.md#the-service) | `run` without `converge` converges first. | `run` applies nothing until a reload. |
| [R49](requirements.md#the-host), [P21](process.md#the-supplied-systemd-unit), [O2](observability.md#logging) | The supplied unit grants every required capability explicitly; each one the process lacks is reported once at start-up. | The unit runs as root with no capability set; nothing checks for or reports a missing capability. |
| [C1](configuration.md#files), [P22](process.md#the-process-contract) | Drop-ins whose name starts with `.` are ignored; both configuration paths can be changed at build time and on the command line. | `.foo.toml` is read; the paths can be changed at build time (`CONFIG_FILE_PATH`, `CONFIG_DIR_PATH`) but not on the command line. |
| [R10](requirements.md#the-host) | `SO_RCVBUFFORCE`, then `SO_RCVBUF`. | The other order, with the same result. |
| [E4](events.md#link-events) | A bind device's own move into or out of a VRF reconnects the tunnels bound to it; a member's move reconnects the tunnels bound to the VRF. | Only a bound VRF's membership changes are acted on. |

The cases roadmap step 3 had to decide (an entry renamed in the
configuration, the deferred-change report, the lookup timeout, the
buffer-option order, the start-up order, the wording of E4) were decided
on 2026-10-28 and the pages changed accordingly; the decisions and their
reasons are in `audit/SPEC_REVIEW_2026-10-28.md`, which also records the
review of the specification itself (one corrected kernel fact, K29, and
the conditions the design is safe under).
