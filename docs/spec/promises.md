# Promises

[Specification index](README.md)

What the daemon and the library guarantee. The unconditional promises
hold whatever the host, the operator, the peers or other managers do;
they are safety properties, and breaking one is a defect however the
daemon was provoked. The conditional promises hold when the
[requirements](requirements.md) are met; they are what the daemon is for.

## Unconditional promises

| | Promise | Where specified |
|---|---|---|
| G1 | The daemon never panics, aborts or exits because of a configuration, a kernel reply, a resolver answer, a notification, its loss, or anything another process does. It exits on request, when the process itself cannot be set up, or when an embedding program's reload callback panics. | [P19](process.md#crashes), [L11](library.md#errors) |
| G2 | The daemon never modifies, deletes or adopts an object it did not create or can no longer prove it created: no foreign tunnel, session or device, whatever name or identifier it carries. The one exception is the descriptor hand-over of [P14](process.md#restart) and [P26](process.md#restart), in which a new instance adopts the tunnels the previous instance handed over on purpose, after verifying each. | [M9](model.md#ownership), [M10](model.md#ownership), [S24](sessions.md#identity-loss) |
| G3 | A session interface's identity (its index, and so its addresses, routes, neighbour state and children) changes only by an operation of the [identity matrix](model.md#identity-matrix): the kernel cannot change its identifiers, its cookies or its tunnel's identifiers in place, the entry was removed from the configuration, or a staged device's identity was lost. Everything else, including every mistake and its correction, every peer, source, binding or family change, every rename and every hardware-address change, keeps the interface. | [M11](model.md#identity), [M17](model.md#identity-matrix), [S17](sessions.md#changes-applied-in-place), [T22–T23](tunnels.md#changes-applied-in-place) |
| G4 | The daemon never takes a running device down and never undoes what another manager did to a device, except by removing or re-creating the device under G3. | [S2](sessions.md#the-right-state-of-a-session), [S12](sessions.md#hardware-addresses) |
| G5 | A tunnel is never connected to a peer the configuration does not name now. A tunnel without a reachable peer is not connected, and the kernel drops its frames ([K5](kernel.md#requirements)): nothing leaves the host through any device or route. A tunnel with a bind device is connected only while that binding satisfies T27: normally the device of that name, or the effective zone member of the configured VRF for a zoned link-local peer. Both dependencies and membership must remain valid. This promise is about sending only: a disconnected tunnel's sessions still receive whatever reaches the host with their identifiers and cookies ([K15](kernel.md#facts), [T1](tunnels.md#the-right-state-of-a-tunnel), [S14](sessions.md#cookies)). | [T1](tunnels.md#the-right-state-of-a-tunnel), [T13](tunnels.md#bind-devices), [T16–T17](tunnels.md#peers-that-cannot-be-reached) |
| G6 | One entry's problem never blocks unrelated entries. A session depends on its tunnel, and claims of shared identifiers or names depend on their release (M4, M6); only those dependent operations may wait. | [M4](model.md#reconciliation), [T25](tunnels.md#identifier-conflicts), [S20](sessions.md#identity-loss) |
| G7 | A hard mistake on reload retains previous values or refuses the reload. A tolerated endpoint mistake may disconnect a tunnel, but preserves its socket and session interfaces; a refused reload changes nothing. | [C12](configuration.md#reload) |
| G8 | Readiness is never reported while an entry that is eligible for it is missing from the kernel. Eligible are all entries of the accepted configuration except those left out for an identifier conflict after the bounded retries, which are reported as left out. Readiness never waits for a resolver, for a route to a peer, for a bind device, for IPv6, for a deferred hardware-address change, for a session's publication under its configured name, or for `network-online.target`. | [P6–P8](process.md#readiness) |
| G9 | No kernel tunnel or session of the daemon's outlives the process: tunnels are owned by sockets. The one exception is the descriptor store of [P14](process.md#restart), where the init system offers one: it keeps the sockets across an unplanned exit for the next instance, and an explicit shutdown withdraws them first. | [P18](process.md#crashes), [T8](tunnels.md#creation-and-identifiers) |
| G10 | The daemon requires `CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE` and no other capability ([R49](requirements.md#the-host)); without one of the latter two it runs on fallbacks ([R4](requirements.md#the-host), [R46](requirements.md#the-host)). It makes no `bpf()` call and loads no module itself. It changes no kernel setting, with one exception the operator can turn off: it sets `net.ipv6.bindv6only` to 0 in its own namespace when it finds it set ([P25](process.md#host-tunables)). | [K8–K13](kernel.md#requirements), [H9](hosts.md#containers-and-namespaces) |
| G11 | Cookies are never logged. Nothing that changes the wire format or the kernel's acceptance of frames is on unless configured; a 0.1.5 configuration keeps working and 0.1.5 peers interoperate. | [S14](sessions.md#cookies), [O5](observability.md#logging) |
| G12 | The cost of an event is bounded by the entries it concerns; events concerning nothing cost at most a comparison against the daemon's records; route changes are not subscribed to at all. The daemon never loops without delay and holds a bounded number of timers. | [M15–M16](model.md#timing), [E20](events.md#monitor-loss) |
| G13 | A lasting condition is reported once when it begins and once when it ends; retries are silent. The one exception is a deferred hardware-address change, reported at every reconcile that carries it ([S12](sessions.md#hardware-addresses)). | [O3](observability.md#logging) |
| G14 | The same rules apply through the library: `Service`, `blocking::Service` and `Runtime` are the daemon without its process, and the public API changes compatibly. | [library](library.md) |

## Conditional promises

Given the requirements, in addition:

| | Promise | Where specified |
|---|---|---|
| G15 | **Readiness in bounded time.** The parent exits 0 and the PID file appears as soon as every eligible entry exists, which is as soon as the kernel has created it: no route, resolver, peer or grace period is waited for. With identifiers held elsewhere, at most ten seconds for the entries concerned. | [P6–P9](process.md#readiness) |
| G16 | **Existence.** From readiness on, every eligible entry's tunnel and session exist continuously, except during a re-creation required by G3, which happens within one reconcile. | [M1](model.md#reconciliation), [T24](tunnels.md#changes-applied-in-place) |
| G17 | **Convergence.** After every event that changes an entry's right state, the daemon attempts the converging operation within the bound below, counted from the event's delivery, and repeats it at the retry interval while the host refuses it; the kernel state is right as soon as the host allows the operation. | [events](events.md) |
| G18 | **Stability.** For an entry whose kernel state is already right and whose relevant host state is unchanged, an unchanged configuration reloaded or reconciled again changes nothing in the kernel: no reconnect, no rename, no address change. Entries with pending work (a conflict, an unpublished name, a deferred change, an unfinished operation) are retried by the same reload. | [M2](model.md#reconciliation), [E17](events.md#operator-events) |
| G19 | **Fidelity.** When the host allows it, the kernel state equals the configuration: the real peer, the configured name, the configured hardware address, the configured cookies, bound as configured (including the zone-member rule of T27), with a source address that exists on the host. Substitutes (the disconnected state, the kernel's hardware address, a temporary name) exist only while the host does not allow the configured state and are replaced as soon as it does. Acknowledged overrides (a rename or a hardware address another manager applied afterwards) are not substitutes and are kept until the configuration changes that field. | [T1](tunnels.md#the-right-state-of-a-tunnel), [S1](sessions.md#the-right-state-of-a-session), [M7–M8](model.md#the-degradation-ladder), [M19](model.md#enforced-fields) |
| G20 | **Shutdown.** Everything owned is removed in order, sessions before tunnels; each tunnel deletion is waited for up to two seconds so that identifiers are free for a restart; the PID file is removed; the exit code says whether every step succeeded. | [P16–P17](process.md#shutdown) |
| G21 | **Early start.** The daemon starts and reaches readiness before the network is configured, so that the network can be built on its interfaces. | [P1](process.md#start-up), [H6](hosts.md#address-families) |
| G22 | **Compatibility.** The configuration format of 0.1.5 keeps working, the readiness semantics and the process contract are kept, and a correctness fix never introduces a connectivity failure that 0.1.5 did not have for a supported, intended configuration. Stopping traffic that formerly left through an unintended device or route is not a connectivity failure. | [P22](process.md#the-process-contract), [C10](configuration.md#start-up), [S14](sessions.md#cookies) |
| G23 | **Resources.** Memory is bounded by the size of the configuration, the monitor buffers and the resolver state of the configured resolvers; descriptors by the number of tunnels plus a constant per resolver plus a constant; neither grows with the number of events handled. | [R9–R10](requirements.md#the-host), [M16](model.md#scale) |

### Convergence bounds

The bound is the delay after which the daemon attempts the operation that
makes the kernel state right; the operation succeeds as soon as the host
allows it, and each retry interval is added once per obstacle still
present. Bounds are measured on the monotonic clock; time spent suspended
does not count ([M14](model.md#timing)).

| Event | Bound |
|---|---|
| A device of a configured bind name appears or is replaced | The event's delivery, then one reconnect; one second per failed reconnect thereafter |
| A bind device loses its name or disappears | The event's delivery: the tunnel is disconnected at once; nothing is reconnected until a device of the name exists |
| An address is added to or removed from a bind device or VRF member | One reconnect; one second per failed reconnect thereafter |
| The source of an unbound tunnel is removed | One reconnect; one second per failure |
| A disconnected tunnel's peer becomes reachable | At most one second |
| A resolver's answer changes | Thirty seconds after the previous lookup returned, plus the lookup's own bound ([V4](resolvers.md#queries-and-answers)); one more second to apply |
| A tolerated configuration mistake is corrected by reload | The reload |
| Held identifiers become free | At most thirty seconds, or the next reload |
| A session device is seen down with a deferred hardware-address change | The event's delivery |
| `bindv6only` found set with the option on | The next socket creation or reconcile, at most one second while anything is retried |
| Notifications lost | The reopening of the subscription, then one resync of every binding and every connected tunnel |
| A reload | One reconcile; one second per retry while an operation fails |
