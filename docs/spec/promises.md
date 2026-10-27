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
| G1 | The daemon never panics, aborts or exits because of a configuration, a kernel reply, a DNS answer, a notification, its loss, or anything another process does. It exits on request, when the process itself cannot be set up, or when an embedding program's reload callback panics. | [P19](process.md#crashes), [L11](library.md#errors) |
| G2 | The daemon never modifies, deletes or adopts an object it did not create or can no longer prove it created: no foreign tunnel, session, device, route or address, whatever name or identifier it carries. | [M9](model.md#ownership), [M10](model.md#ownership), [S24](sessions.md#identity-loss), [D8–D9](discard.md#the-null-device) |
| G3 | A session interface's identity (its index, and so its addresses, routes, neighbour state and children) changes only when the kernel cannot change the session in place: its identifiers, its cookies, or its tunnel's identifiers. Everything else, including every mistake and its correction, every peer, source, binding or family change, every rename and every hardware-address change, keeps the interface. | [M11](model.md#identity), [S17](sessions.md#changes-applied-in-place), [T22–T23](tunnels.md#changes-applied-in-place) |
| G4 | The daemon never takes a running device down and never undoes what another manager did to a device. | [S2](sessions.md#the-right-state-of-a-session), [S12](sessions.md#hardware-addresses) |
| G5 | A tunnel is never connected to a peer the configuration does not name now, and frames of a tunnel without a peer never leave the host unless the operator routed the discard address out. A tunnel with a bind device never sends through another device. | [T17](tunnels.md#peers-that-cannot-be-reached), [D3](discard.md#addresses), [T13](tunnels.md#bind-devices) |
| G6 | One entry's problem never delays, blocks or takes down another entry, except a session's dependence on its own tunnel. | [M4](model.md#reconciliation), [T25](tunnels.md#identifier-conflicts), [S20](sessions.md#identity-loss) |
| G7 | A reload never takes a running entry down because of a mistake; the worst outcome of a bad reload is that nothing changes. | [C12](configuration.md#reload) |
| G8 | Readiness is never reported while a tunnel or session of the applied configuration is missing from the kernel, with one bounded exception: an entry whose identifiers another object holds after ten retries, which is reported as left out. Readiness never waits for DNS, for a route to a peer, for a bind device, for IPv6, for a deferred hardware-address change or for `network-online.target`. | [P6–P8](process.md#readiness) |
| G9 | No kernel tunnel or session of the daemon's outlives the process: tunnels are owned by sockets. | [P18](process.md#crashes), [T8](tunnels.md#creation-and-identifiers) |
| G10 | The daemon changes no global kernel setting, needs no capability beyond `CAP_NET_ADMIN` and `CAP_NET_RAW`, makes no `bpf()` call and loads no module itself. | [R1–R6](requirements.md#the-host), [H9](hosts.md#containers-and-namespaces) |
| G11 | Cookies are never logged. Nothing that changes the wire format or the kernel's acceptance of frames is on unless configured; a 0.1.5 configuration keeps working and 0.1.5 peers interoperate. | [S14](sessions.md#cookies), [O5](observability.md#logging) |
| G12 | The cost of an event is bounded by the entries it concerns; events concerning nothing cost at most a comparison, and route churn is dropped in the kernel. The daemon never loops without delay and holds a bounded number of timers. | [M15–M16](model.md#timing), [E9](events.md#route-events) |
| G13 | A lasting condition is reported once when it begins and once when it ends; retries are silent. | [O3](observability.md#logging) |
| G14 | The same rules apply through the library: `Service`, `blocking::Service` and `Runtime` are the daemon without its process, and the public API changes compatibly. | [library](library.md) |

## Conditional promises

Given the requirements, in addition:

| | Promise | Where specified |
|---|---|---|
| G15 | **Readiness in bounded time.** The parent exits 0 and the PID file appears as soon as every entry exists; on a host that routes the discard addresses, or whose peers are reachable, that is as soon as the kernel has created them; on a host without such routes, at most ten seconds per family in use after the first tunnel needed one; with identifiers held elsewhere, at most ten seconds for the entries concerned. | [P6–P9](process.md#readiness), [D6](discard.md#routes) |
| G16 | **Existence.** From readiness on, every entry's tunnel and session exist continuously, except during a re-creation required by G3, which happens within one reconcile. | [M1](model.md#reconciliation), [T24](tunnels.md#changes-applied-in-place) |
| G17 | **Convergence.** After every event that changes an entry's right state, the kernel state converges to it in place, within the bounds below, counted from the event's delivery. | [events](events.md) |
| G18 | **Stability.** An unchanged configuration, reloaded or reconciled again, changes nothing in the kernel: no reconnect, no rename, no address change. | [M2](model.md#reconciliation), [E17](events.md#operator-events) |
| G19 | **Fidelity.** When the host allows it, the kernel state equals the configuration: the real peer, the configured name, the configured hardware address, the configured cookies, bound to the configured device, with a source address that exists on the host; substitutes (discard addresses, the kernel's hardware address, a temporary name) exist only while the host does not allow the configured state, and are replaced as soon as it does. | [T1](tunnels.md#the-right-state-of-a-tunnel), [S1](sessions.md#the-right-state-of-a-session), [M7–M8](model.md#the-degradation-ladder) |
| G20 | **Shutdown.** Everything owned is removed in order, sessions before tunnels, identifiers are free within two seconds per tunnel, the PID file is removed, and the exit code says whether every step succeeded. | [P16–P17](process.md#shutdown) |
| G21 | **Early start.** The daemon starts and reaches readiness before the network is configured, so that the network can be built on its interfaces. | [P1](process.md#start-up), [H6](hosts.md#address-families) |
| G22 | **Compatibility.** A correctness fix never introduces a connectivity failure that 0.1.5 did not have; the readiness semantics and the systemd unit contract are kept. | [contracts](../contracts.md#compatibility) |
| G23 | **Resources.** Memory is bounded by the size of the configuration plus the monitor buffers; descriptors by the number of tunnels plus a constant; neither grows with the number of events handled. | [R9–R10](requirements.md#the-host), [M16](model.md#scale) |

### Convergence bounds

The bound is the delay after which the kernel state is right, provided
the host then allows it; each retry interval is added once per obstacle
still present.

| Event | Bound |
|---|---|
| A device of a configured bind name appears or is replaced | The event's delivery, then one reconnect; one second per failed reconnect thereafter |
| A bind device loses its name or disappears | The event's delivery: the binding is recorded invalid at once; nothing is reconnected until a device of the name exists |
| An address is added to or removed from a bind device or VRF member | One reconnect; one second per failed reconnect thereafter |
| The source of an unbound tunnel is removed | One reconnect; one second per failure |
| A pending peer becomes reachable | At most one second |
| A host name's answer changes | At most thirty seconds to notice, one more to apply |
| A tolerated configuration mistake is corrected by reload | The reload |
| Held identifiers become free | At most thirty seconds, or the next reload |
| A session device is seen down with a deferred hardware-address change | The event's delivery |
| A discard route the daemon installed is removed | One repair; one second per failure |
| The host starts routing a discard address during the grace | The next retry, at most one second |
| Notifications lost | The reopening of the subscription, then one resync of every binding, tunnel and discard route |
| A reload | One reconcile; one second per retry while an operation fails |
