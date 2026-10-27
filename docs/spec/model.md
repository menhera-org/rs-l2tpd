# Model

[Specification index](README.md)

## Terms

- **Configuration**: the `tunnels`, `sessions` and `resolvers` maps, keyed
  by configuration name, and the `host` settings, after the files were
  merged and converted. The **accepted configuration** is the one in
  force: the last one the daemon accepted, at start-up or from a reload,
  tolerated mistakes already corrected ([C13](configuration.md#reload)).
- **Entry**: one tunnel, one session or one resolver of the configuration.
- **Kernel state**: the L2TP tunnels and sessions the kernel holds, the
  session devices (`l2tpeth`) and the tunnel sockets.
- **Owned object**: a kernel object the daemon created and can still prove
  it created. A tunnel is owned through the socket the daemon holds; a
  session device through its tracked link lifetime; a session through the
  kernel's own record of its creation-time interface name
  ([K16](kernel.md#facts)).
- **Foreign object**: anything else, including an object that reuses a name
  or an identifier of an owned object that no longer exists.
- **Real peer**: the configured literal address, or the selected answer of
  the tunnel's resolver ([V5](resolvers.md#queries-and-answers)). A tunnel
  **has no peer** while neither exists.
- **Connected**: the tunnel socket's last connect succeeded and the socket
  is established; **disconnected** otherwise. A disconnected tunnel exists,
  its sessions exist, and the kernel drops every frame they send
  ([K5](kernel.md#requirements)).
- **Eligible for readiness**: every tunnel and session of the accepted
  configuration except an entry left out for an identifier conflict after
  the bounded retries ([T25](tunnels.md#identifier-conflicts)) and, with it,
  the sessions of a left-out tunnel.
- **Ready**: every eligible entry exists in the kernel
  ([P6](process.md#readiness)).

## Reconciliation

M1. The daemon is a reconciler. At every reconcile it derives, for every
entry of the accepted configuration, the **right kernel state** from the
configuration and the current host state, compares it with the state it
holds, and applies the difference. The right state of a tunnel is defined
in [T1](tunnels.md#the-right-state-of-a-tunnel), that of a session in
[S1](sessions.md#the-right-state-of-a-session), and that of a resolver in
[V1–V2](resolvers.md#model).

M2. A reconcile MUST be idempotent for converged entries: an entry whose
kernel state is right and whose relevant host state is unchanged is not
touched by a second run on the same inputs, and an unchanged
configuration reloaded causes no kernel change for it. Entries with
pending work (a conflict, a name not yet published, a deferred or
unfinished operation, a disconnected tunnel whose peer may now be
reachable) are retried by every reconcile, including an identical reload.

M3. A reconcile MUST keep partial progress. When applying an entry fails,
everything applied before stays applied and recorded, and the next
reconcile continues from there. Nothing is rolled back to make a failure
look clean.

M4. Entries are independent. A failure of one entry MUST NOT keep another
entry from being applied in the same reconcile, with one exception: a
session cannot be applied before its tunnel. A tunnel that cannot be
applied takes its sessions with it, and only them.

M5. A reconcile is triggered by: start-up, a reload, the retry timer while
an earlier reconcile left something unapplied, and the periodic retry of
entries left out for a conflict ([T25](tunnels.md#identifier-conflicts)).
Kernel, resolver and timer events do not run a full reconcile; they run
the handler of the entries they concern ([events](events.md)).

M6. Operations on the kernel are ordered by three rules, not by a fixed
phase list: a provable child is deleted before its parent (sessions before
their tunnel, [S26](sessions.md#removal)); every identifier and name that
an operation needs is released before the operation that claims it
(deletions and renames to temporary names before creations and final
renames, [S11](sessions.md#names), [T24](tunnels.md#changes-applied-in-place));
and operations with no such dependency proceed independently of each
other's failure ([M4](#reconciliation)). Shutdown applies the same rules to
the empty configuration ([P16](process.md#shutdown)).

## The degradation ladder

M7. Every entry is applied in the most useful state the host allows right
now, in this order of preference, and promoted as soon as a better state
becomes possible:

1. The configured state: connected to the real peer, bound to the
   configured device, with the configured name and hardware address.
2. The same entry with a tolerated mistake corrected by the daemon: the
   kernel's hardware address instead of an unusable one; no peer instead
   of an unusable endpoint.
3. The entry with a working but temporary substitute: disconnected while
   the real peer cannot be reached or resolved, or while the bind device
   is absent; a temporary name while the configured name is held by a
   foreign device.
4. The entry kept as it is, with a requested change skipped, when the
   change cannot be made safely (an interface whose identity cannot be
   proved).
5. The entry left out for now, with a bounded retry, when the kernel
   refuses its identifiers.
6. The entry retried every second, with readiness withheld, when the
   kernel cannot create it at all (missing support, missing privilege).

M8. Moving down the ladder MUST NOT change an interface's identity
([M11](#identity)), and moving up MUST happen in place as soon as the
obstacle is gone, without waiting for a reload. The only identity changes
are those of the [identity matrix](#identity-matrix); a lost staging
identity ([S23](sessions.md#identity-loss)) is recovered by re-creation
because nothing else can recover it.

## Ownership

M9. The daemon MUST NOT modify, delete or adopt a foreign object, whatever
name or identifier it carries. It MUST NOT change a foreign device, even
one that reuses the index or the name of a former owned device.

M10. Before every change to an owned object the daemon MUST have proof,
obtained after the last event that could have replaced the object, that
the object is still its own. Where Linux cannot make the proof and the
change atomic, the interval between them MUST be as short as possible and
the residual risk is accepted and documented ([S9](sessions.md#identity),
[S22](sessions.md#identity-loss)).

## Identity

M11. A session interface's identity is its link index for the lifetime of
the device. The daemon MUST NOT re-create a session, and so its interface,
except by an operation the [identity matrix](#identity-matrix) marks as
re-creating. Every other change, including a configuration mistake and
its correction, a rename, a hardware-address change, a peer change, a
bind-device change and a reconnection, keeps the interface.

M12. A tunnel socket's identity is the socket. The daemon MUST NOT replace
it except by an operation the matrix marks as re-creating. Peers, device
bindings, source addresses and the connected state change on the same
socket; the socket family changes only by re-creation.

## Identity matrix

M17. The complete list of operations and their effect on identity. An
operation not listed here keeps every identity; adding a re-creating
operation needs a reason the kernel imposes ([A21](architecture.md#extension)).

| Operation | Tunnel socket | Session interface | Reason |
|---|---|---|---|
| `remote_addr`, `ip_version`, `resolver_name`, `bind_interface` changed; endpoint mistake corrected; peer, source or connected state changed | kept | kept | in place ([T22](tunnels.md#changes-applied-in-place)) |
| `interface_name`, `interface_hwaddr` changed or corrected; rename or address set by another manager | — | kept | in place ([S17](sessions.md#changes-applied-in-place)) |
| `tunnel_id` or `peer_tunnel_id` changed | re-created | re-created | the kernel cannot change them ([T23](tunnels.md#changes-applied-in-place)) |
| `session_id`, `peer_session_id`, `cookie`, `peer_cookie`, `tunnel_name` changed | kept | re-created | the kernel cannot change them ([S17](sessions.md#changes-applied-in-place)) |
| A tunnel or session entry renamed in the configuration | re-created | re-created | a removal and an addition ([C14](configuration.md#semantics-of-changes)) |
| An entry removed from the configuration; shutdown | removed | removed | explicit ([C12](configuration.md#reload), [P16](process.md#shutdown)) |
| A session deleted in the kernel by an operator | — | re-created | the object is gone ([S27](sessions.md#external-deletion)) |
| A staged session whose identity was lost before publication | — | re-created at most once per attempt | nothing else can recover it ([S23](sessions.md#identity-loss)) |
| The socket family changes (an `AF_INET` host gaining `AF_INET6`, or [T26](tunnels.md#hosts-with-bindv6only)) | kept until the entry is next re-created for another reason | kept | the family is never a reason to re-create ([T4](tunnels.md#address-families)) |
| A restart without descriptor hand-over | removed and re-created | removed and re-created | process lifetime ([P14](process.md#restart)) |
| A restart with descriptor hand-over | kept | kept | the sockets survive the process ([P14](process.md#restart)) |

## Monitor generations

M18. Identity proofs belong to a **generation** of the link-lifetime
subscription. A generation begins when the subscription is opened and
seeded, and ends when it overflows or its socket fails
([E20](events.md#monitor-loss)). A proof from an ended generation is
invalid; a session created in the new generation gets a proof of the new
generation. Loss on the event monitor, which is a different socket, ends
no generation: it causes a resync of bindings and connected tunnels and
nothing else. Loss on the lifetime subscription ends the generation and
makes every identity captured in it unprovable, whether or not the event
monitor lost anything.

## Enforced fields

M19. For each session the daemon records, per field, what it is entitled
to enforce: a **configured** value it applies when the host allows; a
**deferred** value it will apply when the device is down
([S12](sessions.md#hardware-addresses)); a **skipped** value it recorded
as applied because the device is unmanageable
([S20](sessions.md#identity-loss)); and an **acknowledged override**, a
rename or hardware address another manager applied afterwards, which the
daemon keeps ([S10](sessions.md#names), [S12](sessions.md#hardware-addresses)).
A configuration change of the field clears the override and the skip and
makes the new value configured again; removing `interface_hwaddr` makes
the hardware address the kernel assigned at creation the configured
value, applied under the same deferral rule.

## Failure classes

M13. Every failure the daemon meets is one of:

- **Transient**: a route, address, device or kernel object not there yet,
  a kernel still finishing a deletion, a peer that cannot be connected to
  now ([T16](tunnels.md#peers-that-cannot-be-reached)). Retried, every
  second while a reconcile is incomplete and otherwise by the handler's
  own timer. Never reported more than once per episode at warning level;
  an episode begins with the first failure and ends with the first
  success, and a change of errno within it is reported at debug level.
- **Lasting conflict**: identifiers held by another tunnel or session.
  Retried a bounded number of times, then the entry is left out and tried
  again slowly and on every reload ([T25](tunnels.md#identifier-conflicts)).
- **Unmanageable**: an owned object whose ownership can no longer be
  proved. The change is skipped and reported once; the object is left
  alone ([S20](sessions.md#identity-loss)).
- **Host defect**: no L2TP support, no privilege, no netlink, a refused
  tunable. Retried every second, reported once, readiness withheld
  because the interfaces the network depends on cannot exist; a defect
  that affects only a resolver withholds nothing ([V12](resolvers.md#dhcpv6-information-request)).
- **Configuration mistake**: handled at load time, never at apply time
  ([configuration](configuration.md)).
- **Defect of the daemon**: an outcome the kernel gives only to a wrong
  sequence of operations (`EAFNOSUPPORT` from a connect,
  [K24](kernel.md#facts); `EPERM` from a device binding,
  [K22](kernel.md#facts)). Reported at error level with the operation,
  then handled as transient; a test that provokes one fails.

## Timing

M14. Intervals are fixed and documented, measured on a monotonic clock
that does not advance while the host is suspended (`CLOCK_MONOTONIC`),
unaffected by wall-clock changes. A timer is fixed-delay: it is armed
when its condition arises and re-armed after each attempt, so that a slow
attempt never causes a burst.

| Interval | Value |
|---|---|
| Reconcile retry while incomplete | 1 s |
| Reconnect retry after a failed reconnect | 1 s per bound device, one timer per device; one shared timer for unbound tunnels |
| Disconnected tunnel with a real peer: connect retry | 1 s, one shared timer |
| Conflict retries before an entry is left out | 10 attempts, a second apart, the first attempt counted |
| Retry of left-out entries | 30 s, and every reload |
| Resolver refresh | 30 s after the previous lookup returned; a lookup is bounded per kind; answers polled every 1 s ([V4](resolvers.md#queries-and-answers)) |
| Resolver host-defect retry | 30 s ([V12](resolvers.md#dhcpv6-information-request)) |
| Wait for a deleted tunnel to leave the kernel | up to 2 s |
| Host tunable re-check | at every socket creation and every reconcile ([P25](process.md#host-tunables)) |

M15. The daemon MUST NOT poll where it can be notified, and MUST NOT loop
without delay. Every timer is bounded in number: one per bound device, one
for unbound reconnects, one for disconnected tunnels and left-out
entries, one per resolver.

## Scale

M16. The cost of handling an event MUST be bounded by the number of
entries it concerns, not by the number of events on the host. Events that
concern no entry (an address change on a device no tunnel is bound to, a
link change of an unrelated device) MUST cost at most a comparison
against the daemon's own records, without a kernel query, and SHOULD be
dropped before they reach the daemon where the host allows a filter
([K10](kernel.md#requirements)). Without the filter the bound is the same
per event, and the number of events is the host's; the cost is buffer
space and, under bursts, a resync ([R6](requirements.md#the-host)). A
rename event is matched against the configured bind names and the owned
indexes by lookup, not by scanning the configuration. Memory is bounded
by the current configuration plus the monitor buffers plus the resolver
state; records of removed entries are released at the reconcile that
removes them.
