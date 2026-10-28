# Sessions

[Specification index](README.md)

## The right state of a session

S1. A session of the accepted configuration has one right kernel state: an
L2TPv3 Ethernet pseudowire session in its tunnel with the configured
session identifier, peer session identifier and cookies, whose device
exists, bears the configured name unless another manager renamed it
([S10](#names)), carries the configured hardware address unless the change
is deferred, the device unmanageable, or another manager changed it
afterwards ([S12](#hardware-addresses), [M19](model.md#enforced-fields)),
and is the device the daemon created ([S19](#identity-loss)).

S2. The daemon never changes a session device's administrative state: it
does not bring it up or down and does not add addresses or routes. Those
belong to the operator and other network managers, and a device that
another manager configured keeps that configuration through everything
the daemon does.

## Creation

S3. A session is created in its tunnel with its identifiers, cookies, no
sequence numbers, no layer-2-specific sublayer, and an explicit interface
name without a `%` ([K32](kernel.md#facts)), so that the kernel never
picks one from its own pool. A session is created whether or not its
tunnel is connected ([K5](kernel.md#requirements)).

S4. The kernel assigns a random hardware address at creation and cannot
take one as a creation parameter ([K31](kernel.md#facts)). Every session
is therefore **staged**: created under a temporary name (`rsl2tp-t`
followed by six hexadecimal digits, unique, chosen from the kernel's
random source (`getrandom`, never a counter, the time or the process
identifier, because the proof of [S22](#identity-loss) rests on the name
being unpredictable), checked against the namespace's device names and
within the kernel's length limit), given its configured address while it is down when one is
configured, and only then renamed to its configured name, so that a
manager matching the configured name never sees the device with the
wrong address. One creation path serves sessions with and without a
configured address.

S5. A manager can match the temporary device nonetheless (by type, by the
random address) and bring it up or attach children before the daemon has
finished. The daemon MUST NOT lower such a device: the address change is
deferred ([S12](#hardware-addresses)) and the device is published under
its configured name as it is.

S6. When staging or publication fails (a temporary failure, the configured
name occupied by a foreign device), the created kernel session and its
device are kept and the step is retried at the next reconcile, so that
children a manager attached are not destroyed by the retry. The session
is removed only when it leaves the configuration, when a creation
parameter changes, or when it can no longer be identified
([S20](#identity-loss)).

S7. Creation refused for an identifier already in use is a conflict
([T25](tunnels.md#identifier-conflicts)). A configured name occupied by a
foreign device is a transient failure of publication, retried every
second, with the session kept under its temporary name meanwhile; the
foreign device is never touched. A temporary name occupied by a foreign
device at creation makes the kernel refuse the creation without leaving a
session behind ([K20](kernel.md#facts)); the daemon picks another.

## Identity

S8. The daemon addresses a session device by its link index, never by a
name, because names are reusable and the kernel records a session's name
only once, at creation ([K16](kernel.md#facts)). The index is captured
from the kernel's registration broadcast, observed by the link-lifetime
subscription opened before the creation request, so that a manager
renaming the device immediately cannot make the daemon address another
device. The broadcast is matched to the creation request by the temporary
name and nothing else: the name is unique at that instant because the
kernel refuses a taken name ([K20](kernel.md#facts)), and the broadcast
is sent while the kernel still holds the lock that a rename needs
(`l2tp_eth_create` registers the device and copies its name under
`rtnl`), so the first broadcast of that name is the device created. The
index is never obtained by a lookup by name, which would race a rename.

S9. The link-lifetime subscription, opened before the first session,
proves before every change that the index still refers to the device
created: the subscription saw no removal of that index since the
registration, and a lookup on the same socket, ordered after every
notification queued before it, finds the device. The proof belongs to the
subscription's generation ([M18](model.md#monitor-generations)). Linux
cannot make this proof and the change atomic; the interval is kept
minimal.

## Names

S10. The configured name is the name the daemon gives the device at
publication and when the configuration changes it. Another manager may
rename the device afterwards; the daemon follows the device, not the
name, accepts the rename as an acknowledged override
([M19](model.md#enforced-fields)) and does not fight it. A later
configured rename applies to the device under whatever name it bears. A
configured rename to a name a foreign device holds is a transient
failure. The kernel allows renaming a device that is up
([K31](kernel.md#facts)).

S11. Several sessions may exchange names in one reload, and a removed
session's name may be taken by a surviving one. Renames go through
temporary names (`rsl2tp-r` followed by six hexadecimal digits, unused in
the namespace) so that no step collides, under the ordering rules of
[M6](model.md#reconciliation); a collision batch advances past foreign
devices occupying candidate names.

## Hardware addresses

S12. The kernel accepts a new hardware address on an l2tpeth device only
while the device is down ([K31](kernel.md#facts)), and lowering a running
device drops its IPv6 addresses by default ([K33](kernel.md#facts)) and
its routes and neighbour state and those of its children, in every
namespace. The daemon therefore never lowers a device: a configured
address, a changed address, or the restoration of the creation-time
address when the key is removed, is applied at once when the device is
down and deferred when it is up, until the device is seen down. Readiness
does not wait for a deferred change. The deferral is reported at every
reconcile that carries it, an exception to [O3](observability.md#logging)
so that a reload shows the operator why the address did not apply; the
eventual application is reported once. The daemon applies the configured address at
creation and when the configuration changes it; an address another
manager sets afterwards is an acknowledged override and is not
re-asserted, because two managers re-asserting would never converge.

S13. An unusable configured address is a tolerated mistake: the device
keeps the kernel's address and a corrected address applies in place under
the same rule.

## Cookies

S14. Cookies are off unless configured; that is the 0.1.5 wire format and
the only one a 0.1.5 peer understands. `cookie` is appended to every frame
sent and `peer_cookie` required in every frame received; a frame without
the right cookie is dropped by the kernel. This end's `cookie` is the
peer's `peer_cookie` and vice versa. Cookies are the only admission
control the kernel applies to data: a frame carrying a session's
identifier is delivered whatever its source address or ingress device
([K15](kernel.md#facts)), so a session without `peer_cookie` accepts
frames from anyone who can reach the host with IP protocol 115 and knows
the identifier, and does so whether or not its tunnel is connected
([T1](tunnels.md#the-right-state-of-a-tunnel)); anything stricter is the
host's packet filter. A 4-byte cookie is a 32-bit secret carried in clear
in every frame; a session exposed to untrusted senders SHOULD use 8-byte
cookies.

S15. The kernel cannot change a session's cookies: a change re-creates the
session. The new device is created under the configured name once the old
one is gone, and the identifiers are reused; a refusal meanwhile is a
transient conflict ([T25](tunnels.md#identifier-conflicts), [K18](kernel.md#facts)).

S16. Cookie values are never logged.

## Changes applied in place

S17. `interface_name` and `interface_hwaddr` change in place, as does
anything about the tunnel that changes in place. `session_id` (a removal
and an addition), `peer_session_id`, `cookie`, `peer_cookie` and
`tunnel_name` re-create the session; a re-creation of the tunnel re-creates
its sessions ([M17](model.md#identity-matrix)). Those fields, with the
tunnel's own kernel identity ([T23](tunnels.md#changes-applied-in-place)),
are the session's **kernel identity**: a session entry of a reload is the
same session as an entry of the accepted configuration when its tunnel
is the same tunnel and `session_id`, `peer_session_id`, `cookie` and
`peer_cookie` are unchanged, an absent `peer_cookie` comparing as its
default, whatever the entry's configuration name
([C14](configuration.md#semantics-of-changes)).

## Children and other managers

S18. Managers may attach VLAN, macvlan, ipvlan or other child interfaces to
a session device, in the daemon's namespace or moved to another, as
container managers do. Children are never managed, counted or restored by
the daemon. Every operation the daemon performs in place (rename, deferred
hardware-address change, peer change, reconnection, reload) keeps the
parent and so its children. A re-creation or a removal of the parent
removes the children with it, in every namespace; this is the operator's to
arrange around.

## Identity loss

S19. Two things end the proof of S9, and they are told apart:

- **Observed removal**: the subscription saw the index leave the
  namespace, because the device was deleted, or moved to another namespace
  as a container manager's `physical` device. The index may now belong to
  a replacement: the kernel never gives a freed index to a newly created
  device before its 31-bit counter wraps, but a device moved in from
  another namespace keeps its old index whenever that index is free here
  (`__dev_change_net_namespace`), which is why [S24](#identity-loss) is
  needed.
- **Loss of notifications**: the lifetime subscription overflowed, or its
  socket stopped answering ([E21](events.md#monitor-loss)); the device may
  or may not still be the one created. A new generation is opened and
  seeded ([M18](model.md#monitor-generations)); devices created afterwards
  get fresh proofs, identities captured before cannot be proved again.
  Loss on the event monitor alone ends no proof.

S20. A session whose proof ended is **unmanageable** for changes to its
device: a requested rename or hardware-address change is skipped,
recorded as applied ([M19](model.md#enforced-fields)) so that it is not
attempted every second, and reported once per session with the reason.
The reload completes; every other entry is applied. Existing traffic and
underlay reconnection are unaffected. The state is permanent for the
session: nothing re-proves a published device, because the kernel's
session record holds a name and no index ([K16](kernel.md#facts)) and a
lookup by name is the race [S8](#identity) refuses. The session becomes
manageable again only when it is created anew: by a re-creating change
of its entry ([S17](#changes-applied-in-place)), or at the next start.
The one report of this rule says so and names the change that would
re-create the session.

S21. After an observed removal, removing the session from the
configuration or re-creating it forgets the session without deleting
anything through its identifiers, because a foreign session may hold them
now; the kernel object, if any, remains until its tunnel is torn down,
which removes it ([K17](kernel.md#facts)). A re-creation that the kernel
then refuses is a conflict and is handled as one.

S22. After a loss of notifications, the kernel's own record decides: the
session is deleted if, and only if, the kernel still reports it under the
interface name the daemon gave it at creation ([K16](kernel.md#facts)),
and the deletion names that interface name (`L2TP_ATTR_IFNAME`) rather
than the identifiers, so that the check and the deletion are one kernel
operation. That makes removal and re-creation with new cookies work, and
lets a session whose notifications were lost while it was still staged
be identified again or deleted and created again, so that readiness is
reached even when a burst of link changes overflows the subscription at
boot. The limit of this proof is stated and accepted: a foreign session
created during the loss with the same identifiers and the same
creation-time name is indistinguishable from the daemon's own and would
be deleted; the temporary names of [S4](#creation) and [S11](#names) make
such a collision require deliberate imitation, and [R17–R18](requirements.md#the-operator)
forbid it.

S23. A session still being prepared whose device can no longer be proved
is first re-identified at the index the registration broadcast reported,
if the device there still bears the temporary name and the lifetime
subscription of the current generation finds it; otherwise it is removed
through the kernel's record ([S22](#identity-loss)) and created again, at
most once per attempt, with ordinary retries thereafter.

S24. The daemon MUST NOT, after any loss, modify a device that reuses the
index of a former session device, even if it bears the configured name.

## Removal

S25. A session that leaves the configuration is deleted, with the proof of
S9 or S22, and its device disappears with it. Deletion failures that mean
the object is already gone are successes.

S26. Deleting a tunnel deletes its sessions ([K17](kernel.md#facts)): the
daemon still deletes the sessions it can prove first, so that identifiers
and names are released deterministically before the tunnel is torn down.

## External deletion

S27. A session deleted in the kernel by an operator while it remains in
the configuration MUST be created again, as any desired object the kernel
lacks: the observed removal of its device, followed by the kernel
reporting no session with its identifiers, is the proof that it is gone,
as opposed to moved. The two observations may arrive in either order
([K18](kernel.md#facts)); the daemon queries the kernel after the removal
and acts on the answer. A device moved to another namespace, whose
session the kernel still has, is not re-created. This is a
[known gap](README.md#known-gaps): today the daemon does not re-create
such a session. It marks the device as no longer manageable, skips its
renames and hardware-address changes, and creates the session again only
when a reload changes a field that re-creates it, or at restart.
