# Sessions

[Specification index](README.md)

## The right state of a session

S1. A session of the applied configuration has one right kernel state: an
L2TPv3 Ethernet pseudowire session in its tunnel with the configured
session identifier, peer session identifier and cookies, whose device
exists, bears the configured name unless another manager renamed it
([S10](#names)), carries the configured hardware address unless the change
is deferred or the device unmanageable ([S12](#hardware-addresses)), and
is the device the daemon created ([S19](#identity)).

S2. The daemon never changes a session device's administrative state: it
does not bring it up or down and does not add addresses or routes. Those
belong to the operator and other network managers, and a device that
another manager configured keeps that configuration through everything
the daemon does.

## Creation

S3. A session is created in its tunnel with its identifiers, cookies, no
sequence numbers, no layer-2-specific sublayer, and an explicit interface
name, so that the kernel never picks one from its own pool.

S4. The kernel assigns a random hardware address at creation and cannot
take one as a creation parameter. A session with a configured hardware
address is therefore **staged**: created under a temporary name
(`rsl2tp-t` followed by six hexadecimal digits, unique, checked for
collisions and within the kernel's length limit), given its address while
it is down, and only then renamed to its configured name, so that a manager
matching the configured name never sees the device with the wrong address.
A session without a configured address is created directly under its name.

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
foreign device is never touched.

## Identity

S8. The daemon addresses a session device by its link index, never by a
name, because names are reusable and the kernel records a session's name
only once, at creation. The index is captured from the kernel's
registration broadcast, observed by a subscription opened before the
creation request, so that a manager renaming the device immediately cannot
make the daemon address another device.

S9. A separate link-lifetime subscription, opened before the first
session, proves before every change that the index still refers to the
device created: the subscription saw no removal of that index since the
registration, and a lookup on the same socket, ordered after every
notification queued before it, finds the device. Linux cannot make this
proof and the change atomic; the interval is kept minimal.

## Names

S10. The configured name is the name the daemon gives the device at
creation or publication and when the configuration changes it. Another
manager may rename the device afterwards; the daemon follows the device,
not the name, accepts the rename and does not fight it. A later
configured rename applies to the device under whatever name it bears. A
configured rename to a name a foreign device holds is a transient failure.

S11. Several sessions may exchange names in one reload. Renames go through
temporary names (`rsl2tp-r` followed by six hexadecimal digits, unused on
the host) so that no step collides, and a collision batch advances past
foreign devices occupying candidate names.

## Hardware addresses

S12. The kernel accepts a new hardware address only while the device is
down, and lowering a running device drops its IPv6 addresses, routes and
neighbour state and those of its children, in every namespace. The daemon
therefore never lowers a device: a configured address, a changed address,
or the restoration of the kernel's address when the key is removed, is
applied at once when the device is down and deferred when it is up, until
the device is seen down. Readiness does not wait for a deferred change.
The deferral is reported once; the eventual application once. The daemon
applies the configured address at creation and when the configuration
changes it; an address another manager sets afterwards is not re-asserted,
because two managers re-asserting would never converge.

S13. An unusable configured address is a tolerated mistake: the device
keeps the kernel's address and a corrected address applies in place under
the same rule.

## Cookies

S14. Cookies are off unless configured; that is the 0.1.5 wire format and
the only one a 0.1.5 peer understands. `cookie` is appended to every frame
sent and `peer_cookie` required in every frame received; a frame without
the right cookie is dropped by the kernel. This end's `cookie` is the
peer's `peer_cookie` and vice versa.

S15. The kernel cannot change a session's cookies: a change re-creates the
session. The new device is created under the configured name once the old
one is gone, and the identifiers are reused.

S16. Cookie values are never logged.

## Changes applied in place

S17. `interface_name` and `interface_hwaddr` change in place, as does
anything about the tunnel that changes in place. `session_id` (a removal
and an addition), `peer_session_id`, `cookie`, `peer_cookie` and
`tunnel_name` re-create the session; a re-creation of the tunnel re-creates
its sessions.

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
  a replacement.
- **Loss of notifications**: the subscription overflowed, or its socket
  stopped answering; the device may or may not still be the one created.
  A new subscription is opened and seeded; devices created afterwards get
  fresh proofs, identities captured before cannot be proved again.

S20. A session whose proof ended is **unmanageable** for changes to its
device: a requested rename or hardware-address change is skipped,
recorded as applied so that it is not attempted every second, and reported
once per session with the reason. The reload completes; every other entry
is applied. Existing traffic and underlay reconnection are unaffected.

S21. After an observed removal, removing the session from the
configuration or re-creating it forgets the session without deleting
anything through its identifiers, because a foreign session may hold them
now; the kernel object, if any, remains until its tunnel is torn down. A
re-creation that the kernel then refuses is a conflict and is handled as
one.

S22. After a loss of notifications, the kernel's own record decides: the
session is deleted through its identifiers if, and only if, the kernel
still reports it under the interface name the daemon gave it at creation
(a foreign session with the same identifiers would carry another name).
That makes removal and re-creation with new cookies work, and lets a
session whose notifications were lost while it was still staged be
identified again or deleted and created again, so that readiness is
reached even when a burst of link changes overflows the subscription at
boot.

S23. A session still being prepared whose device can no longer be proved
is first re-identified at the index the registration broadcast reported,
if the device there still bears the temporary name; otherwise it is
removed through the kernel's record and created again, at most once per
attempt, with ordinary retries thereafter.

S24. The daemon MUST NOT, after any loss, modify a device that reuses the
index of a former session device, even if it bears the configured name.

## Removal

S25. A session that leaves the configuration is deleted through its
identifiers, with the proof of S9 or S22, and its device disappears with
it. Deletion failures that mean the object is already gone are successes.

S26. Deleting a tunnel deletes its sessions: the daemon still deletes the
sessions it can prove first, so that identifiers and names are released
deterministically before the tunnel is torn down.

## External deletion

S27. A session deleted in the kernel by an operator while it remains in
the configuration MUST be created again, as any desired object the kernel
lacks: the observed removal of its device followed by the kernel reporting
no session with its identifiers is the proof that it is gone, as opposed
to moved. A device moved to another namespace, whose session the kernel
still has, is not re-created. This is a [known gap](README.md#known-gaps):
today the daemon notices such a deletion only when the session's
configuration changes or at restart.
