# Session identity, hardware addresses and cookies

[Documentation index](README.md)

## Interface identity

Session interfaces are tracked by their link lifetime, so renames by udev
or networkd are supported without confusing a reused index with the old
device. A session interface is recreated only when its session must
change in the kernel: its identifiers, its peer identifier, its cookies or
its `tunnel_name`, or its tunnel's identifiers; and when its
configuration entry is removed or renamed. Other configuration changes,
including mistakes and a changed `bind_interface` of its tunnel, preserve
the interface. The daemon never takes a session interface down to apply a
MAC change, including during initial creation.

## Hardware addresses

Every new session is created under a temporary name with the
project-specific prefix `rsl2tp-t`, followed by six hexadecimal digits
from a random source, and published under its configured name only once
it is ready, with or without `interface_hwaddr`. Temporary names used to
resolve rename cycles use `rsl2tp-r`. Both check for collisions and stay
within Linux's 15-byte name limit; neither uses generic prefixes such as
`v`. Ordinarily, the daemon applies and verifies a configured MAC before
publishing the configured name. A network manager
can activate even the temporary device through a match such as
`Type=l2tpeth`. If it does, the daemon preserves the active interface and
defers its MAC change until the
interface is down. Readiness does not wait for this deferred change.
Configurations that require a particular MAC before activation must let
rs-l2tpd prepare the device before activating it, for example by matching
its final name.

This is a kernel API limitation: L2TP session creation cannot specify a
MAC address. The device becomes visible with a random MAC before rs-l2tpd
can issue its separate MAC-setting request. There is no guaranteed ordering
against networkd or another manager that matches the temporary device by
type or other properties; making that request faster cannot eliminate the
race. See the kernel's [L2TP attributes](https://github.com/torvalds/linux/blob/master/include/uapi/linux/l2tp.h)
and [Ethernet pseudowire driver](https://github.com/torvalds/linux/blob/master/net/l2tp/l2tp_eth.c).

Preparation or publication errors, including a final name occupied by a
foreign device, are retried every second on the same pending session,
which stays under its temporary name meanwhile and counts for readiness.
They do not delete an interface that another manager may already be
using, and the foreign device is never touched. Removing that session
from the configuration or changing a kernel creation parameter still
removes it.

`ip link` shows the current name. `ip l2tp show session` may retain the
temporary name because the kernel records that name at creation.

For an active session, a MAC change is deferred until the interface is
seen down, for example after `ip link set <name> down`. The kernel accepts
a new address only while the interface is down, and taking a running
interface down can drop addresses, routes and neighbours on both the
parent and its children, including children in other network namespaces.
Removing the key restores the original address under the same rule.

## Child interfaces and other managers

Network managers may rename a session interface and attach VLAN, macvlan
or other child interfaces. Moving those children to another network
namespace, as container managers such as LXD or Incus do, does not change
the identity of the parent. Reconnection, unchanged reloads and deferred
MAC updates preserve the parent and its children. rs-l2tpd manages neither
their addresses nor their routes.

Keep the session parent in the daemon's network namespace. Moving or
deleting the parent invalidates its tracked identity; the daemon must not
modify a replacement that reuses its index. Link notification loss also
invalidates identities that can no longer be proved. Neither stops existing
traffic or underlay reconnection. A name or MAC change requested for such
a session is skipped and reported once; the reload completes, and every
other entry is applied. New sessions acquire fresh tracked identities after
the monitor reopens.

What removing or re-creating such a session does depends on how its
identity was lost. After an observed removal from the namespace, the
daemon asks the kernel: a session the kernel no longer has was deleted,
and it is created again, as any configured object the kernel lacks; a
session the kernel still has was moved (its device lives in another
namespace), and it is left alone, never deleted through identifiers a
foreign object may reuse. After a loss of notifications, the kernel's own
record decides: a session the kernel still reports under the interface
name it was given at creation is the daemon's own and is deleted by that
name, in one operation with the check, so that its re-creation with new
cookies, or its removal, succeeds. The same
record lets a session whose notifications were lost while it was still
being prepared be deleted and created again, when its device cannot be
identified again at its registration index by its temporary name, so that
readiness is reached even when a burst of link changes overflows the
monitor during startup.
Restoring management of a session whose device was moved away requires
controlled tunnel recreation or a daemon stop and start, which also
removes dependent children.

Linux cannot atomically validate the recorded lifetime and then change or
delete the session. A privileged manager deleting and replacing it during
that gap remains outside this guarantee.

Explicit session removal, changes requiring recreation and daemon shutdown
delete the parent; a `SIGUSR2` restart does not
([restart](operation.md#restart)). Linux can then delete its dependent children, including
children moved to other namespaces. Arrange container and network-manager
lifecycles accordingly; moving a child does not make it independent of
its parent.

## Session cookies

Without cookies, anyone who can send IP protocol 115 packets to the host
and knows a session identifier can inject frames into that pseudowire:
the kernel checks neither the sender's address nor the bind device.

A `cookie` of four or eight bytes is appended to every frame sent, and
`peer_cookie` is required in every frame received; the kernel discards
the rest. This end's `cookie` is the peer's `peer_cookie` and vice versa.
With one value for both directions, `cookie` alone suffices.

Cookies are off unless configured, which is the 0.1.5 wire format, so
enable them on both ends at once. Changing them recreates the session.
Frames stay in clear text: cookies are not encryption. `--check` prints
them; the logs do not. See the [configuration example](configuration.md#example)
for their hexadecimal representation.
