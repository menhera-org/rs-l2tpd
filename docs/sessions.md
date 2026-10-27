# Session identity, hardware addresses and cookies

[Documentation index](README.md)

## Interface identity

Session interfaces are tracked by their link lifetime, so renames by udev
or networkd are supported without confusing a reused index with the old
device. A session interface is recreated only when its session must
change in the kernel: its peer identifier or cookies, or its tunnel's
identifiers or bind device. Other configuration changes, including
mistakes, preserve the interface. The daemon never takes a session
interface down to apply a MAC change, including during initial creation.

## Hardware addresses

When `interface_hwaddr` is configured, a new session is created under a
temporary name with the project-specific prefix `rsl2tp-t`. Temporary names
used to resolve rename cycles use `rsl2tp-r`. Both use hexadecimal suffixes,
check for collisions, and stay within Linux's 15-byte name limit; neither
uses generic prefixes such as `v`. Ordinarily, the daemon applies and
verifies its MAC before publishing the configured name. A network manager
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

Preparation or publication errors, including an occupied final name, are
retried on the same pending session. They do not delete an interface that
another manager may already be using. Removing that session from the
configuration or changing a kernel creation parameter still removes it.

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
invalidates identities that can no longer be proved. Notification loss
itself does not stop existing traffic or underlay reconnection, but the
daemon refuses further MAC or name changes on those sessions. Removing an
unverifiable session from the
configuration forgets it without deleting a potentially foreign object;
an original session may remain until its owned tunnel is torn down.
Restoring management of those sessions requires controlled tunnel
recreation or a daemon restart, which also removes dependent children.
New sessions acquire fresh tracked identities after the monitor reopens.

Linux cannot atomically validate the recorded lifetime and then change or
delete the session. A privileged manager deleting and replacing it during
that gap remains outside this guarantee.

Explicit session removal, changes requiring recreation and daemon shutdown
delete the parent. Linux can then delete its dependent children, including
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
