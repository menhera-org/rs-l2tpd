# Session identity, hardware addresses and cookies

[Documentation index](README.md)

## Interface identity

Session interfaces are tracked by index, so renames by udev or networkd
are supported. A session interface is recreated only when its session must
change in the kernel: its peer identifier or cookies, or its tunnel's
identifiers or bind device. Other configuration changes, including
mistakes, preserve the interface. The daemon never takes an existing,
published session interface down to apply a MAC change.

## Hardware addresses

When `interface_hwaddr` is configured, a new session is created under a
temporary name. The daemon applies and verifies its MAC before publishing
the configured name. A network manager can activate even the temporary
device through a match such as `Type=l2tpeth`; the daemon may take this new
device down to set its MAC, preserving its previous up state when publishing
the final name. It retries preparation on that staged device for a bounded
period; preparation that still fails is cleaned up and retried.

`ip link` shows the current name. `ip l2tp show session` may retain the
temporary name because the kernel records that name at creation.

For an existing session, a MAC change is deferred until the interface is
seen down, for example after `ip link set <name> down`. The kernel accepts
a new address only while the interface is down, and taking a running
interface down would drop its IPv6 addresses, routes and neighbours.
Removing the key restores the original address under the same rule.

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
