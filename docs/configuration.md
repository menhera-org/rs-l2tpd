# Configuration and error handling

[Documentation index](README.md)

The daemon reads `/etc/rs-l2tpd.toml`, then every `*.toml` file in
`/etc/rs-l2tpd.toml.d/` in lexicographic order. Later files override
individual keys. `rs-l2tpd --check` prints the merged result as it would be
applied and exits with status 1 if it found any problem.

A configuration mistake does not stop the daemon: what can be applied is
applied, and the rest is reported. An empty configuration, including one
emptied by mistakes, is valid. The supplied systemd unit has
[configuration path restrictions](installation.md#supplied-systemd-unit).

## Example

```toml
[tunnels.uplink]
tunnel_id = 10
peer_tunnel_id = 10          # defaults to tunnel_id
remote_addr = "peer.example.org"   # an address or a host name
ip_version = "V6"            # "V4" or "V6": required for a host name, implied by an address
bind_interface = "vrf-wan"   # optional: SO_BINDTODEVICE

[sessions.lan]
tunnel_name = "uplink"
session_id = 100             # unique on the host, whatever the tunnel
peer_session_id = 100        # defaults to session_id
interface_name = "l2tp0"
interface_hwaddr = "02:00:5e:00:53:01"   # optional, unicast
cookie = "0011223344556677"  # optional: 8 or 16 hex digits, sent in every frame
peer_cookie = "8899aabb"     # optional, defaults to cookie: required in every received frame
```

Identifiers are non-zero. Tunnel identifiers, session identifiers and
interface names are each unique on the host. L2TPv3 over IP delivers
frames by session identifier alone, so a session identifier cannot repeat
even across tunnels. A literal `remote_addr` is a unicast address of the
`ip_version` family; loopback is allowed for testing.

See [sessions](sessions.md) for MAC and cookie behavior, and
[operation](operation.md) for binding, readiness and discard peers.

## Mistakes

| Mistake | At start-up | On reload |
|---|---|---|
| Unusable endpoint: `remote_addr` missing, neither an address nor a host name, not unicast or of the wrong family; `ip_version` invalid, or missing for a host name | The tunnel and its sessions are created, connected to the discard address of its family (`100::`, or `192.0.0.8` for an IPv4 tunnel), where frames are dropped; warning | The same; a correction reconnects the tunnel in place |
| `interface_hwaddr` not a unicast address | The session is created with the kernel's address; warning | The same; a correction applies the address in place |
| Any other mistake in an entry: a missing, zero or duplicate identifier, an invalid interface name or cookie | The entry is left out, a tunnel with its sessions; warning | The entry keeps the values in force; a new entry is left out; warning |
| A file that cannot be inspected, read or parsed, or a configuration directory that cannot be listed | Discoverable, readable files are used; warning | The previous configuration is kept as a whole |
| An entry's previous values no longer fit the rest, such as an identifier now taken by another entry | | The previous configuration is kept as a whole |

A tunnel with an unusable endpoint keeps the family its `ip_version` names,
or that of its literal address, so that an IPv4 tunnel with a mistake needs
no IPv6 on the host. For comparison, 0.1.5 accepted a wrong-family literal
and retried the tunnel forever, and it ignores the cookie keys silently.

A literal peer that cannot be reached is not a mistake: see
[peers that cannot be reached yet](operation.md#peers-that-cannot-be-reached-yet).
Identifiers that another tunnel or session on the host already holds are
refused by the kernel, not by the configuration; see
[identifiers in use](operation.md#identifiers-in-use).

An absent file or directory is allowed. A failed lookup, such as a
permission error or symlink loop, is an error rather than a request to
remove its configuration.
