# Configuration and error handling

[Documentation index](README.md)

The daemon reads its main file, then every file in its drop-in directory
whose name ends in `.toml` (in any ASCII case), in ascending byte order of
their names. Later files override individual keys; a table a later file
mentions is merged, not replaced. Files whose name starts with `.` are
ignored, and file names need not be valid UTF-8. The paths default to
`/etc/rs-l2tpd.toml` and `/etc/rs-l2tpd.toml.d/`; both can be changed at
build time and on the command line (see `rs-l2tpd --help`).
`rs-l2tpd --check` prints the merged result as it would be applied and
exits with status 1 if it found any problem, an unknown key included.

A configuration mistake does not stop the daemon: what can be applied is
applied, and the rest is reported. An empty configuration, including one
emptied by mistakes, is valid. The supplied systemd unit has
[configuration path restrictions](installation.md#supplied-systemd-unit).

## Example

```toml
[tunnels.uplink]
tunnel_id = 10
peer_tunnel_id = 10          # defaults to tunnel_id
remote_addr = "peer.example.org"   # an address, fe80::1%eth0 style for link-local, or a host name
ip_version = "V6"            # "V4" or "V6": required for a host name, implied by an address
bind_interface = "vrf-wan"   # optional: an interface or a VRF; it need not exist yet
resolver_name = "wan-dns"    # optional, host names only: defaults to the system resolver

[resolvers.wan-dns]
method = "ipv6"              # "ra", "dhcpv6" or "ipv6" (both); or addresses = ["192.0.2.53", "[2001:db8::53]:5353"]
bind_interface = "wan0"      # required with method: a link, not a VRF

[sessions.lan]
tunnel_name = "uplink"
session_id = 100             # unique on the host, whatever the tunnel
peer_session_id = 100        # defaults to session_id
interface_name = "l2tp0"
interface_hwaddr = "02:00:5e:00:53:01"   # optional, unicast
cookie = "0011223344556677"  # optional: 8 or 16 hex digits, sent in every frame
peer_cookie = "8899aabb"     # optional, defaults to cookie: required in every received frame

[host]
fix_bindv6only = true        # default: keep net.ipv6.bindv6only at 0, see operation
```

Identifiers are 1 to 2^32-1. Tunnel identifiers, session identifiers and
interface names are each unique on the host. L2TPv3 over IP delivers
frames by session identifier alone, so a session identifier cannot repeat
even across tunnels. A literal `remote_addr` is a unicast address of the
`ip_version` family (an IPv4-mapped IPv6 literal counts as IPv4); loopback
is allowed for testing. A link-local peer needs a zone or a
`bind_interface`. A host name is ASCII letters, digits, hyphens and dots,
at most 253 bytes. Interface names are 1 to 15 bytes without `/`, `:`,
`%` or whitespace.

A resolver either lists name servers in `addresses`, or discovers them on
its `bind_interface` with `method`: router advertisements (`"ra"`),
DHCPv6 Information-Request (`"dhcpv6"`), or both (`"ipv6"`). DHCPv6
identifies itself with a DUID-LL from the interface's MAC address by
default (`dhcpv6_identity = "link-layer"`); `"anonymous"` sends no client
identifier, `"random"` a new random one at every start, and `dhcpv6_duid`
an exact one. See [resolvers](spec/resolvers.md) in the specification.

See [sessions](sessions.md) for MAC and cookie behavior, and
[operation](operation.md) for binding, readiness and disconnected tunnels.

## Mistakes

| Mistake | At start-up | On reload |
|---|---|---|
| Unusable endpoint: `remote_addr` missing, neither an address nor a host name, not unicast or of the wrong family; `ip_version` invalid, or missing for a host name | The tunnel and its sessions are created; the tunnel stays disconnected, and the kernel drops what its sessions send; warning | The same; a correction connects the tunnel in place |
| `interface_hwaddr` not a unicast address | The session is created with the kernel's address; warning | The same; a correction applies the address in place |
| `resolver_name` on a literal address | Applied, the key ignored; warning | The same |
| An unknown key | Ignored; warning; `--check` exits 1 | The same |
| Any other mistake in an entry: a missing, zero, out-of-range or duplicate identifier, an invalid name or cookie, an unknown `tunnel_name` or `resolver_name`, a link-local peer without a zone on an unbound tunnel, an invalid resolver | The entry is left out, a tunnel with its sessions, a resolver with its tunnels; error | The entry keeps the values in force; a new entry is left out; warning |
| A file that cannot be inspected, read or parsed, a dangling symbolic link, or a configuration directory that cannot be listed | Discoverable, readable files are used; the problem names the file | The previous configuration is kept as a whole; the refused reload is an error |
| An entry's previous values no longer fit the rest, such as an identifier now taken by another entry | | The previous configuration is kept as a whole; the refused reload is an error naming the entry |

Whether a reload is refused never depends on the names of the entries: a
retained entry (a hard mistake with its old values in force) that
collides with a new valid entry refuses the reload, naming the retained
entry.

A tunnel with an unusable endpoint keeps the family its `ip_version`
names, or that of its literal address. For comparison, 0.1.5 accepted a
wrong-family literal and retried the tunnel forever, and it ignores the
cookie keys silently.

A literal peer that cannot be reached is not a mistake: see
[peers that cannot be reached yet](operation.md#peers-that-cannot-be-reached-yet).
Identifiers that another tunnel or session on the host already holds are
refused by the kernel, not by the configuration; see
[identifiers in use](operation.md#identifiers-in-use).

An absent file or directory is allowed. A failed lookup, such as a
permission error, a symlink loop or a dangling symbolic link, is an error
rather than a request to remove its configuration.

Renaming a `[tunnels.*]` or `[sessions.*]` entry is a removal and an
addition: its kernel objects are re-created. See the
[identity matrix](spec/model.md#identity-matrix) for which changes apply
in place.
