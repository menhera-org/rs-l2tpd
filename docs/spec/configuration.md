# Configuration

[Specification index](README.md)

## Files

C1. The daemon reads the main file (`/etc/rs-l2tpd.toml` unless built
otherwise), then every file whose name ends in `.toml`, compared without
regard to ASCII case, in the drop-in directory (`/etc/rs-l2tpd.toml.d/`),
in ascending byte order of their file names. Other files in the directory
are ignored. The main file is always first, whatever its name. A file
whose name is not valid UTF-8 is ignored with a warning.

C2. Each file is one TOML document. Documents are merged key by key and
table by table, recursively: a value in a later document replaces the
value of the same key in an earlier one; keys a later document does not
mention keep their earlier value; a table a later document mentions is
merged, not replaced. A key cannot be removed by a later document, only
replaced. Example: the main file defines `tunnels.a` with `tunnel_id = 1`
and `remote_addr = "192.0.2.1"`; a drop-in says `[tunnels.a]
remote_addr = "192.0.2.2"`; the result has `tunnel_id = 1` and
`remote_addr = "192.0.2.2"`. To remove a field, edit the document that
defines it.

C3. An absent main file or an absent directory is not a problem. A file
that cannot be inspected, read or parsed, or a directory that cannot be
listed, is a problem that names the file: at start-up the file is left out
and the rest is used; on reload the whole previous configuration stays in
force, because the entries of an unreadable file cannot be told apart from
intentional removals ([C12](#reload)). A main file or directory that was
present at the last load and is absent now is a removal of its contents,
not a problem.

C4. A symbolic link is followed. A link loop, a dangling link, a
permission error or any other failed lookup is an error, not a removal.
Files are read one by one; a file replaced between the listing and its
reading is read in its new content, and one that disappears meanwhile is
treated as absent.

## Documents

C5. A document has four optional tables: `tunnels`, `sessions` and
`resolvers`, each a map from configuration name to entry, and `host`, a
table of settings ([C17](#host-settings)). Every field of an entry is
optional in a document, so that documents can be merged before
validation. Values that have a textual form (addresses, host names, names
of interfaces, hardware addresses, cookies, the address family, resolver
names) stay text until the merged result is validated, so that a later
document can replace an invalid value.

C6. A value of the wrong type (a string where an integer is expected, a
table where a string is expected) fails the document. An unknown key is a
problem of the document that carries it, named with the key's path: at
start-up and on reload it is ignored with a warning, for forward
compatibility; `--check` reports it and exits 1; the strict conversion
fails on it ([C15](#library-conversions)).

## Tunnel entries

C7. Fields of a tunnel entry:

| Field | Rule |
|---|---|
| `tunnel_id` | Required. Integer, 1 to 2^32-1. Unique among tunnels. |
| `peer_tunnel_id` | Integer, 1 to 2^32-1. Defaults to `tunnel_id`. |
| `remote_addr` | Required. An IPv4 literal (dotted quad), an IPv6 literal (RFC 4291 text form, optionally with a zone `%` followed by an interface name, which is valid only for a link-local address), or a host name: one to 253 bytes of labels of 1 to 63 ASCII letters, digits and hyphens, separated by dots, not beginning or ending with a hyphen, with an optional trailing dot that is removed; an IPv4-mapped IPv6 literal is an IPv4 literal. A literal MUST be a unicast address: not unspecified, not multicast, not the IPv4 broadcast address; loopback is allowed. A link-local IPv6 literal without a zone is valid only on a tunnel with a `bind_interface` ([T27](tunnels.md#link-local-peers)); otherwise it is a hard mistake. |
| `ip_version` | `"V4"` or `"V6"`, either case. Required for a host name, where it selects which answers are used. Optional for a literal, whose family it then is; a literal of the other family is a mistake. |
| `bind_interface` | Optional. An interface name valid for the kernel ([K32](kernel.md#facts)): 1 to 15 bytes, no `/`, no `:`, no `%`, no whitespace, no NUL, not `.` or `..`. The device need not exist. |
| `resolver_name` | Optional. The configuration name of a resolver ([C16](#resolver-entries)); meaningful only with a host name, ignored with a warning otherwise ([V1](resolvers.md#model)). Absent, the system resolver is used. |

## Session entries

C8. Fields of a session entry:

| Field | Rule |
|---|---|
| `tunnel_name` | Required. The configuration name of a tunnel of the same configuration. |
| `session_id` | Required. Integer, 1 to 2^32-1. Unique among all sessions of the configuration, whatever their tunnel, because the kernel delivers L2TPv3-over-IP frames by session identifier alone ([K15](kernel.md#facts), [K19](kernel.md#facts)). |
| `peer_session_id` | Integer, 1 to 2^32-1. Defaults to `session_id`. |
| `interface_name` | Required. A valid interface name as for `bind_interface`, unique among sessions. |
| `interface_hwaddr` | Optional. Six hexadecimal octets separated by `:` or `-`, either case, unicast, not all zero. |
| `cookie` | Optional. 8 or 16 hexadecimal digits, either case: the cookie appended to every frame sent. The kernel would accept other lengths up to 8 bytes ([K35](kernel.md#facts)); this specification allows only RFC 3931's 4 and 8 bytes. |
| `peer_cookie` | Optional. 8 or 16 hexadecimal digits: the cookie required in every frame received. Defaults to `cookie`. |

## Resolver entries

C16. Fields of a resolver entry ([resolvers](resolvers.md)):

| Field | Rule |
|---|---|
| `addresses` | A non-empty list of name-server addresses: an IPv4 or IPv6 literal as for `remote_addr`, optionally with a port (`192.0.2.53:5353`, `[2001:db8::53]:5353`), port 53 by default. A link-local IPv6 server needs a zone in its address unless `bind_interface` names a link (not a VRF). Exclusive with `method`. |
| `method` | `"ra"`, `"dhcpv6"` or `"ipv6"` (both, DHCPv6 preferred, [V14](resolvers.md#the-unified-ipv6-method)), either case. Exclusive with `addresses`; requires `bind_interface`, which must then be a link, not a VRF ([V9](resolvers.md#binding)). |
| `bind_interface` | An interface name as for a tunnel. Required with `method`, optional with `addresses`. |
| `dhcpv6_identity` | `"link-layer"` (default), `"anonymous"` or `"random"`, either case: the DHCPv6 client identifier. `"link-layer"` is a DUID-LL (DUID type 3, RFC 8415 section 11.4) with hardware type 1 (Ethernet) and the bind interface's six-byte address, stable across restarts of the daemon because it derives from the device. `"anonymous"` sends no Client Identifier (RFC 7844 anonymity profile). `"random"` is a DUID-LL from a random locally administered address, new at every start of the resolver. See [V12](resolvers.md#dhcpv6-information-request). Meaningful with `method = "dhcpv6"` or `"ipv6"`; ignored with a warning otherwise. |
| `dhcpv6_duid` | Optional. An exact Client Identifier as 6 to 260 hexadecimal digits (3 to 130 bytes), for a network that expects a registered DUID; exclusive with `dhcpv6_identity`. |

An entry with neither `addresses` nor `method`, with both, with `method`
and no `bind_interface` or with a VRF as `bind_interface`, with an
unknown `method` or `dhcpv6_identity` value, with both `dhcpv6_identity`
and `dhcpv6_duid`, with an invalid `dhcpv6_duid`, or with `"link-layer"`
identity on a device without a hardware address, is a hard mistake.

## Host settings

C17. Fields of the `host` table:

| Field | Rule |
|---|---|
| `fix_bindv6only` | Boolean, default `true`: whether the daemon keeps `net.ipv6.bindv6only` at 0 in its namespace ([P25](process.md#host-tunables)). |

C9. Uniqueness is checked across the merged configuration, in ascending
byte order of configuration names: the later of two entries that collide
is the one at fault. Resolver names are a separate space from tunnel and
session names.

## Start-up

C10. At start-up the merged configuration is converted leniently. Each
entry is one of:

| Condition | Effect |
|---|---|
| Valid | Applied as configured. |
| Unusable endpoint: `remote_addr` missing or neither a literal nor a host name; `ip_version` invalid, or missing for a host name; a literal that is not unicast or of the other family | Applied without a peer: the tunnel is created disconnected and its sessions exist ([T16](tunnels.md#peers-that-cannot-be-reached)). The family is the one `ip_version` names if it parses, else the literal's if it parses, else IPv6. Reported as a warning. |
| Unusable `interface_hwaddr` | Applied with the hardware address the kernel assigns. Reported as a warning. |
| `resolver_name` on a literal address | Applied, the key ignored. Reported as a warning. |
| Any other mistake: a missing, zero, out-of-range or duplicate identifier, a missing or invalid name, an invalid cookie, an unknown `tunnel_name` or `resolver_name`, a link-local literal without a zone on an unbound tunnel, an invalid resolver entry, a tunnel or resolver that was left out | Left out, and a left-out tunnel takes its sessions with it; a left-out resolver leaves the tunnels that name it out. Reported as an error. |

The result MAY be empty; that is a valid configuration. The daemon never
refuses to start because of a configuration.

C11. Tolerated mistakes (the second, third and fourth rows) are corrected
in place when a later reload fixes them: the tunnel is connected to the
corrected peer, the hardware address is applied once the interface is
down, and the interface keeps its identity.

## Reload

C12. On a reload the merged configuration is converted against the
accepted configuration:

| Condition | Effect |
|---|---|
| A file problem ([C3](#files)) | The whole previous configuration stays in force; the reload is reported as refused. |
| Valid entry, tolerated mistake | As at start-up. |
| An entry with a hard mistake that exists in the accepted configuration under the same name | Keeps the values in force, with a warning naming the mistake. |
| A new entry with a hard mistake | Left out, with a warning. |
| An entry whose previous values no longer fit the rest (an identifier or name now taken by another entry; a tunnel or resolver it depends on removed) | The whole previous configuration stays in force; the reload is reported as refused, naming the entry. |
| An entry no longer present | Removed from the kernel: a session's interface is deleted, a tunnel's socket closed with its sessions, a resolver's queries stopped. |

The conversion runs in two passes so that the outcome does not depend on
names. First, every entry of the new documents is validated on its own and
the valid ones are checked for uniqueness in name order ([C9](#tunnel-entries));
a new valid entry that collides with another new valid entry is left out
as the later one. Second, every retained entry (a hard mistake with
values in force) is checked against the result of the first pass; a
retained entry that collides with a new valid entry, or whose tunnel or
resolver is gone, makes the reload refused as a whole, naming the retained
entry, because the operator's new values and the old values in force
cannot both be honoured. Example: `a` had identifier 10 and `b` had 20; the
reload gives `a` a hard mistake and `b` identifier 10; the reload is
refused, naming `a`.

So a mistake made while the daemon runs never takes a running tunnel or
session down, and a reload that cannot be made sense of changes nothing.

C13. The accepted configuration, as reported by the control handle and
used as the base of the next reload, is the result of the last accepted
reload, tolerated mistakes already corrected. The daemon does not keep the
text of the files.

## Semantics of changes

C14. Which configuration changes are applied in place and which re-create
an object is defined in the [identity matrix](model.md#identity-matrix),
[T22](tunnels.md#changes-applied-in-place) and
[S17](sessions.md#changes-applied-in-place). Renaming a configuration
entry while keeping its identifiers is a removal and an addition: the
kernel objects are re-created. A reload MUST handle any mixture of
removals, additions and changes in one step, including swaps of interface
names between sessions, swaps of identifiers between entries, and a
removed session whose name a surviving session takes, under the ordering
rules of [M6](model.md#reconciliation): deleting and renaming to
temporary names before creating and renaming to final names.

## Library conversions

C15. The library offers the strict conversion, which fails on the first
problem of any kind, including an unknown key, and names the entry or the
document path at fault; and the two lenient conversions of C10 and C12,
which return the configuration together with every problem. Each problem
carries its kind: an entry problem names the entry kind and name, the
field at fault where there is one, what became of the entry, and the
underlying error; a document problem names the file and the key path. The
strict conversion is what deserialising a configuration type directly
does.
