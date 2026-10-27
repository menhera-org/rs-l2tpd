# Configuration

[Specification index](README.md)

## Files

C1. The daemon reads the main file (`/etc/rs-l2tpd.toml` unless built
otherwise), then every file whose name ends in `.toml`, compared without
regard to case, in the drop-in directory (`/etc/rs-l2tpd.toml.d/`), in
lexicographic order of file name. Other files in the directory are
ignored. The main file is always first, whatever its name.

C2. Each file is one TOML document. Documents are merged key by key: a
value in a later document replaces the value of the same key in an earlier
one; keys a later document does not mention keep their earlier value. A
key cannot be removed by a later document, only replaced.

C3. An absent main file or an absent directory is not a problem. A file
that cannot be inspected, read or parsed, or a directory that cannot be
listed, is a problem that names the file: at start-up the file is left out
and the rest is used; on reload the whole previous configuration stays in
force, because the entries of an unreadable file cannot be told apart from
intentional removals ([C12](#reload)).

C4. A symbolic link is followed. A link loop, a permission error or any
other failed lookup is an error, not a removal.

## Documents

C5. A document has two optional tables, `tunnels` and `sessions`, each a
map from configuration name to entry. Every field of an entry is optional
in a document, so that documents can be merged before validation. Values
that have a textual form (addresses, host names, names of interfaces,
hardware addresses, cookies, the address family) stay text until the
merged result is validated, so that a later document can replace an
invalid value.

C6. A value of the wrong type (a string where an integer is expected, a
table where a string is expected) fails the document. An unknown key MUST
be ignored, for forward compatibility, and SHOULD be reported as a
problem of the document that carries it ([known gap](README.md#known-gaps)).

## Tunnel entries

C7. Fields of a tunnel entry:

| Field | Rule |
|---|---|
| `tunnel_id` | Required. Integer, 1 to 2^32-1. Unique among tunnels. |
| `peer_tunnel_id` | Integer, 1 to 2^32-1. Defaults to `tunnel_id`. |
| `remote_addr` | Required. An IPv4 literal, an IPv6 literal or a host name. A literal MUST be a unicast address: not unspecified, not multicast, not the IPv4 broadcast address; loopback is allowed. |
| `ip_version` | `"V4"` or `"V6"`, either case. Required for a host name, where it selects which answers are used. Optional for a literal, whose family it then is; a literal of the other family is a mistake. |
| `bind_interface` | Optional. An interface name valid for the kernel: 1 to 15 bytes, no `/`, no whitespace, not `.` or `..`. The device need not exist. |

C8. Fields of a session entry:

| Field | Rule |
|---|---|
| `tunnel_name` | Required. The configuration name of a tunnel of the same configuration. |
| `session_id` | Required. Integer, 1 to 2^32-1. Unique among all sessions of the host, whatever their tunnel, because the kernel delivers L2TPv3-over-IP frames by session identifier alone. |
| `peer_session_id` | Integer, 1 to 2^32-1. Defaults to `session_id`. |
| `interface_name` | Required. A valid interface name, unique among sessions. |
| `interface_hwaddr` | Optional. Six hexadecimal octets separated by `:` or `-`, unicast, not all zero. |
| `cookie` | Optional. 8 or 16 hexadecimal digits: the cookie appended to every frame sent. |
| `peer_cookie` | Optional. 8 or 16 hexadecimal digits: the cookie required in every frame received. Defaults to `cookie`. |

C9. Uniqueness is checked across the merged configuration, in name order:
the later of two entries that collide is the one at fault.

## Start-up

C10. At start-up the merged configuration is converted leniently. Each
entry is one of:

| Condition | Effect |
|---|---|
| Valid | Applied as configured. |
| Unusable endpoint: `remote_addr` missing or neither a literal nor a host name; `ip_version` invalid, or missing for a host name; a literal that is not unicast or of the other family | Applied with the discard address of its family as peer, where frames are dropped. The family is the one `ip_version` names if it parses, else the literal's if it parses, else IPv6. Reported as a warning. |
| Unusable `interface_hwaddr` | Applied with the hardware address the kernel assigns. Reported as a warning. |
| Any other mistake: a missing, zero, out-of-range or duplicate identifier, a missing or invalid name, an invalid cookie, an unknown `tunnel_name`, a tunnel that was left out | Left out, and a left-out tunnel takes its sessions with it. Reported as an error. |

The result MAY be empty; that is a valid configuration. The daemon never
refuses to start because of a configuration.

C11. Tolerated mistakes (the second and third rows) are corrected in place
when a later reload fixes them: the tunnel is reconnected to the corrected
peer, the hardware address is applied once the interface is down, and the
interface keeps its identity.

## Reload

C12. On a reload the merged configuration is converted against the applied
configuration:

| Condition | Effect |
|---|---|
| A file problem ([C3](#files)) | The whole previous configuration stays in force; the reload is reported as refused. |
| Valid entry, tolerated mistake | As at start-up. |
| An entry with a hard mistake that exists in the applied configuration under the same name | Keeps the values in force, with a warning naming the mistake. |
| A new entry with a hard mistake | Left out, with a warning. |
| An entry whose previous values no longer fit the rest (an identifier or name now taken by another entry) | The whole previous configuration stays in force; the reload is reported as refused. |
| An entry no longer present | Removed from the kernel: a session's interface is deleted, a tunnel's socket closed with its sessions. |

So a mistake made while the daemon runs never takes a running tunnel or
session down, and a reload that cannot be made sense of changes nothing.

C13. The applied configuration, as reported by the control handle and used
as the base of the next reload, is the result of the last accepted reload,
tolerated mistakes already corrected. The daemon does not keep the text of
the files.

## Semantics of changes

C14. Which configuration changes are applied in place and which re-create
an object is defined in [T22](tunnels.md#changes-applied-in-place) and
[S17](sessions.md#changes-applied-in-place). Renaming a configuration
entry while keeping its identifiers is a removal and an addition: the
kernel objects are re-created. A reload MUST handle any mixture of
removals, additions and changes in one step, including swaps of interface
names between sessions and swaps of identifiers between entries, by
deleting before creating and renaming through temporary names.

## Library conversions

C15. The library offers the strict conversion, which fails on the first
problem of any kind and names the entry, and the two lenient conversions
of C10 and C12, which return the configuration together with every
problem, each problem carrying the entry kind, its name, what became of
it, and the underlying error. The strict conversion is what deserialising
a configuration type directly does.
