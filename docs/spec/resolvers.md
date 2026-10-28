# Resolvers

[Specification index](README.md)

How a host name in `remote_addr` becomes a peer address: through the
system resolver by default, or through a resolver the configuration names,
given by address or by a discovery method, with an optional bind interface.
The mechanism is implemented in the `iphost` crate (version 0.4.0 adds the
configured resolvers and the unified `ipv6` method); this page states the
behaviour the daemon requires of it.

## Model

V1. A configuration MAY define resolvers in the `resolvers` table
([C16](configuration.md#resolver-entries)), keyed by name. A tunnel whose
`remote_addr` is a host name names one of them with `resolver_name`, or
uses the system resolver when the key is absent. A tunnel with a literal
`remote_addr` uses no resolver; a `resolver_name` on such a tunnel is a
tolerated mistake: ignored with a warning.

V2. A resolver is one of four kinds, chosen by its fields:

| Kind | Fields | Name servers |
|---|---|---|
| Address | `addresses`: one or more literal IPv4 or IPv6 addresses, each with an optional port (`[2001:db8::53]:5353`, `192.0.2.53:5353`), port 53 by default; `bind_interface` optional | The listed servers, tried in order |
| Router advertisements | `method = "ra"`; `bind_interface` required | The servers of the RDNSS options received on the bind interface ([V10](#router-advertisements)) |
| DHCPv6 Information-Request | `method = "dhcpv6"`; `bind_interface` required | The servers a DHCPv6 server returns on the bind interface ([V12](#dhcpv6-information-request)) |
| IPv6 (unified) | `method = "ipv6"`; `bind_interface` required | Both of the above at once, DHCPv6 servers first ([V14](#the-unified-ipv6-method)) |

A resolver with both `addresses` and `method`, or with `method` and no
`bind_interface`, is a hard mistake ([C10](configuration.md#start-up)).
All four kinds are part of the first implementation; none is optional,
and a `method` value outside the three defined ones is a hard mistake.

V3. The system resolver is the libc resolver of the build: on glibc the
host's NSS configuration, on musl `/etc/resolv.conf` and `/etc/hosts` and
nothing else. The daemon does not read those files itself
([L1](library.md#boundaries)); it asks the libc. Answer order, timeouts and
search-domain handling are the libc's, and no rule below depends on them.

## Queries and answers

V4. For every tunnel with a host name, the daemon has the tunnel's
resolver look the host name up (both families at once; the answer of the
family `ip_version` names is the one used) every thirty seconds
([M14](model.md#timing)), and at once when the tunnel's configuration or
its resolver's configuration changes. Lookups run on threads of the
resolver and never block the reconciler ([A9](architecture.md#concurrency));
the reconciler learns of a changed answer through the resolver's change
notification, or by polling every second. Lookups for one host name run
one at a time, and each is bounded by the bound the resolver library
states for its kind: for the address kind, ten seconds per configured
server, because each server is asked twice with a five-second timeout
per query (over UDP, then over TCP within the same five seconds when the
answer was truncated) and the first server that answers ends the lookup;
for the discovery kinds, three seconds of waiting for the first servers
plus thirty seconds, because at most three discovered servers are used.
The next refresh is sent thirty seconds after the previous lookup
returned, so a slow or failing resolver stretches the period and never
piles lookups up. The address kind asks the configured servers directly:
the hosts file and the special names of the system resolver
(`localhost`) play no part in it.

V5. An **answer** is the list of addresses a lookup returned. An address
is **usable** when it is a unicast address of the requested family: not
unspecified, not multicast, not the IPv4 broadcast address, and for `V6`
not an IPv4-mapped address. The **selected** address is the previously
selected one while the answer still contains it, otherwise the first
usable address of the answer, so that a change in the order of an answer
never causes a reconnect; it is the tunnel's real peer
([T14](tunnels.md#peers)). Unusable addresses are skipped, with one
warning per answer that contains any.

V6. An answer stays in force until a later answer for the same host name
from the same resolver replaces it. A lookup that fails (resolver
unreachable, error, timeout) and a negative answer (no record of the
family) both keep the previous answer in force, so that a working tunnel
is never disconnected by a resolver outage; the condition is reported once
when it begins and once when it ends ([O3](observability.md#logging)).
Keeping a family's address through a negative answer is an option of the
resolver library and MUST be enabled (`retain_stale_values`); keeping the
cache through a failed lookup is its default, and a lookup in which one
family's query fails while the other's succeeds keeps the failed family's
address whatever the option, because only a negative answer settles a
family. A tunnel that never had an
answer has no real peer and is disconnected
([T16](tunnels.md#peers-that-cannot-be-reached)).

V7. Answers belong to a host name, a family and a resolver. A changed
host name, a changed `ip_version` or a changed `resolver_name` on reload
discards the answers in force and queries anew; nothing else does. An
answer of the other family is never used.

V8. Readiness never waits for a resolver ([P7](process.md#readiness)); a
resolver that never answers leaves its tunnels disconnected and reported
once.

## Binding

V9. A resolver with `bind_interface` sends its queries from sockets bound
to that device by name, a fresh socket per query, so that the kernel
resolves the name inside the bind, the configured name stays
authoritative ([T11](tunnels.md#bind-devices)), and no capability is
needed ([K22](kernel.md#facts)). For the address kind the device may be
a VRF, which routes the queries in the VRF's table
([K28](kernel.md#facts)); a link-local name server then needs a zone in
its address, because only a link supplies a scope. For `ra`, `dhcpv6`
and `ipv6` the bind interface MUST be a link (an interface that carries
advertisements and DHCPv6 traffic, which may be a VRF member), never a
VRF device; the resolver's sockets are tied to that link, so it works on
a VRF member without the `l3mdev_accept` sysctls. While the device does
not exist the resolver's lookups fail and its tunnels keep their answers
in force ([V6](#queries-and-answers)); the device may appear later.

## Router advertisements

V10. For `method = "ra"` (and as half of `ipv6`, [V14](#the-unified-ipv6-method)) the resolver speaks ICMPv6 itself on the
bind interface from a raw ICMPv6 socket, which needs `CAP_NET_RAW`
([K39](kernel.md#requirements)): it receives Router Advertisements
(type 134, code 0) directly, accepting only those with a link-local
source, hop limit 255 and arrival on the bind interface, and takes their
RDNSS options. The socket is bound to the interface (`SO_BINDTODEVICE`),
filtered in the kernel to type 134 (`ICMP6_FILTER`), because a raw
ICMPv6 socket otherwise receives every ICMPv6 packet of the namespace,
and reads the hop limit and the arrival interface from ancillary data
(`IPV6_RECVHOPLIMIT`, `IPV6_RECVPKTINFO`), which is the only way the
three checks can be made. And it **solicits**, sending Router Solicitations (type
133, to `ff02::2`, hop limit 255) up to three times four seconds apart
until the first advertisement arrives, again whenever the interface is
created or re-created, so that servers are learned at once instead of at
the next periodic advertisement. When the raw socket cannot be opened
for lack of the capability, the resolver falls back to the kernel's
`RTNLGRP_ND_USEROPT` group ([K14](kernel.md#requirements)); the two are
alternatives, never used together. The fallback works only where
`accept_ra` is enabled on the interface ([K40](kernel.md#facts)), and
interfaces managed by systemd-networkd and similar daemons usually have
it disabled, because the manager processes advertisements in user space;
the raw socket is therefore required, not optional, for this method
([R4](requirements.md#the-host)). An advertisement replaces the server
list: each server of its RDNSS options is in force for the option's
lifetime, a lifetime of zero withdraws the server, and the servers of the
previous advertisement that it does not repeat are dropped. Servers whose
lifetimes have expired are still used while no unexpired server exists,
so that a router outage does not end resolution. A link-local server
address is used with the interface as its scope. DNSSL options are
ignored. Advertisements are multicast, so the daemon neither competes
with nor disturbs other consumers of them and needs nothing from them.

V11. A loss of the daemon's own notifications ([E20](events.md#monitor-loss))
does not touch the resolvers: each owns its sockets and keeps its servers
and answers; nothing is re-read or re-solicited for it. The daemon's
event monitor does not subscribe to `RTNLGRP_ND_USEROPT`: advertisements
reach the resolver through its own sockets ([E23](events.md#resolver-events)).

## DHCPv6 Information-Request

V12. For `method = "dhcpv6"` (and as half of `ipv6`, [V14](#the-unified-ipv6-method)) the resolver sends an Information-Request
(RFC 8415 section 18.2.6) to `ff02::1:2` from UDP port 546 on the bind
interface, requesting the DNS Recursive Name Server option (23) and the
Information Refresh Time option (32), with RFC 8415's retransmission
timing (initial 1 s, maximum 1 h, randomised by ±10 %) until a Reply with
its transaction id, a matching or absent Client Identifier and a success
status arrives. The servers of the Reply are in force until the next
Reply, also past the refresh time; the request is repeated at the
Information Refresh Time the server gave, or every 24 hours when it gave
none, and never more often than every 10 minutes (RFC 8415 section
21.23), and at once when the interface is created or re-created. All
resolvers on one interface share one socket on port 546, tied to the
interface and bound to the unspecified address, so that a system client
bound to the interface's own address (systemd-networkd) keeps receiving
its Replies ([K38](kernel.md#facts)); every resolver keeps only the
Replies to its own transactions. Nothing else is
taken from DHCPv6. The client socket is bound with `SO_REUSEADDR` and
`SO_BINDTODEVICE`, both set before `bind`, so that it binds beside
another DHCPv6 client on the host that also set `SO_REUSEADDR`; the
kernel's sharing needs the option on both sockets, and beside a client
that did not set it the bind fails `EADDRINUSE`, which is handled exactly
as the refused port below (reported once, retried every thirty seconds,
an `ipv6` resolver falling back to its RDNSS servers). This method
exists mainly for VRFs, where the system resolver breaks and where no
system DHCPv6 client (systemd-networkd or the like) holds port 546, so the
port is normally free. When a system client does hold it, that client is
bound to the interface's address and the kernel prefers it over the
resolver's wildcard socket ([K38](kernel.md#facts)), so the resolver
never takes Replies away from it and simply gets none: coexistence is
tolerated, not relied upon, and the condition shows as a resolver without
servers, retried by the normal timing. The client identifier, with the default
`dhcpv6_identity = "link-layer"`, is a DUID-LL (DUID type 3, RFC 8415
section 11.4: the two-byte type 3, the two-byte hardware type 1 for
Ethernet, then the address) built from the bind interface's Ethernet
address, so it is the same at every start while the device keeps its
address: the daemon reads
the address over rtnetlink (`RTM_GETLINK`, `IFLA_ADDRESS`,
[A5](architecture.md#layers)) when the resolver starts and hands the
resolver the real six-byte address, never a DUID; the resolver forms the
DUID from it and always uses the Ethernet hardware type. A device whose
address is not a six-byte Ethernet address (`ifi_type` other than
`ARPHRD_ETHER`) counts as a device without a hardware address below. The
identifier is kept for the resolver's lifetime, so a later change of the
device's address does not change it.
The other values of `dhcpv6_identity` ([C16](configuration.md#resolver-entries)):
`"anonymous"` sends no Client Identifier at all, the anonymity profile of
RFC 7844, and reads nothing from the device; `"random"` sends a DUID-LL
made from a random locally administered unicast address generated when
the resolver starts, kept for its lifetime and never written to disk;
and `dhcpv6_duid` gives an exact DUID (3 to 130 bytes) for a network
that expects a registered one. With the default `"link-layer"`, a bind
interface without a hardware address (`ARPHRD_NONE`, as a point-to-point
tunnel device) cannot form a DUID-LL: a `dhcpv6` resolver on it is a
hard mistake of the entry, and an `ipv6` resolver on it uses router
advertisements only ([V14](#the-unified-ipv6-method)); with any other
value such a device is fine. Port 546 needs [K13](kernel.md#requirements); without
it a `dhcpv6` resolver is reported once as a host defect, retried every
thirty seconds, and its tunnels stay disconnected, while an `ipv6`
resolver falls back to its RDNSS servers ([V14](#the-unified-ipv6-method));
readiness is not withheld.

## The unified IPv6 method

V14. For `method = "ipv6"` the resolver runs both discovery methods on
the bind interface at once: router advertisements
([V10](#router-advertisements)) and Information-Requests
([V12](#dhcpv6-information-request)). Precedence is by source: while the
DHCPv6 source has servers in force, only they are queried; otherwise the
router-advertisement servers are, so DHCPv6 takes precedence while
whichever source works suffices. Either source being absent, expired or
failing (no router advertises servers, no DHCPv6 server answers, port
546 refused, the raw socket refused) is not a failure of the resolver as
long as the other source has a server; the resolver starts if either
source starts, and is reported as without servers only when both are
empty. A lookup waits up to three seconds for the first servers from
either source. The lifetimes and refresh rules of each source apply
unchanged.

## Resources

V15. A resolver of the address kind owns no socket between lookups; one
of the `ra` kind owns one raw ICMPv6 socket and one thread; one of the
`dhcpv6` kind owns one thread, and all resolvers on one interface share
one UDP socket and one receiving thread; one of the `ipv6` kind owns
both. Lookups run on one refresh thread per host name, one at a time,
each with one helper thread for its duration, because the two families
are queried in parallel; there is no shared runtime.
These are bounded by the number of configured resolvers and interfaces
and count toward [G23](promises.md#conditional-promises).

## Resolver events

V13. Events concerning resolvers and what they cause:

| Event | Effect |
|---|---|
| An answer in force changes | The tunnels using it are reconnected to the selected address ([T15](tunnels.md#peers), [T28](tunnels.md#peer-changes)) |
| A resolver's configuration changes on reload | Its answers are discarded and queried anew ([V7](#queries-and-answers)) |
| A resolver named by a tunnel is removed from the configuration | The tunnel's entry has a hard mistake whose values in force still name the resolver, so the reload is refused as a whole, naming the tunnel ([C12](configuration.md#reload)) |
| The bind device of a resolver appears or disappears | Nothing is done by the daemon: lookups bind to the device when it exists and fail while it does not ([V9](#binding)); answers in force are kept |
| An RDNSS lifetime expires | The server is used only while no unexpired server exists ([V10](#router-advertisements)); answers in force are kept ([V6](#queries-and-answers)) |
| Notifications are lost | Nothing: the resolvers own their sockets and keep their servers and answers ([V11](#router-advertisements)) |
| Shutdown | Queries are abandoned; nothing is removed, because resolvers create no kernel object |
