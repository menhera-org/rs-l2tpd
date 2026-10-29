# Resolvers

[Specification index](README.md)

How a host name in `remote_addr` becomes a peer address: through the
system resolver by default, or through a resolver the configuration names,
given by address or by a discovery method, with an optional bind interface.
The mechanism is implemented in the `iphost` crate (version 0.4.0 adds the
configured resolvers and the unified `ipv6` method); this page states the
behaviour the daemon requires of it. The V10 protocol correction and the
V14 opt-in fallback are in version 0.4.1 (2026-10-29), produced by
[the upstream instruction](../upstream-iphost.md); 0.4.0 replaced the
RDNSS list on every advertisement and had no fallback.

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
search-domain handling are the libc's. There is no portable finite
deadline or safe thread cancellation for this call; `iphost` correctly
reports `Resolver::System.max_lookup_time() == None`. The daemon bounds
outstanding calls under V15, not their execution time. Convergence for a
new system-resolved name requires a worker to become available and libc
eventually to return; readiness, existing traffic and shutdown never wait
for it. Configured resolvers have a separate budget and remain usable if
all system calls stall.

## Queries and answers

V4. For every tunnel with a host name, the daemon has the tunnel's
resolver look the host name up (both families at once; the answer of the
family `ip_version` names is the one used), with a refresh eligible
thirty seconds after completion ([M14](model.md#timing)). A tunnel or
resolver configuration change makes a fresh lookup eligible immediately.
Lookups run on threads of the
resolver and never block the reconciler ([A9](architecture.md#concurrency));
the reconciler learns of a changed answer through the resolver's change
notification, or by polling every second. One current lookup per
host name and resolver incarnation is eligible at a time, subject to
V15's worker admission. Bounds below start when a worker begins the call;
queue time is separate. System lookups have no finite execution bound
(V3). The address kind takes at most ten seconds per configured server:
two attempts with a five-second absolute deadline per attempt, including
UDP and any TCP retry after truncation. RA-only and DHCPv6-only lookups
wait at most three seconds for servers, then query at most three servers
within thirty seconds. Unified `ipv6` with failure fallback (V14) waits
at most three seconds once, then spends at most thirty seconds on each
source, for a total bound of 63 seconds; families run in parallel.
The next refresh becomes eligible thirty seconds after the previous
lookup returned; overload coalesces pending work rather than queuing ticks.
A reload invalidates old results immediately (V7), but does not free an
in-flight worker until its call actually returns. The address kind asks
the configured servers directly:
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
The daemon keeps the answer in force itself, from the list of addresses
each lookup returns; it does not rely on the resolver library's own
cache or its retention options. A lookup in which one family's query
fails while the other's succeeds is a failed lookup for that family
only, because only a negative answer settles a family; the system
resolver cannot tell the two apart and its empty family counts as a
negative answer. A tunnel that never had an answer has no real peer and
is disconnected ([T16](tunnels.md#peers-that-cannot-be-reached)).

V7. Answers belong to a host name, a family and a resolver. A changed
host name, a changed `ip_version` or a changed `resolver_name` on reload
discards the answers in force and queries anew. A change of the named
resolver's configuration does the same, even when its name is unchanged.
Each lookup carries the incarnation of the resolver configuration and the
host name/family it serves; a result from an earlier incarnation is
ignored. No other change discards answers. An answer of the other family
is never used.

V8. Readiness never waits for a resolver ([P7](process.md#readiness)); a
resolver that never answers leaves its tunnels disconnected and reported
once.

## Binding

V9. A resolver with `bind_interface` sends its queries from sockets bound
to that device by name, a fresh socket per query, so that the kernel
resolves the name inside the bind, the configured name stays
authoritative ([T11](tunnels.md#bind-devices)), and no capability is
needed ([K22](kernel.md#facts)). For every kind, including the address kind, the bind interface MUST be
a link, never a VRF device. The daemon checks the device kind before
starting the resolver and after a replacement; it opens no resolver
socket on a VRF. A link may itself be a VRF member: the sockets are tied
to that link, so discovery works without the `l3mdev_accept` sysctls.
A link-local name server uses its explicit zone, or the bind link as its
scope; a configured zone must refer to that same link when a bind link
is given. An explicit zone also must resolve to a non-VRF link when no
bind interface is configured. Track these zone dependencies like bind
links. Device kind and scope are runtime checks made before using the
affected server; an invalid zone is not passed to the resolver library. While the device is absent,
while any resolver's bind or zone device is a VRF, while the zone does not refer to the configured bind
link, or while a link-local
server has neither an explicit zone nor a bind link supplying its scope,
the affected resolver operation waits and is retried every thirty seconds;
its tunnels keep their answers in force ([V6](#queries-and-answers)).
These conditions are reported once per episode and never remove an
accepted entry; a suitable device may appear later. A resolver whose
previously valid bind link disappears or is replaced by a VRF stops its
queries and discovery sockets, retaining only answers in force. The
daemon retries device validation every thirty seconds and on relevant
link events; it never deliberately selects a VRF device for the resolver
library. As with T10, lookup and socket binding are not atomic against
external replacement (M10); revalidate after a replacement is observed.

## Router advertisements

V10. For `method = "ra"` (and as half of `ipv6`, [V14](#the-unified-ipv6-method)) the resolver speaks ICMPv6 itself on the
bind interface from a raw ICMPv6 socket, which needs `CAP_NET_RAW`
([K39](kernel.md#requirements)): it receives Router Advertisements
(type 134, code 0) directly, accepting only those with a link-local
source, hop limit 255 and arrival on the bind interface, and takes their
RDNSS options. The socket is bound to the interface (`SO_BINDTODEVICE`),
filtered in the kernel to type 134 (`ICMP6_FILTER`), because a raw
ICMPv6 socket otherwise receives every ICMPv6 packet of the namespace,
reads the hop limit from ancillary data (`IPV6_RECVHOPLIMIT`), and takes
the arrival interface from the scope of the link-local source address,
which the kernel sets to the ingress device; the binding is set again
whenever the interface is re-created. And it **solicits**, sending Router Solicitations (type
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
([R4](requirements.md#the-host)). Process RDNSS entries individually,
keyed by address on the receiving interface, as
[RFC 8106 §6.2](https://www.rfc-editor.org/rfc/rfc8106.html#section-6.2)
specifies: a nonzero lifetime inserts or refreshes that address; zero
withdraws that address, including any stale copy. Omitted addresses keep
their lifetimes. An advertisement with no RDNSS changes nothing; several
options or advertisements, including those from different routers, never
replace the entire repository. Raw and netlink sources apply the same
updates; no timing heuristic groups netlink options into a replacement
snapshot.

The repository is bounded: at most 64 distinct server addresses per
resolver, including stale ones. On overflow, evict expired entries first,
then the earliest finite expiry, with infinite lifetimes last; use address
byte order to break ties. Explicit withdrawals are processed even when
full. Queries use at most three servers, with refreshed entries preferred
in their advertised order and omitted entries retained behind them.
As an explicit availability extension to RFC expiry behavior, expired
servers may still be queried while no unexpired server exists; explicit
withdrawal is never treated as expiry. This preserves the existing
`iphost` stale-server contract without discarding a live server merely
because a later advertisement omitted it. A link-local server address
uses the interface as its scope. DNSSL is ignored. Discovery creates no
host DNS configuration and does not modify another consumer's state.

V11. After event-monitor loss ([E20](events.md#monitor-loss)), revalidate
every resolver bind and zone dependency under V9. A dependency proved
unchanged keeps its discovery sockets, server lifetimes and answers;
loss alone does not flush servers or solicit again. An absent, replaced
or invalid dependency stops the affected operations; restart discovery
only after validation, retaining answers under V6. The event monitor
does not subscribe to `RTNLGRP_ND_USEROPT`: advertisements reach the
resolver through its own sockets ([E23](events.md#resolver-events)).

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
[A5](architecture.md#layers)) when the resolver starts, retrying with
the resolver's thirty-second timer while the device does not exist or
reports no six-byte address, during which the resolver has no DHCPv6
half and an `ipv6` resolver uses advertisements only, and hands the
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
runtime condition retried every thirty seconds, and an `ipv6` resolver
on it uses router advertisements only ([V14](#the-unified-ipv6-method)); with any other
value such a device is fine. Port 546 needs [K13](kernel.md#requirements); without
it a `dhcpv6` resolver is reported once as a host defect, retried every
thirty seconds, and its tunnels stay disconnected, while an `ipv6`
resolver falls back to its RDNSS servers ([V14](#the-unified-ipv6-method));
readiness is not withheld.

## The unified IPv6 method

V14. For `method = "ipv6"` the resolver runs both discovery methods on
the bind interface at once: router advertisements
([V10](#router-advertisements)) and Information-Requests
([V12](#dhcpv6-information-request)). Start if either source starts,
and report no servers only when neither has a usable server list.
Wait at most three seconds once for initial discovery, then take bounded
snapshots of at most three servers per source for this lookup.

For each address family independently, query DHCPv6-provided servers
first. A successful positive answer or a definitive negative answer
(NXDOMAIN or NOERROR with no records for that family) ends that family's
lookup; do not consult RA to override it. If DHCPv6 has no servers, or
all its attempts fail through timeout, transport error, SERVFAIL, REFUSED
or malformed responses, query the RA-provided servers for that family.
Keep a successful result of the other family unchanged. If both sources
fail, V6 retains the previous answer. Every later lookup starts with
DHCPv6 again; a fallback does not delete either discovery source's list.
Thus stale DHCPv6 information cannot indefinitely hide working RA DNS.
The total bound is V4's 63 seconds, not 33 seconds per unified lookup.

The daemon enables this explicitly with
`Ipv6ResolverConfig::with_failure_fallback(true)` (`iphost` 0.4.1); the
library's default stays selection-only for other consumers. Discovery
lifetimes follow V10 and V12.

## Resources

V15. A resolver of the address kind owns no socket between lookups; one
of the `ra` kind owns one raw ICMPv6 socket and one thread; one of the
`dhcpv6` kind owns one thread, and all resolvers on one interface share
one UDP socket and one receiving thread; one of the `ipv6` kind owns
both. Discovery configurations are shared by their current users and
released when unused; completed old incarnations are not cached forever.

Lookup scheduling belongs to the daemon, not to `iphost`. Across all
library instances in one process, allow at most eight in-flight system
lookups and, separately, eight in-flight configured-resolver lookups.
A configured lookup may use one additional helper for its second family.
Acquire the appropriate permit before spawning work; retain it until the
actual call returns, even after reload, cancellation of interest, or
dropping the service. Never spawn a replacement worker for a timed-out
libc call. This bounds stuck system workers at eight across repeated
reloads and service creation; configured DNS cannot consume or wait on
those system permits.

Keep at most one pending job and one latest result per current lookup
key; replace superseded work and discard results from old incarnations.
Admit pending keys fairly when permits return, with no busy polling.
Shutdown drops queued work and returns without joining blocked libc
calls. Workers retain only their bounded job inputs and release discovery
references on completion; bounded configured calls may finish after
shutdown. Memory is bounded by current configuration/discovery state,
fixed worker budgets and their in-flight snapshots, not reload history.
If all system workers stall, new system lookups wait with an episode
report; no finite system-DNS convergence is promised in that condition.
This is the explicit resource limit of [G23](promises.md#conditional-promises),
not a reason to stop the reconciler, readiness or shutdown.

## Resolver events

V13. Events concerning resolvers and what they cause:

| Event | Effect |
|---|---|
| An answer in force changes | The tunnels using it are reconnected to the selected address ([T15](tunnels.md#peers), [T28](tunnels.md#peer-changes)) |
| A resolver's configuration changes on reload | Its answers are discarded and queried anew ([V7](#queries-and-answers)) |
| A resolver named by a tunnel is removed from the configuration | The tunnel's entry has a hard mistake whose values in force still name the resolver, so the reload is refused as a whole, naming the tunnel ([C12](configuration.md#reload)) |
| The bind device appears, disappears, is renamed or replaced | Revalidate its lifetime and non-VRF kind before starting queries or discovery; stop them while absent or a VRF. Retry as V9 requires; retain answers in force |
| An RDNSS lifetime expires | The server is used only while no unexpired server exists ([V10](#router-advertisements)); answers in force are kept ([V6](#queries-and-answers)) |
| Monitor notifications are lost | Revalidate every resolver's bind device before further queries; retain answers. Discovery-source lifetimes still follow V11 |
| Shutdown | Drop pending work, invalidate results, release unused discovery state; do not join blocked libc calls or release their permits early (V15) |
