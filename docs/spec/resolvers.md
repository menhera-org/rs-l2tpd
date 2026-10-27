# Resolvers

[Specification index](README.md)

How a host name in `remote_addr` becomes a peer address: through the
system resolver by default, or through a resolver the configuration names,
given by address or by a discovery method, with an optional bind interface.
This page describes the behaviour whether the mechanism is implemented in
the `iphost` crate or in this crate; that choice is open and does not
change the rules.

## Model

V1. A configuration MAY define resolvers in the `resolvers` table
([C16](configuration.md#resolver-entries)), keyed by name. A tunnel whose
`remote_addr` is a host name names one of them with `resolver_name`, or
uses the system resolver when the key is absent. A tunnel with a literal
`remote_addr` uses no resolver; a `resolver_name` on such a tunnel is a
tolerated mistake: ignored with a warning.

V2. A resolver is one of three kinds, chosen by its fields:

| Kind | Fields | Name servers |
|---|---|---|
| Address | `addresses`: one or more literal IPv4 or IPv6 addresses, each with an optional port (`[2001:db8::53]:5353`, `192.0.2.53:5353`), port 53 by default; `bind_interface` optional | The listed servers, tried in order |
| Router advertisements | `method = "ra"`; `bind_interface` required | The servers of the RDNSS options received on the bind interface ([V10](#router-advertisements)) |
| DHCPv6 Information-Request | `method = "dhcpv6"`; `bind_interface` required | The servers a DHCPv6 server returns on the bind interface ([V12](#dhcpv6-information-request)) |

A resolver with both `addresses` and `method`, or with `method` and no
`bind_interface`, is a hard mistake ([C10](configuration.md#start-up)).
All three kinds are part of the first implementation; none is optional,
and a `method` value outside the two defined ones is a hard mistake.

V3. The system resolver is the libc resolver of the build: on glibc the
host's NSS configuration, on musl `/etc/resolv.conf` and `/etc/hosts` and
nothing else. The daemon does not read those files itself
([L1](library.md#boundaries)); it asks the libc. Answer order, timeouts and
search-domain handling are the libc's, and no rule below depends on them.

## Queries and answers

V4. For every tunnel with a host name, the daemon asks the tunnel's
resolver for the records of the family `ip_version` names (`A` for `V4`,
`AAAA` for `V6`) every thirty seconds ([M14](model.md#timing)), and at
once when the tunnel's configuration or its resolver's configuration
changes. Queries are asynchronous and never block the reconciler
([A9](architecture.md#concurrency)); their results are polled every
second. A query that has no result after thirty seconds is abandoned and
the next one is sent.

V5. An **answer** is the list of addresses a query returned, in the order
returned. An address is **usable** when it is a unicast address of the
requested family: not unspecified, not multicast, not the IPv4 broadcast
address, and for `V6` not an IPv4-mapped address. The **selected** address
is the first usable address of the answer; it is the tunnel's real peer
([T14](tunnels.md#peers)). Unusable addresses are skipped, with one warning
per answer that contains any.

V6. An answer stays in force until a later answer for the same host name
from the same resolver replaces it. A query that fails (resolver
unreachable, error, timeout) and a negative answer (no record of the
family) both keep the previous answer in force, so that a working tunnel
is never disconnected by a resolver outage; the condition is reported once
when it begins and once when it ends ([O3](observability.md#logging)). A
tunnel that never had an answer has no real peer and is disconnected
([T16](tunnels.md#peers-that-cannot-be-reached)).

V7. Answers belong to a host name, a family and a resolver. A changed
host name, a changed `ip_version` or a changed `resolver_name` on reload
discards the answers in force and queries anew; nothing else does. An
answer of the other family is never used.

V8. Readiness never waits for a resolver ([P7](process.md#readiness)); a
resolver that never answers leaves its tunnels disconnected and reported
once.

## Binding

V9. A resolver with `bind_interface` sends its queries from a socket bound
to that device by index, the name resolved at each query so that the
configured name stays authoritative ([T11](tunnels.md#bind-devices)). A
VRF as bind interface routes the queries in the VRF's table
([K28](kernel.md#facts)). While the device does not exist the resolver
makes no queries and its tunnels keep their answers in force. The binding
needs no capability ([K22](kernel.md#facts)).

## Router advertisements

V10. For `method = "ra"` the daemon joins the rtnetlink group
`RTNLGRP_ND_USEROPT` ([K14](kernel.md#requirements)) and takes the RDNSS
options of router advertisements received on the resolver's bind
interface, matched by index. Each server is in force for the option's
lifetime and refreshed by every advertisement that repeats it; a server
whose lifetime expires is forgotten. A link-local server address is used
with the interface as its scope. DNSSL options are ignored. No raw socket
and no capability beyond [K8](kernel.md#requirements) is needed.

V11. After a loss of notifications ([E20](events.md#monitor-loss)) the
servers in force are kept until their lifetimes expire, because the kernel
does not replay advertisements; the next periodic advertisement refreshes
them. The event monitor's filter MUST pass `RTM_NEWNDUSEROPT` messages
whenever such a resolver is configured ([E24](events.md#resolver-events)).

## DHCPv6 Information-Request

V12. For `method = "dhcpv6"` the daemon sends an Information-Request
(RFC 8415 section 18.2.6) to `ff02::1:2` from UDP port 546 on the bind
interface, requesting the DNS Recursive Name Server option (23) and the
Information Refresh Time option (32), with RFC 8415's retransmission
timing until a Reply arrives. The servers of the Reply are in force until
the next Reply; the request is repeated at the Information Refresh Time
the server gave, or every 24 hours when it gave none, and never more
often than every 10 minutes (RFC 8415 section 21.23). Nothing else is
taken from DHCPv6. Port 546 needs [K13](kernel.md#requirements); without
it the resolver is reported once as a host defect, retried every thirty
seconds, and its tunnels stay disconnected; readiness is not withheld.

## Resolver events

V13. Events concerning resolvers and what they cause:

| Event | Effect |
|---|---|
| An answer in force changes | The tunnels using it are reconnected to the selected address ([T15](tunnels.md#peers), [T28](tunnels.md#peer-changes)) |
| A resolver's configuration changes on reload | Its answers are discarded and queried anew ([V7](#queries-and-answers)) |
| A resolver named by a tunnel is removed from the configuration | The tunnel's entry has a hard mistake: on reload it keeps its values in force ([C12](configuration.md#reload)) |
| The bind device of a resolver appears or disappears | Queries start or stop ([V9](#binding)); answers in force are kept |
| An RDNSS lifetime expires | The server is forgotten; answers in force are kept ([V6](#queries-and-answers)) |
| Notifications are lost | Servers in force are kept ([V11](#router-advertisements)); pending queries are repeated |
| Shutdown | Queries are abandoned; nothing is removed, because resolvers create no kernel object |
