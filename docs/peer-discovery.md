# Peer discovery

Use a literal peer address when DNS is unnecessary. For a host name, set
`ip_version` explicitly and choose the resolver in the tunnel's
`resolver_name` field. See the [configuration example](operation.md#configuration-files).

## Resolver choices

Without `resolver_name`, the system resolver uses the host's libc settings.
A configured resolver can use explicit DNS server addresses or discover
servers on one interface:

| Method | Servers used | Requirements |
|---|---|---|
| Explicit `addresses` | Up to three configured DNS servers | Reachability from the selected binding |
| `ra` | IPv6 Router Advertisement RDNSS | An ordinary bind interface; raw reception needs `CAP_NET_RAW` |
| `dhcpv6` | DHCPv6-discovered DNS servers | An ordinary bind interface; port 546 normally needs `CAP_NET_BIND_SERVICE` |
| `ipv6` | DHCPv6 first, with RA fallback per address family | The applicable requirements above |

Discovery bindings must name an ordinary interface, rather than a VRF.
The daemon waits for missing interfaces and retries when their state changes.
Link-local DNS server addresses use that interface's scope.

## Selection and failure

Unified IPv6 discovery falls back to RA when DHCPv6 has no servers or
its queries exhaust their failures. A positive or definitive negative
DHCPv6 answer is final. Lookup bounds are 33 seconds with one discovery
source and 63 seconds with both.

RDNSS updates affect each advertised address independently. Refreshing one
server does not remove another live server. A zero lifetime withdraws the
address. Discovery retains at most 64 addresses and selects at most three
servers for a query.

The daemon retains usable peer answers according to
[V5 and V6](spec/resolvers.md#queries-and-answers). A late answer from an
obsolete configuration cannot replace current state.

## Identity and degraded hosts

DHCPv6 can use a link-layer, anonymous, random or explicit DUID identity.
Anonymous clients reject replies carrying any Client Identifier; identified
clients require a matching identifier when one is present.

Without `CAP_NET_RAW`, RA discovery depends on kernel user-option delivery
and the interface's `accept_ra` setting. Without permission to bind port
546, DHCPv6 can fail while RA remains usable. These conditions are reported;
other entries continue running.

Libc DNS calls cannot be canceled. Separate process-wide limits admit eight
system lookups and eight configured lookups. A blocked obsolete call keeps
its slot until it returns, but kernel events and shutdown continue.

These protocols use locked `iphost` 0.4.4. The
[verification scope](developer.md#kernel-evidence) distinguishes downstream traffic
tests from upstream parser and state tests.
