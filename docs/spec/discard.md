# Discard addresses (retired)

[Specification index](README.md)

This page held requirements D1–D13: the discard addresses `100::` and
`192.0.0.8` as peers for tunnels without a reachable peer, the `dummy` null
device `rsl2tpnullN`, the routes through it, the grace period before
installing them, and their repair. They are withdrawn, and their numbers
are not reused.

The reason is a kernel fact: a tunnel may be registered on a socket that
is not connected, and the kernel drops every frame of such a tunnel itself
([K5](kernel.md#requirements)); this holds on every release from v6.8 on
and was verified end to end, including connecting the socket later. A
tunnel without a reachable peer is therefore left disconnected
([T1](tunnels.md#the-right-state-of-a-tunnel),
[T16](tunnels.md#peers-that-cannot-be-reached)): nothing is sent, no route
is needed, no device is created, and no event about routes or null devices
has to be watched. The second audit records the defects the discard
design had (silent loss of IPv4 routes when the null device went down,
frames following the routing table at transmit time, device-bound tunnels
that could never use a null-device route or that sent ARP for the discard
address, a null device without a link-local address) and the decision to
retire it.

Nothing in the configuration format referred to this page; the names
`rsl2tpnull*` are no longer reserved ([R19](requirements.md#the-operator)).
