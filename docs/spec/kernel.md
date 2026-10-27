# Kernel

[Specification index](README.md)

What the daemon requires of the Linux kernel, stated precisely and
minimally, and the kernel facts the other pages rely on. Each requirement
says what it is needed for and whether it is unconditional or conditional
on a feature the configuration uses. Each fact names the source that
establishes it. Line references are to the Ubuntu `6.8.0-147` tree (Linux
6.8.12 plus Ubuntu backports); the facts were also checked in v7.0 and in
the mainline tree after v7.3, and K5 in every release tag from v6.8 to
v7.3. The verified range is the range this specification claims, not a
statement about older kernels.

## Requirements

| | Requirement | Needed for | Condition | Kernel option, module or property |
|---|---|---|---|---|
| K1 | L2TPv3 core with generic-netlink configuration | everything | always | `CONFIG_L2TP` builds `l2tp_core`; `CONFIG_L2TP_V3` builds `l2tp_netlink` (`net/l2tp/Makefile`); loaded or loadable on demand ([K21](#facts)) |
| K2 | L2TP over IPv4 (IP protocol 115) sockets | the tunnel socket; IPv4 peers | always | `CONFIG_L2TP_IP`; module `l2tp_ip` |
| K3 | Ethernet pseudowire sessions | session interfaces | always | `CONFIG_L2TP_ETH`; module `l2tp_eth` |
| K4 | L2TP over IPv6 sockets | IPv6 peers; the dual-stack socket of [T3](tunnels.md#address-families) | only when a tunnel has an IPv6 peer or the daemon carries IPv4 peers on `AF_INET6` sockets; otherwise `AF_INET` sockets ([T4](tunnels.md#address-families)) | `CONFIG_IPV6` with `CONFIG_L2TP_IP` builds `l2tp_ip6` |
| K5 | A tunnel may be registered on a user-space socket that is not connected, and the kernel drops every frame sent through it while the socket is not established | the no-peer state ([T1](tunnels.md#the-right-state-of-a-tunnel), [T16](tunnels.md#peers-that-cannot-be-reached)) | always | a property of `net/l2tp/l2tp_core.c`: `l2tp_validate_socket` (1467-1487) and `l2tp_tunnel_register` (1489-) check no socket state; `l2tp_xmit_core` drops when `tunnel->fd >= 0 && sk->sk_state != TCP_ESTABLISHED` (1086-1090). Present in every release v6.8 … v7.3 |
| K6 | Connecting, disconnecting (`connect(AF_UNSPEC)`) and reconnecting an L2TP/IP socket that carries a registered tunnel | applying a peer, peer changes, source reselection | always | `l2tp_ip_connect`, `l2tp_ip6_connect`, `__udp_disconnect` (`net/ipv4/udp.c:1998-2013`) |
| K7 | rtnetlink with the link and address multicast groups, and generic netlink | monitoring, identity proofs, device lookups | always | `CONFIG_NET`; `RTNLGRP_LINK`, `RTNLGRP_IPV4_IFADDR`, `RTNLGRP_IPV6_IFADDR`; no route group |
| K8 | `CAP_NET_ADMIN` in the daemon's network namespace | creating tunnels, sessions and devices over netlink | always | the capability checks of rtnetlink and the l2tp family |
| K9 | VRF support | a `bind_interface` that names a VRF | only when a VRF is configured as a bind device | `CONFIG_NET_VRF` (depends on `CONFIG_NET_L3_MASTER_DEV`, `CONFIG_IP_MULTIPLE_TABLES`; `drivers/net/Kconfig:461-464`); module `vrf` |
| K10 | Classic BPF socket filter (`SO_ATTACH_FILTER`) | reducing the monitor's traffic | optional: without it the monitor runs unfiltered ([R6](requirements.md#the-host)) | `net/core/filter.c`, built unconditionally; no `bpf()` syscall |
| K11 | `net.ipv6.bindv6only = 0` in the daemon's namespace | IPv4 peers on `AF_INET6` sockets | only while a tunnel carries IPv4 peers on an `AF_INET6` socket; otherwise `AF_INET` sockets ([T26](tunnels.md#hosts-with-bindv6only)) | `IPV6_V6ONLY` is fixed at socket creation ([K13](#facts)) |
| K12 | `procfs` at `/proc` | the namespace identity of the current library dependency ([R7](requirements.md#the-host)) | only while that dependency is used | — |
| K13 | `CAP_NET_BIND_SERVICE`, or `net.ipv4.ip_unprivileged_port_start` at or below 546 (Docker sets it to 0 in its containers) | resolvers with `method = "dhcpv6"` or `"ipv6"` ([V12](resolvers.md#dhcpv6-information-request), [V14](resolvers.md#the-unified-ipv6-method)) | only when such a resolver is configured; an `ipv6` resolver works without it through its RDNSS servers | `net/ipv4/af_inet.c:508-510`, `include/net/ip.h:374-377` |
| K14 | Router-advertisement user options delivered on `RTNLGRP_ND_USEROPT` | the fallback source of RDNSS servers for resolvers with `method = "ra"` or `"ipv6"` when the raw socket of K39 cannot be opened ([V10](resolvers.md#router-advertisements)) | only when such a resolver is configured and `CAP_NET_RAW` is missing, and only useful where `accept_ra` is enabled on the interface ([K40](#facts)) | `net/ipv6/ndisc.c:1189-1235` |
| K39 | `CAP_NET_RAW` in the daemon's namespace, for a raw ICMPv6 socket | receiving and soliciting router advertisements ([V10](resolvers.md#router-advertisements)) | required whenever a resolver with `method = "ra"` or `"ipv6"` is configured; not needed otherwise | `net/ipv6/af_inet6.c:180-182` |

Not required: the `dummy` driver, any route, any route lookup, the route
multicast groups, `/sys`, and `CAP_NET_RAW` for anything but the
router-advertisement resolvers of K39 (every change of a device binding
follows a disconnect, which clears the binding; [K22](#facts)). The daemon
MUST NOT depend on any of them.

## Facts

Facts the other pages rely on. A fact is cited as K*n*; a page that
depends on a fact that is not here is wrong.

| | Fact | Source |
|---|---|---|
| K15 | An L2TP/IP data packet (session id ≠ 0) is delivered to the session found by session id in the namespace; the receiving socket, its binding, the source address and the ingress device are not consulted. Cookies are the only admission check. | `net/l2tp/l2tp_ip.c:137-157`, `l2tp_ip6.c:147-167`, cookie check `l2tp_core.c:653-662`; v7.0 `l2tp_ip.c:152-158` |
| K16 | The interface name the kernel reports for a session is a copy of the device name taken once after registration; it survives renames and is reused verbatim by a re-created session. The kernel looks sessions up by that stored name (`L2TP_ATTR_IFNAME`). | `l2tp_eth.c:310`, `l2tp_core.c:317-340`, `l2tp_netlink.c:55-57`, `731-732` |
| K17 | Closing the tunnel socket queues the tunnel deletion to a workqueue; the deletion removes every session on the tunnel, whoever created it, then the tunnel id. | `l2tp_ip.c:236-246`, `l2tp_core.c:1574-1581`, `1273-1298`, `1227-1249` |
| K18 | Session deletion is synchronous up to 6.10 (the device is unregistered inside the netlink call) and asynchronous from 6.11 on. | `l2tp_core.c:1584-1596`, `l2tp_netlink.c:652-672`; v7.0 `l2tp_core.c:1733-1740` |
| K19 | Tunnel and session registries are per network namespace. A session id is refused when any session of the namespace holds it and either tunnel uses IP encapsulation. A refused id is `EEXIST`. | `l2tp_core.c:342-384`, `1500-1503`; v7.0 `476-483`, `578-595`, `1642-1656` |
| K20 | A session whose device cannot be registered (name taken, invalid name) is not created at all. | `l2tp_eth.c:300-308` |
| K21 | Module autoload from `rtnl-link-*`, `net-pf-*` and generic-netlink family names has no namespace or capability gate; a host may still restrict it by policy. | `net/core/rtnetlink.c:3849-3855`, `net/ipv6/af_inet6.c:164-173`, `net/netlink/genetlink.c:1446-1447`, `l2tp_netlink.c:620-626` |
| K22 | `SO_BINDTODEVICE` and `SO_BINDTOIFINDEX` need `CAP_NET_RAW` only when the socket already has a binding. A disconnect clears the binding. `SO_BINDTOIFINDEX` binds by index. | `net/core/sock.c:627-655`, `671-717`, `1516-1518`, `1977-1979`; `net/ipv4/udp.c:2009` |
| K23 | `net.ipv6.bindv6only` sets `IPV6_V6ONLY` at socket creation; the option cannot be changed on an L2TP/IPv6 socket (`inet_num` is pinned at open) but can always be read; a connect to an IPv4-mapped address on such a socket fails `ENETUNREACH`. | `net/ipv6/af_inet6.c:228`, `datagram.c:185-191`, `ipv6_sockglue.c:656-662`, `1212-1214`, `l2tp_ip6.c:228-233` |
| K24 | A `connect()` on a connected datagram socket keeps the previous source address; only a disconnect resets it. A connect from an IPv4-mapped peer to an IPv6 peer without a disconnect fails `EAFNOSUPPORT`; the reverse succeeds but the socket keeps reporting the IPv6 source. | `net/ipv4/datagram.c:38-39`, `64-65`; `net/ipv6/datagram.c:51`, `206-208`; `net/ipv6/ip6_output.c:1215-1219`; `net/ipv4/udp.c:2010-2011` |
| K25 | A disconnect resets the IPv4 destination and both sources but not `sk_v6_daddr`; the kernel's tunnel record of a disconnected `AF_INET6` socket shows the previous peer and an empty source. | `net/ipv4/udp.c:2006-2011`; `l2tp_netlink.c:337`, `359` |
| K26 | Errno of a refused connect: no route `ENETUNREACH`; `unreachable` route `EHOSTUNREACH`; `prohibit` `EACCES`; `blackhole` `EINVAL`; `throw` ends as `ENETUNREACH`; no usable source address in the socket's L3 domain `EADDRNOTAVAIL`, raised before the route is consulted; link-local peer without a scope or binding `EINVAL`. | `net/ipv4/fib_semantics.c:124-137`, `net/core/fib_rules.c:328-335`, `net/ipv6/route.c:1083-1096`, `include/net/ip6_route.h:128-152`, `net/ipv6/datagram.c:221-238` |
| K27 | Connecting to a link-local IPv6 peer with a scope id binds the socket to the scope device; the scope must equal the bound device or be a member of the bound VRF. | `net/ipv6/datagram.c:221-238`, `include/net/sock.h:3023-3035` |
| K28 | IPv4 output through a bound ordinary device with no matching route assumes the destination is on-link and succeeds; a lookup with an output device matches only routes through that device; a bound device that is a VRF member is routed in the VRF's table. | `net/ipv4/route.c:2785-2817`, `fib_trie.c:1419-1420`, `fib_rules.c:81-105`, `net/l3mdev/l3mdev.c:271-300` |
| K29 | A netlink socket whose receive queue overflows reports `ENOBUFS` once on its next receive unless `NETLINK_NO_ENOBUFS` is set; unicast replies and acknowledgements that do not fit are dropped silently; a socket filter also drops unicast and dump replies. | `net/netlink/af_netlink.c:350-360`, `1211-1235`, `1347-1352`, `1481-1485`, `2278-2281`; `net/core/datagram.c:97-99`, `251-254` |
| K30 | Unicasting to another process's netlink socket needs `CAP_NET_ADMIN` in the namespace, except on `NETLINK_USERSOCK`. | `net/netlink/af_netlink.c:1087-1089`, `1847-1850`, `2858` |
| K31 | An l2tpeth device gets a random hardware address at creation, refuses a hardware-address change while up (`EBUSY`), and can be renamed while up. | `l2tp_eth.c:95-115`, `net/core/dev.c:1264-1308` |
| K32 | A device name may not be empty, 16 bytes or longer, `.`, `..`, or contain `/`, `:` or whitespace; a `%` in a requested name is a format pattern the kernel expands. | `net/core/dev.c:1119-1134`, `1210-1225` |
| K33 | Taking a device down removes its IPv6 addresses unless `keep_addr_on_down` is set on the device or on `all`; routes and neighbour state through it go regardless. | `net/ipv6/addrconf.c:3890-3898`, defaults `226`, `288` |
| K34 | An IPv4 connect succeeds with source `0.0.0.0` when no IPv4 address exists; an IPv6 connect fails `EADDRNOTAVAIL` when no IPv6 address exists in the socket's L3 domain; `::1` is selected outside a VRF when nothing else exists. | `net/ipv4/devinet.c:1370-1376`, `include/net/ip6_route.h:128-152` |
| K35 | The kernel accepts a cookie of any length up to 8 bytes. | `l2tp_netlink.c:584-600`, `913-920` |
| K37 | A tunnel lives as long as any descriptor of its socket is open, in any process: a descriptor passed with `SCM_RIGHTS` or inherited across `execve` keeps the tunnel, its sessions and their devices intact, and the receiving program can register sessions on it, connect and disconnect it. | `l2tp_ip.c:236-246` (deletion only in the socket's destructor); shown by F1 and F8 of the feasibility report |
| K40 | The kernel processes a router advertisement, and forwards its user options on `RTNLGRP_ND_USEROPT`, only when `accept_ra` is enabled on the receiving interface; with `accept_ra=0` the advertisement is dropped before any option is looked at. | `net/ipv6/ndisc.c:1287` and `1505` (early returns), `1599` (forwarding) |
| K38 | Two UDP sockets may bind the same port with `SO_REUSEADDR`; a unicast datagram is delivered to one of them, the most recently bound among equal matches, because the lookup keeps the first socket with a strictly better score and new sockets are added at the head of the port chain. Multicast datagrams reach every member. | `net/ipv6/udp.c:222-227`, `net/ipv4/udp.c:342` |
| K36 | `SO_RCVBUF` is capped by `net.core.rmem_max` and doubled; `SO_RCVBUFFORCE` is not capped but needs `CAP_NET_ADMIN` in the **initial** user namespace (`capable()`, not `ns_capable()`), so it is refused with `EPERM` inside a user-namespaced container whatever capabilities the process holds there. | `net/core/sock.c:1080-1083`, `1271-1275` |

## Verified behaviour

Every fact above was reproduced on Linux `6.8.0-147-generic` on 2026-10-27
in privileged containers, except K21 (reproduced on the host) and K35
(source only). The procedures are in the
repository's `audit/` directory: `SPEC_AUDIT_2026-10-27_2.md` and, for
the mechanisms of K13, K14, K16's deletion by name, K23's write-and-recreate
sequence and K36, `SPEC_FEASIBILITY_2026-10-27.md`,
which also showed the descriptor hand-over of [P14](process.md#restart)
and the re-exec of [P26](process.md#restart) on a live tunnel (K37). The tests of roadmap step 6 MUST repeat them against the
live kernel.
