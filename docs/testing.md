# Testing and compatibility

[Documentation index](README.md)

The 0.2.0 daemon is intended to preserve working 0.1.5 configurations and
wire compatibility. Cookies remain disabled unless configured. New cookie
settings require both peers to agree, and changes to previously broken
configuration handling are described in the
[configuration guide](configuration.md#mistakes).

The repository's [Docker validation guide](https://github.com/menhera-org/rs-l2tpd/blob/HEAD/tests/docker/README.md)
contains complete build and run commands for privileged kernel and daemon
validation. These tests use static musl artifacts and disposable container
network namespaces.

## Startup invariants

The [early-start contract](operation.md#early-start-contract) is normative.
When changing startup, reconnection, readiness or the service unit:

- The daemon **MUST** be able to create the session interfaces needed to make
  the network ready. It **MUST NOT** wait for `network-online.target`,
  wait-online services, complete DNS setup or peer reachability first.
- The supplied unit **MUST** retain `Before=network-online.target`,
  `RequiredBy=network-online.target` and `Type=forking`. Do not add a
  dependency that reverses this startup order.
- Readiness **MUST** mean the applied kernel tunnels and sessions exist,
  including discard peers. Unresolved names, absent bind devices,
  unroutable peers and identifiers held by another tunnel or session must
  not turn into a requirement for a ready network.
- Actual kernel prerequisites still apply: the L2TP modules, and a route to
  a discard address or, after the grace period, the daemon's null device.

Check these invariants with the runtime discard-peer, pending-peer,
conflict and deferred-binding tests, the binary's
`systemd_unit_keeps_its_contract_and_is_hardened` test,
`tests/docker/degraded-start.sh`, `tests/docker/source-and-peers.sh` and
`tests/docker/ipv6-disabled.sh`. The systemd-unit test guards ordering,
including dependencies on wait-online services; the container tests verify
actual kernel resources and daemon readiness with incomplete networking.
Keep these checks when changing the implementation or packaging.

## Coverage

Coverage includes:

- Baseline/baseline, current/baseline and current/current peers over IPv4
  and IPv6, unbound, bound to an interface, and bound to a VRF.
- Payload delivery, unchanged-config reloads and shutdown cleanup.
- Source removal, interface replacement, VRF membership changes and
  recovery after lost netlink notifications, while preserving sockets
  and session identities.
- Degraded startup, late peers, last-resort discard routes of both families
  and ownership of null devices; a host with IPv6 disabled by sysctl.
- Unbound tunnels whose selected source is replaced, literal peers without
  a route, and identifiers held by a foreign tunnel and session.
- Loss of link notifications while a session is still being prepared, and
  after it is established, with re-creation and removal through the
  kernel's record; the kernel-side notification filter.
- Session MAC changes, cookies, and preparation while real
  systemd-networkd matches a temporary session by `Type=l2tpeth`.
- External parent renames and child VLAN/macvlan interfaces moved into a
  guest network namespace, preserving their addresses and routes through
  publication retries, reloads and reconnection.
- Reused interface indices after a session parent leaves its namespace,
  and preservation of unrelated replacement devices.
- Fallback route restoration after networkd reconfiguration, without
  replacing existing routes.

Tests require the documented Docker capabilities and host-kernel support;
they do not use host networking. The current procfs prerequisite and the
supplied systemd unit's path restrictions are described under
[installation](installation.md).

The child tests reproduce the kernel operations used by container
managers; they do not run LXD or Incus themselves. These regressions cover
specific observed races, not every possible kernel or manager behavior.
The [session lifecycle constraints](sessions.md#child-interfaces-and-other-managers)
and [kernel tunnel ownership requirement](operation.md#ownership-of-kernel-tunnels)
also apply when coordinating with other network software. The rules the
tests guard are collected in [contracts](contracts.md).

## Kernel test pitfalls

Facts that cost time once and shape how the tests are written:

- The kernel never echoes a route notification to the netlink port that
  requested the change. A test listening for `RTM_DELROUTE` must make the
  change on a second connection, as the daemon itself does.
- A VRF whose table has no IPv4 `unreachable default` route falls through
  to the main table for IPv4 lookups, so a route in the main table makes an
  IPv4 discard address routable inside the VRF too.
- Classic BPF loads multi-byte fields in network byte order, while netlink
  headers are in host byte order: a message type is compared byte-swapped.
- A process traced by strace reports `State: t` after `SIGSTOP`, not `T`.
- The l2tpeth device of a session keeps the name the kernel recorded at
  creation in `ip l2tp show session`, whatever its current name.
- Deleting a session and creating one with the same identifiers at once can
  be refused with `EEXIST` for a moment; tests wait for a retry.
- A netlink socket whose receive queue is full loses unicast replies too:
  a lookup on an overflowed subscription times out rather than failing.
