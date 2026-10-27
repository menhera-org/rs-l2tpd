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
  including discard peers. Unresolved names and absent bind devices must
  not turn into a requirement for a ready network.
- Actual kernel prerequisites still apply. A required literal-peer underlay
  route must be supplied independently or concurrently, without a cycle
  through daemon readiness.

Check these invariants with the runtime discard-peer and deferred-binding
tests, the binary's `systemd_unit_keeps_its_contract_and_is_hardened` test,
and `tests/docker/degraded-start.sh`. The systemd-unit test guards ordering,
including dependencies on wait-online services; the container test verifies
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
- Degraded startup, late peers, last-resort discard routes and ownership
  of null devices.
- Session MAC changes, cookies, and preparation while real
  systemd-networkd matches a temporary session by `Type=l2tpeth`.
- Fallback route restoration after networkd reconfiguration, without
  replacing existing routes.

Tests require the documented Docker capabilities and host-kernel support;
they do not use host networking. The current procfs prerequisite and the
supplied systemd unit's path restrictions are described under
[installation](installation.md).
