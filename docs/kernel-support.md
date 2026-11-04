# Kernel support

Linux must provide L2TPv3 Ethernet sessions and the socket families used by
the configured peers. The modules are `l2tp_core`, `l2tp_netlink`, `l2tp_ip`,
`l2tp_eth` and, for IPv6, `l2tp_ip6`. Load them on the host before starting an
unprivileged system container. The daemon itself does not need the dummy driver.

Repository file `audit/VERIFICATION.md` identifies the qualified source,
exact commands and results. Final qualification of `f5a2e7b` is in progress.
Kernel-only guests test the daemon against distribution kernels; they do
not establish support for that distribution's systemd, udev, networkd,
SELinux policy or package installation.

## Required kernels

The moving targets are the latest two Ubuntu LTS kernels, their vanilla
equivalents and mainline. Current selections are:

| Target | Kernel | Profiles |
|---|---|---|
| Ubuntu 24.04 | `6.8.0-147-generic` | Normal and clock/pause |
| Vanilla | `6.8.12` | Normal and clock/pause |
| Ubuntu 26.04 | `7.0.0-42-generic` | Normal, clock/pause and missing-Ethernet-driver recovery |
| Vanilla | `7.0.14` | Normal and clock/pause |
| Mainline | `7.4.0-rc1` | Normal, clock/pause, IPv6 disabled at boot and IPv6 omitted from the kernel |

Normal profiles exercise all 28 host scenarios and 37 process cases, plus
the kernel conformance and private fault suites. These include 300
tunnels/sessions, interface and namespace reuse, capability degradation,
fragmentation, socket handover, resolver traffic and recovery from lost
notifications.

## Optional distribution kernels

These targets extend the required matrix with stock, checksum-verified
images, configurations and matching modules.

| Distribution | Kernel | Profiles |
|---|---|---|
| Debian 13 | `6.12.115+deb13.1-amd64`, package `6.12.115-2` | Normal and clock/pause |
| Rocky Linux 9 | `5.14.0-687.61.1.el9_8.x86_64` | Normal and clock/pause |
| Rocky Linux 10 | `6.12.0-211.72.1.el10_2.x86_64` | Normal and clock/pause |

An earlier Debian 13 failure was a test capture-startup race, not a daemon
failure. The fixture now activates capture only after nlmon bind; the
daemon's AF_NETLINK path needed no behavior change. The controlled regression
and full investigation remain in
[signed history](https://github.com/menhera-org/rs-l2tpd/blob/9817a0d19ac89d5cc0844180022ec8b0dfa07ce5/audit/nlmon-bind-fix/README.md).

## Debian 12

Debian 12 is outside the support target. Its 6.1 kernel refuses renaming
an UP session device, and can refuse even an unchanged MAC write while UP.
The daemon preserves the active device, addresses and children, reports the
refusal and retries pending work. It never lowers an active interface to
force convergence.

A rename or staged publication can remain pending until the operator lowers
the device. Readiness does not wait for publication; reload completion can
wait for a refused rename. Earlier observations remain in the
[archived run](https://github.com/menhera-org/rs-l2tpd/tree/129a4e1fb02da9fab01ef61730853c2129ee9e5a/audit/phase6/optional-kernels-20261104).

## Operating limits

An empty IPv6 VRF without a usable source or route returns
`EADDRNOTAVAIL` on the selected stock/newer kernels and `ENETUNREACH` on
vanilla 6.8.12. Both leave the tunnel disconnected until dependencies change.
Neither refusal destroys an existing session.

Older kernels announce commanded L2TP deletions across network namespaces;
upstream confines them to the object's namespace from 7.3. The daemon
verifies local identity before acting, so foreign notices do not authorize
removing local objects. Distribution backports require direct verification.

An UP session device refuses a differing hardware address. The daemon
defers the change and preserves its index, state, addresses and children.
With udev and networkd, persistent MAC assignment and activation can race;
persistent assignment is not guaranteed to win. Use explicit MAC policy
for names that other managers may configure.

In containers without udev, networkd before v253 does not apply a
`[Match] Name=` rule to a session initially staged under a temporary name.
Incus system containers with udev and Ubuntu 24.04 or later do not have that
specific limitation. See [other network managers](spec/hosts.md#other-network-managers).

## Fragmentation

Session MTUs 1500 and 9000 are tested over a 1500-byte underlay with IPv4
and IPv6, both ordinary and VRF binding. The tests require full-size
bidirectional delivery, bulk traffic, fragment and session counters, and
no transmit drops. The daemon leaves MTU and administrative state to
the operator.

IPv4 fragmentation has an explicit socket-option contract. IPv6 delivery
also depends on the current kernel output path and is retested on every
normal target. Kernel reassembly counters alone do not prove or disprove
delivery.

## Managers and containers

Unprivileged Incus/LXD qualification exercises namespace-local tunables,
ordinary receive-buffer fallback, systemd socket storage, adoption,
in-place restart, networkd/udev and clean shutdown. These tests use no
host network attachment.

The unmodified supplied systemd unit is tested with Ubuntu 24.04 userspace
on the selected Ubuntu 6.8 kernel. That result includes its filesystem
sandbox, three capabilities, tunable-write exception and dedicated PID
directory. A successful kernel-only guest does not extend this userspace
qualification to Debian or Rocky.

The [verification scope](developer.md#kernel-evidence) distinguishes executed
assertions, source observations and protocols delegated to upstream
libraries. The [developer chapter](developer.md) gives the reproduction
commands and acceptance criteria.
