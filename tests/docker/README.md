# Docker networking validation

These tests use real Linux L2TP sockets and sessions. They need Docker access
and host-kernel support for `l2tp_ip6`, `l2tp_eth`, dummy interfaces and VRFs.
They run in disposable container network namespaces, without host networking
or writable host mounts. Missing prerequisites fail explicitly.

Build static x86_64 musl binaries for the current tree and the `v0.1.5` tag,
using each version's Cargo.lock. Put them in an artifacts directory as
`current` and `baseline`. Both binaries must use the default `/etc/rs-l2tpd.toml`
and `/etc/rs-l2tpd.toml.d` configuration paths.

```sh
cargo build --locked --target x86_64-unknown-linux-musl --features setup
cargo test --locked --target x86_64-unknown-linux-musl --all-features --lib --no-run
```

The second command prints the library test executable's path. Copy that
executable into the artifacts directory as `kernel-tests`. To obtain the
baseline source without changing the working tree:

```sh
git --no-pager archive --output /tmp/rs-l2tpd-baseline.tar v0.1.5
mkdir -p /tmp/rs-l2tpd-baseline
tar -xf /tmp/rs-l2tpd-baseline.tar -C /tmp/rs-l2tpd-baseline
cargo build --locked --target x86_64-unknown-linux-musl \
    --manifest-path /tmp/rs-l2tpd-baseline/Cargo.toml
```

Run all eighteen privileged library tests, substituting an absolute
artifacts directory for `/path/to/artifacts`:

```sh
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW \
    --mount type=bind,source=/path/to/artifacts,target=/artifacts,readonly \
    alpine:3.22 sh -c 'set -eu
        cp /artifacts/kernel-tests /tmp/kernel-tests
        chmod 755 /tmp/kernel-tests
        exec timeout 30 /tmp/kernel-tests state::tests::privileged_ \
            --ignored --nocapture --test-threads=1'
```

These assert exact IPv4-mapped and IPv6 local/remote endpoints, peer changes,
source removal and replacement, disconnect/retry recovery, interface identity
after rename and name reuse, VRF source selection, session MAC/link state,
session cookies as reported back by the kernel, the null device routing
the discard address in the main table and in a VRF table with an
unreachable default route, source reselection after a discard peer, ownership
checks when cleaning up null devices, and kernel cleanup. IPv4 source verification
rejects `::ffff:0.0.0.0` as well as the native wildcards.

Run the daemon interoperability matrix:

```sh
docker build --progress plain -t rs-l2tpd-network-test:local tests/docker
docker run --rm --network none \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined \
    --mount type=bind,source=/path/to/artifacts,target=/artifacts,readonly \
    --entrypoint timeout rs-l2tpd-network-test:local 180 sh /opt/network.sh
```

`SYS_ADMIN` is used only to create and enter the test's two network namespaces.
`nsenter` avoids the sysfs remount required by `ip netns exec`, allowing nested
Docker hosts with restricted sysfs mounts. Test binaries are copied into the
container so a no-exec host mount does not prevent execution.

The matrix covers baseline/baseline, current/baseline, and current/current
peers over IPv4 and IPv6, each unbound, bound to an interface, and bound to a
VRF: eighteen cases. Each case checks IPv4 and IPv6 payload delivery in both
directions, reload completion, delivery after an unchanged-config reload, and
removal of tunnels and session interfaces on SIGTERM. Peer tunnel/session IDs
are deliberately asymmetric.

## Additional MAC-changing reload check

Add `--env MAC_RELOAD=1` to the matrix command to change the current daemon's
session MAC during reload. This is a separate check of a feature introduced
after 0.1.5, rather than the unchanged-config compatibility matrix.

The daemon never takes a running session interface down to change its MAC:
on this kernel that removes the interface's configured IPv6 addresses (and
its routes), which an earlier version of this check demonstrated as an IPv6
`Network unreachable` after the reload. A change on an up interface is
deferred instead. The check therefore verifies that the MAC is unchanged and
traffic intact right after the reload, then takes the interface down, waits
for the daemon to apply the new MAC on the link-change notification, brings
the interface back up, restores the test's IPv6 address and checks traffic
again.

## Additional cookie check

Add `--env COOKIES=1` to the matrix command to run the six current/current
cases with session cookies: an asymmetric pair, each side sending a
different cookie and requiring the other's. The twelve cases with a
baseline peer stay cookie-free, as a 0.1.5 daemon ignores the keys. Cookies
are a feature introduced after 0.1.5, so this is separate from the
unchanged-config compatibility matrix.

After the usual checks, each cookie case reloads the left daemon with a
`peer_cookie` the right side does not send. The session is re-created (the
kernel cannot change a session's cookies), the test restores the new
interface's addresses, and a ping in either direction must now fail: the
kernel discards the right side's requests and its replies alike. Restoring
the agreed cookies re-creates the session again and traffic must flow.

On Linux 6.8.0-147-generic, validation on 2026-10-22 passed all eleven
privileged library tests, all eighteen compatibility cases and the
MAC-changing check. On 2026-10-27, on the same kernel, the thirteen
privileged library tests, the eighteen compatibility cases, the MAC-changing check, the
cookie check, the four address-notification cases and the ten
degraded-start cases below all passed.

The tests establish behavior on the kernel and topologies exercised. They do
not establish universal compatibility across all kernels or routing setups.

## Daemon address-change notifications

`address-changes.sh` exercises the daemon's netlink event subscription and
handling, in addition to the direct state-method tests above. Run it with a
freshly built `current` binary in the artifacts directory, and substitute
absolute paths for both mounts:

```sh
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW \
    --mount type=bind,source=/path/to/artifacts,target=/artifacts,readonly \
    --mount type=bind,source=/path/to/rs-l2tpd/tests/docker/address-changes.sh,target=/opt/address-changes.sh,readonly \
    --entrypoint timeout rs-l2tpd-network-test:local 90 sh /opt/address-changes.sh
```

The existing test image supplies the `ip` tools; the script is mounted
separately so rebuilding the image is unnecessary. These tests need no
`SYS_ADMIN`: all dummy interfaces and VRFs are inside the container's own
network namespace.

Four cases cover IPv4 and IPv6, each bound directly to the underlay interface
or to its VRF master. Each removes the selected source address, observes the
reconnect notification, then adds a replacement. A separate underlay outage
forces failed reconnects and retries before the interface comes back up.
Kernel tunnel dumps must report the replacement source and original peer.
A competing main-table route selects a different source, so dropping the
device or VRF binding fails the endpoint assertion. The daemon PID, persistent
socket inode identities, session interface index, tunnel/session IDs and inner
interface addresses must remain unchanged. Address changes in the other
family and on a slave of another VRF
must not trigger reconnects; successful recovery must stop retries. Shutdown
must remove both the tunnel and its session interface.

Each case also renames the configured device and creates a replacement with
the original name and a new interface index. The old device stays alive, so a
stale binding cannot be mistaken for correct name resolution. Direct bindings
receive a new dummy underlay; VRF bindings receive a new VRF and the existing
underlay is moved into it. A distinct source address must be selected through
the replacement while the existing tunnel socket and session remain intact.

Both VRF cases then configure a second slave with a less preferred route and
delete the selected slave entirely. The daemon is briefly stopped while the
device is deleted, so it handles the queued notifications after the device
has disappeared. The socket must refresh its source to the
already configured survivor without requiring a new address notification from
that interface. The checks still require the same socket and session, preserved
VRF routing, and no further retries after recovery.

These are endpoint and lifecycle tests with dummy underlays; packet delivery
is covered separately by the two-peer interoperability matrix above.

## Discard-peer recovery and device ownership

`discard-recovery.sh` covers native IPv6 recovery from the temporary `100::`
peer and preservation of interfaces that the daemon does not own. Run it with
the same test image and a fresh `current` artifact:

```sh
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW \
    --mount type=bind,source=/path/to/artifacts,target=/artifacts,readonly \
    --mount type=bind,source=/path/to/rs-l2tpd/tests/docker/discard-recovery.sh,target=/opt/discard-recovery.sh,readonly \
    --entrypoint timeout rs-l2tpd-network-test:local 150 sh /opt/discard-recovery.sh
```

The four cases check:

- A valid unresolved IPv6 hostname starts with `100::`, its bound interface
  is renumbered, and the hostname then resolves to a real peer. The selected
  source must be the replacement address. Resolution uses a container-local
  `/etc/hosts` update and the normal 30-second DNS refresh, without a reload.
- A tunnel using the daemon's fallback route to `100::` is reloaded with a
  real native IPv6 peer. Its source must be selected from the real underlay.
- A preexisting `rsl2tpnull0` dummy, its address and an administrator-installed
  route survive daemon startup and shutdown.
- A daemon-created fallback device is removed and a different device receives
  the same name. Route repair allocates another owned device, and both repair
  and shutdown preserve the replacement, its address and route.

Both peer-recovery cases require the same tunnel socket, daemon PID, session
interface index, session IDs and inner interface addresses throughout. The
ownership checks permit any fallback allocation strategy that preserves the
unowned devices and their configuration. Each case also checks tunnel and
session cleanup. Use `--env CASES=dns`, `fallback`, `existing`, or `replacement`
to run one case. The full run includes the normal fallback grace periods and
DNS refresh interval; all filesystem and network changes stay in the container.

## Route repair with systemd-networkd

`networkd-routes.sh` runs a real networkd instance with a configuration that
matches the daemon's fallback devices. Its separate Debian image provides
networkd, networkctl and a container-local D-Bus; it does not use the host's
systemd installation or network configuration.

```sh
docker build --progress=plain -f tests/docker/Dockerfile.networkd \
    -t rs-l2tpd-networkd-test:local tests/docker
docker run --rm --network none \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BROADCAST \
    --cap-add BPF --cap-add SYS_ADMIN \
    --mount type=bind,source=/path/to/artifacts,target=/artifacts,readonly \
    --entrypoint timeout rs-l2tpd-networkd-test:local 180 sh /opt/networkd-routes.sh
```

The main-table and VRF cases let networkd remove the daemon's `100::/128`
route during initial configuration, reload/reconfiguration and restart.
Each removal must be repaired, as must three successive explicit deletions.
The VRF case also replaces the configured VRF with the same name, a new
interface index and a different routing table: repair must follow the new
table, leave an unrelated table unchanged, and stop restoring the old table.
Both cases require the same daemon, tunnel socket, session interface, IDs and
inner addresses throughout. Shutdown with a repair pending must remove the
owned device and routes without recreating them.

Use `--env CASES=main` or `--env CASES=vrf` for one case. `NETWORKD` and
`NETWORKCTL` can select alternate executable paths in a prepared container.
The extra capabilities allow networkd to establish its normal capability set;
the test retains Docker's isolated network namespace and default filesystem
protections. All configuration changes and the D-Bus instance stay inside
the disposable container.

## Session preparation with systemd-networkd

The same image includes `networkd-sessions.sh`, which checks configured
session MAC addresses against a final-name match, the exact
`[Match] Type=l2tpeth` rule, and a match on the configured `MACAddress`.
It runs real networkd and udevd, and delays the
daemon's netlink receives by 100 ms with strace to expose startup races.
The type-match case also pauses the daemon immediately after creation until
networkd has configured the temporary link, then resumes it. This makes the
preparation race reproducible; cleanup always resumes it before termination.
The MAC-match case instead pauses after the address is set, allowing networkd
to configure and bring up the staged link before its final rename.

```sh
docker run --rm --network none \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BROADCAST \
    --cap-add BPF --cap-add SYS_ADMIN --cap-add SYS_PTRACE \
    --security-opt apparmor=unconfined \
    --mount type=bind,source=/path/to/artifacts,target=/artifacts,readonly \
    --entrypoint timeout rs-l2tpd-networkd-test:local 150 sh /opt/networkd-sessions.sh
```

The final interface name must never appear with an unconfigured MAC. In the
type-match case, recorded netlink events must prove networkd brought up and
assigned IPv4 and IPv6 addresses and routes to the temporary interface before
MAC preparation. Both addresses and routes must converge on the published
interface afterward, and shutdown must remove the tunnel and session.
The MAC-match case requires the same staged interface to survive this later
race and retain both address families and routes after publication.
Use `--env CASES=name`, `type`, or `mac` to select one case.

The test needs udev's genuine `DEVTYPE=l2tpeth` metadata. Networkd skips udev
when the `/sys` root filesystem is read-only, so `networkd-sysfs.sh` puts a
private tmpfs at that root and bind-mounts the original sysfs directories
under it read-only. Actual kernel attributes remain read-only; no host
`/sys`, `/run`, or device directories are mounted into the container.
The AppArmor override permits these container-local mount operations;
`SYS_PTRACE` permits the scheduling delay. The ordinary route-repair test
does not need either addition.

## Route-monitor overflow recovery

`monitor-resync.sh` pauses the daemon, queues 3,000 unrelated address events,
replaces its bound source address, and resumes it. It requires a logged
buffer overflow and monitor reopen, then the new source with the original
tunnel socket, session interface, inner addresses and IDs. Shutdown must
clean up the tunnel and session.

```sh
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW \
    --mount type=bind,source=/path/to/artifacts,target=/artifacts,readonly \
    --mount type=bind,source=/path/to/rs-l2tpd/tests/docker/monitor-resync.sh,target=/opt/monitor-resync.sh,readonly \
    --entrypoint timeout rs-l2tpd-network-test:local 45 sh /opt/monitor-resync.sh
```

## Degraded start

`degraded-start.sh` checks that configuration mistakes never stop the
daemon. Run it like `address-changes.sh`, mounting it at
`/opt/degraded-start.sh` and with a 150-second timeout:

```sh
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW \
    --mount type=bind,source=/path/to/artifacts,target=/artifacts,readonly \
    --mount type=bind,source=/path/to/rs-l2tpd/tests/docker/degraded-start.sh,target=/opt/degraded-start.sh,readonly \
    --entrypoint timeout rs-l2tpd-network-test:local 150 sh /opt/degraded-start.sh
```

The configuration has a valid tunnel and session; a tunnel whose literal
address contradicts its `ip_version`, with a session on it; a tunnel with a
zero identifier, with a session on it; a tunnel to a literal peer without a
route, with a session on it; a session with a multicast hardware address;
and an unparsable drop-in. `--check` must print the three tunnels and four
sessions that would be applied, the contradicting tunnel with the discard
address `100::` as its peer and the session without its hardware address,
name each problem, exit 1 and touch nothing. The namespace routes neither
the far peer nor `100::`: the daemon must not become ready while the far
tunnel cannot be created, and must meanwhile be waiting for a route to
`100::` without having created the null device yet. Once the far peer has
a route and the grace period has passed it must have created
`rsl2tpnull0`, routed `100::` to it and reached readiness with every
entry, the unusable endpoint connected to `100::` and the session carrying
the kernel's address, and frames sent into the pseudowire without a peer
must count as transmitted on the null device. It must keep the previous configuration when a reload still has
the unparsable drop-in. A reload that breaks the valid tunnel's identifier
must keep that tunnel's previous values and leave the new broken tunnel
out, applying the rest; a reload correcting the identifiers must create
the missing entries; a reload correcting the endpoint and the hardware
address must reconnect that tunnel in place and set the address, the
interfaces keeping their indexes throughout. Shutdown must remove every
tunnel and the null device. A configuration with nothing usable and an
empty one must both start and reach readiness with no tunnels and without
creating the null device.
