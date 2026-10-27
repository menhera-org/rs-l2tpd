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

Run all eleven privileged library tests, substituting an absolute artifacts
directory for `/path/to/artifacts`:

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
after rename and name reuse, VRF source selection, session MAC/link state, and
kernel cleanup. IPv4 source verification rejects `::ffff:0.0.0.0` as well as
the native wildcards.

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

On Linux 6.8.0-147-generic, validation on 2026-10-22 passed all eleven privileged
library tests, all eighteen compatibility cases and the MAC-changing check.

The tests establish behavior on the kernel and topologies exercised. They do
not establish universal compatibility across all kernels or routing setups.
