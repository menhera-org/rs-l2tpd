# Installation and requirements

[Documentation index](README.md)

rs-l2tpd runs on Linux and requires kernel L2TPv3 over IP and Ethernet
pseudowire support: `l2tp_core`, `l2tp_netlink`, `l2tp_ip` and `l2tp_eth`,
plus `l2tp_ip6` for IPv6 peers, loaded or loadable on demand. It needs no
`dummy` driver, no route and no particular network state at start-up. It
does not require an init system; a musl build has no dependency on the
host's libc. IPv6 need not be available: a host without IPv6 addresses,
with IPv6 disabled by sysctl or booted with `ipv6.disable=1` runs IPv4
tunnels as usual; see
[binding and source selection](operation.md#binding-and-source-selection).
The full list, with the condition for each item, is the specification's
[kernel page](spec/kernel.md#requirements).

## Capabilities

The daemon requires these capabilities in its network namespace:

| Capability | Used for | Without it |
|---|---|---|
| `CAP_NET_ADMIN` | creating tunnels, sessions and devices | nothing can be created: reported, retried every second, readiness withheld |
| `CAP_NET_RAW` | router-advertisement resolvers (a raw ICMPv6 socket); binding a socket that already has a device binding | router-advertisement resolvers learn servers only where `accept_ra` is on; a binding is changed only after a disconnect |
| `CAP_NET_BIND_SERVICE` | DHCPv6 resolvers (UDP port 546) | works only where `net.ipv4.ip_unprivileged_port_start` is at most 546 (Docker sets it to 0); otherwise DHCPv6 resolvers fail and `ipv6` resolvers use router advertisements only |

At start-up the daemon reports each one it lacks, once, at warning level,
and then runs on the fallbacks above. The fallbacks are not guaranteed to
work in every case; grant all three.

## Building

The crate requires Rust 1.89 or newer. The `bin` feature is enabled by
default, so `cargo build --release` builds the daemon. For a static Linux
binary, use a musl target:

```sh
cargo build --release --locked --target x86_64-unknown-linux-musl
```

Add `--features setup` to include the `--setup` installer. Set
`CONFIG_FILE_PATH` and `CONFIG_DIR_PATH` at build time to change the
default configuration paths; they can also be given on the command line.
The repository's `build-release.sh` uses `cross` to build release
archives; its default targets are x86_64 and aarch64 musl.

Read the [configuration guide](configuration.md), then run `rs-l2tpd --check`
to inspect the merged configuration. Running `rs-l2tpd` starts the daemon;
see [operation](operation.md) for readiness, PID files and signals.

## Supplied systemd unit

A binary built with the `setup` feature accepts `rs-l2tpd --setup`. Run this
as root to install the binary and sandboxed systemd unit under `/usr/local`,
ensure the configuration paths exist, and enable and start the service.

The unit grants the three required capabilities explicitly. It confines
the service to netlink and IP sockets (plus what the host's resolver
needs), keeps the system read-only except for the PID file, allows the
`net.ipv6.bindv6only` write of [host tunables](operation.md#hosts-with-bindv6only),
and enables the systemd descriptor store, so that tunnels survive a
restart ([restart](operation.md#restart)).

When using this supplied unit on a systemd-based system, configuration files
under `/home` or `/tmp` are not supported, including symlinks that resolve
there. The unit uses `ProtectHome=yes` and `PrivateTmp=yes`; keep configuration
in `/etc` or another location visible inside its sandbox. This restriction
does not apply when running the daemon without that unit.

The unit uses `Before=network-online.target`,
`RequiredBy=network-online.target` and `Type=forking`. rs-l2tpd can start
before the network is fully ready, and network readiness can depend on its
session interfaces. This is a required compatibility contract: the service
**MUST NOT** wait for `network-online.target`, complete DNS setup or peer
reachability before creating usable session interfaces. See the
[early-start contract](operation.md#early-start-contract) and the
[kernel-resource definition of readiness](operation.md#readiness).

The unit is one integration. The daemon works under any init system
(OpenRC, runit, s6, busybox init, a container entry point) through its
[process contract](spec/process.md#the-process-contract): it double-forks,
its parent exits 0 at readiness, it writes a PID file, takes `SIGHUP`,
`SIGTERM`, `SIGINT` and `SIGUSR2`, and logs to standard error. It needs
only `/proc` of the filesystem besides its own files.

## Current procfs requirement

The current `l2tp 0.4.0` dependency requires procfs to be mounted and
`/proc/thread-self/ns/net` to be accessible at startup, including inside
chroots and other sandboxes. Supporting operation without procfs again is
deferred until a new upstream `l2tp 0.4.x` release resolves this requirement.
