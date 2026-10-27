# Installation and requirements

[Documentation index](README.md)

rs-l2tpd runs on Linux and requires kernel L2TPv3 over IP and Ethernet
pseudowire support. The daemon manages network interfaces and sockets, so
it needs the corresponding network privileges. It does not require an init
system; a musl build has no dependency on the host's libc.

## Building

The crate requires Rust 1.89 or newer. The `bin` feature is enabled by
default, so `cargo build --release` builds the daemon. For a static Linux
binary, use a musl target:

```sh
cargo build --release --locked --target x86_64-unknown-linux-musl
```

Add `--features setup` to include the `--setup` installer. The repository's
`build-release.sh` uses `cross` to build release archives; its default
targets are x86_64 and aarch64 musl.

Read the [configuration guide](configuration.md), then run `rs-l2tpd --check`
to inspect the merged configuration. Running `rs-l2tpd` starts the daemon;
see [operation](operation.md) for readiness, PID files and signals.

## Supplied systemd unit

A binary built with the `setup` feature accepts `rs-l2tpd --setup`. Run this
as root to install the binary and sandboxed systemd unit under `/usr/local`,
ensure the configuration paths exist, and enable and start the service.

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
reachability before creating usable session interfaces. Literal-peer underlay route
providers must run concurrently or independently to avoid a startup cycle.
See the [early-start contract](operation.md#early-start-contract) and the
[kernel-resource definition of readiness](operation.md#readiness).

## Current procfs requirement

The current `l2tp 0.4.0` dependency requires procfs to be mounted and
`/proc/thread-self/ns/net` to be accessible at startup, including inside
chroots and other sandboxes. Supporting operation without procfs again is
deferred until a new upstream `l2tp 0.4.x` release resolves this requirement.
