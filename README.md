# rs-l2tpd

[![crates.io](https://img.shields.io/crates/v/rs-l2tpd.svg)](https://crates.io/crates/rs-l2tpd)

A Linux L2TPv3 daemon written in Rust, and the `rs_l2tpd` library it is built on.
The kernel carries Ethernet pseudowires over IPv4 or IPv6.

- Peers can be addresses or host names, with interface or VRF binding.
- Address changes, late bind devices and replacements under the same name
  are handled without recreating working session interfaces.
- Sessions support optional fixed MAC addresses and cookies.
- Invalid configuration degrades gracefully; usable entries keep running.
  Peers that cannot be reached yet and identifiers held elsewhere are
  retried without holding anything else up.
- [Early startup](docs/operation.md#early-start-contract) lets network readiness
  depend on daemon-created session interfaces, without any route to a peer.
- Hosts without IPv6, with IPv6 disabled, and routers with large routing
  tables are supported.
- The daemon works with any init system and includes a systemd installer.

## Quick start

Build a static daemon with the optional installer:

```sh
cargo build --release --locked --target x86_64-unknown-linux-musl --features setup
```

Write `/etc/rs-l2tpd.toml` using the
[configuration example](docs/configuration.md), then validate it:

```sh
target/x86_64-unknown-linux-musl/release/rs-l2tpd --check
```

See [installation](docs/installation.md) for kernel requirements, running the
daemon and the supplied systemd unit.

## Documentation

Start with the [documentation index](docs/README.md):

- [Installation and requirements](docs/installation.md)
- [Configuration and error handling](docs/configuration.md)
- [Session identity, hardware addresses and cookies](docs/sessions.md)
- [Readiness, reconnection and routing](docs/operation.md)
- [Library APIs](docs/library.md)
- [Testing and compatibility](docs/testing.md)
- [Contracts every change must keep](docs/contracts.md)
- [Specification: requirements, promises, architecture, behaviour in every condition](docs/spec/README.md)

Complete container test commands are in the
[Docker validation guide](tests/docker/README.md).
