# rs-l2tpd

[![CI](https://github.com/menhera-org/rs-l2tpd/actions/workflows/ci.yml/badge.svg)](https://github.com/menhera-org/rs-l2tpd/actions/workflows/ci.yml)
![GitHub License](https://img.shields.io/github/license/menhera-org/rs-l2tpd)

[![crates.io](https://img.shields.io/crates/v/rs-l2tpd.svg)](https://crates.io/crates/rs-l2tpd)
[![docs.rs](https://img.shields.io/docsrs/rs-l2tpd)](https://docs.rs/rs-l2tpd/)
[![Maintainability](https://qlty.sh/gh/menhera-org/projects/rs-l2tpd/maintainability.svg)](https://qlty.sh/gh/menhera-org/projects/rs-l2tpd)
[![Code Coverage](https://qlty.sh/gh/menhera-org/projects/rs-l2tpd/coverage.svg)](https://qlty.sh/gh/menhera-org/projects/rs-l2tpd)

A Linux L2TPv3 daemon written in Rust, and the `rs_l2tpd` library it is built on.
The kernel carries Ethernet pseudowires over IPv4 or IPv6.

- Peers can be addresses or host names, resolved by the system resolver or
  by configured resolvers (fixed servers, router advertisements, DHCPv6),
  with interface or VRF binding.
- Address changes, late bind devices and replacements under the same name
  are handled without recreating working session interfaces.
- Sessions support optional fixed MAC addresses and cookies.
- Invalid configuration degrades gracefully; usable entries keep running.
  Peers that cannot be reached yet and identifiers held elsewhere are
  retried without holding anything else up.
- The daemon starts before the network is ready, so network readiness can
  depend on its session interfaces without any route to a peer.
- Hosts without IPv6, with IPv6 disabled, VRFs, containers and routers with
  large routing tables are supported.
- The daemon works with any init system; `SIGUSR2` restarts it onto a new
  binary without re-creating its tunnels, and under systemd its tunnels
  survive a crash through the descriptor store.

## Status

Version 0.2.0 has not been published. The [verification record](audit/VERIFICATION.md)
identifies qualified source, commands, results and remaining checks.
[Kernel support](docs/kernel-support.md) describes supported targets and
operating limits. Debian 12 receives best-effort degradation outside support.

Completed implementation diaries and superseded audits remain in
[Git history](https://github.com/menhera-org/rs-l2tpd/tree/f5a2e7b/audit).

## Quick start

Build a static daemon:

```sh
cargo build --release --locked --target x86_64-unknown-linux-musl
```

Write `/etc/rs-l2tpd.toml` using the
[configuration example](docs/operation.md#configuration-files), then
validate it:

```sh
target/x86_64-unknown-linux-musl/release/rs-l2tpd --check
```

See the [interface page](docs/operation.md) for the command line,
signals, the supplied systemd unit and the host requirements.

## Documentation

Read the [published book](https://menhera-org.github.io/rs-l2tpd/) or the
[documentation index](docs/README.md):

- [Installation](docs/installation.md): static binaries, Debian packages and systemd
- [Configuration and operation](docs/operation.md): files, command line, signals and host requirements
- [Kernel support](docs/kernel-support.md): qualified targets and operating limits
- [Peer discovery](docs/peer-discovery.md): DNS, RA and DHCPv6 choices
- [Dependencies](docs/dependencies.md): shipped software and build tools
- [Developer guide](docs/developer.md): library integration and contribution gates
- [Specification](docs/spec/README.md): normative behavior

Current evidence is indexed in [audit/VERIFICATION.md](audit/VERIFICATION.md);
completed historical reports remain in Git history.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- Mozilla Public License, Version 2.0 ([LICENSE-MPL](LICENSE-MPL))

at your option.
