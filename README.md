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

The last release is 0.1.5. The rewrite will ship as 0.2.0 and implements
the [specification](docs/spec/README.md). Phases 1–6 are complete, with the
[Phase 6 verification record](audit/PHASE6_VERIFICATION_2026-11-03.md)
retaining the commands, exact source identities and unsuccessful attempts.

Signed `9e6aae6` passes [all three CI jobs](https://github.com/menhera-org/rs-l2tpd/actions/runs/41607623091),
including production coverage, and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41607623178). Its
[required-kernel matrix](audit/phase6/matrix-20261103T090121Z-983779/README.md)
passes all thirteen profiles: five normal suites including fragmentation
and 300 tunnels, five clock/pause cases, both IPv6-absent boots and
missing-driver recovery. Source and publication selections remain unchanged
throughout the matrix. Earlier parallel clock failures remain recorded.

The approved checker passes **8,486/8,486 merged production source lines and
1,852/1,852 condition outcomes** in the
[final CI artifact](audit/phase6/ci-coverage-9e6aae6-20261103/README.md).
The [clause assessment](audit/phase6/clause-assessment-20261103/README.md)
checks semantic cases separately from lexical traceability. The S8 race it
found is fixed and included in the final CI, matrix and host runs.

Strict rule/source maps cover all 333 active rules and all 43 kernel facts.
Three consecutive unprivileged Incus runs and the unmodified root systemd
sandbox pass on the final source.
[Required-kernel behavior](docs/kernel-behavior.md) records every target's
differences and limitations. The November 3 publication recheck retains Ubuntu
6.8.0-147.147 and 7.0.0-42.42, vanilla 6.8.12 and 7.0.14, and mainline 7.4-rc1.
The specification's known-gap tables describe historical commit `741117b`.

## Quick start

Build a static daemon:

```sh
cargo build --release --locked --target x86_64-unknown-linux-musl
```

Write `/etc/rs-l2tpd.toml` using the
[configuration example](docs/interface.md#configuration-files), then
validate it:

```sh
target/x86_64-unknown-linux-musl/release/rs-l2tpd --check
```

See the [interface page](docs/interface.md) for the command line,
signals, the supplied systemd unit and the host requirements.

## Documentation

Start with the [documentation index](docs/README.md):

- [Plan](docs/plan.md): the rewrite in phases, with exit criteria
- [Architecture](docs/architecture.md): modules, the kernel boundary, records, tasks
- [Interface](docs/interface.md): configuration, command line, signals, unit, library
- [Dependencies](docs/dependencies.md): the supply chain and upstream needs
- [Testing](docs/testing.md): the suites, the gates, kernel test pitfalls
- [Required-kernel behavior](docs/kernel-behavior.md): all five target profiles, behavior differences, test coverage and limitations
- [Packaging](docs/packaging.md): the implemented `--setup-systemd` installer and planned `musl-deb` packages
- [Specification](docs/spec/README.md): requirements, promises, architecture, behaviour in every condition

The audit reports and reviews behind the specification are in
[audit/](audit/).

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- Mozilla Public License, Version 2.0 ([LICENSE-MPL](LICENSE-MPL))

at your option.
