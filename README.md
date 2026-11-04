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

The last release is 0.1.5; v0.2.0 is not released. Its implementation and
Phase 6 proof are complete. The [verification record](audit/VERIFICATION.md)
indexes current commands, source identities, results and limitations.

Production source `c599b1f` passes [all three CI jobs](https://github.com/menhera-org/rs-l2tpd/actions/runs/41777583123)
and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41777583117).
Merged production coverage is **8,582/8,582 lines and 1,844/1,844 condition
outcomes**, with unchanged exclusions. Strict rule/source maps cover all
333 active rules and 43 kernel facts; semantic clause cases remain a
separate obligation.

All thirteen required kernel profiles pass: Ubuntu 6.8.0-147 and 7.0.0-42,
vanilla 6.8.12 and 7.0.14, and mainline 7.4-rc1, with separate clock and
special boot checks. Three fresh scenario/Incus pairs and the unmodified
root-systemd guest pass. [Kernel qualification](docs/kernel-behavior.md)
records exact scope and differences. All six optional Debian 13 and Rocky
9/10 profiles pass after a test-only capture fix: each normal guest passes
28 scenarios and 37 process cases, with a separate clock/pause pass.
The daemon is unchanged. Debian 12 receives best-effort degradation outside
the support target.

Completed implementation diaries and superseded audits are preserved in
[Git history](https://github.com/menhera-org/rs-l2tpd/tree/c599b1f9c2343a3ffe6be315a6d77c4b68106744/audit).

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

Read the [published book](https://menhera-org.github.io/rs-l2tpd/) or the
[documentation index](docs/README.md):

- [Plan](docs/plan.md): completed milestones, verification requirements and pending release work
- [Architecture](docs/architecture.md): modules, the kernel boundary, records, tasks
- [Interface](docs/interface.md): configuration, command line, signals, unit, library
- [Dependencies](docs/dependencies.md): the supply chain and upstream needs
- [Testing](docs/testing.md): the suites, the gates, kernel test pitfalls
- [Required-kernel behavior](docs/kernel-behavior.md): required and optional targets, behavior differences, test scope and limitations
- [Packaging](docs/packaging.md): the implemented `--setup-systemd` installer and planned `musl-deb` packages
- [Specification](docs/spec/README.md): requirements, promises, architecture, behaviour in every condition

Current evidence is indexed in [audit/VERIFICATION.md](audit/VERIFICATION.md);
completed historical reports remain in Git history.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- Mozilla Public License, Version 2.0 ([LICENSE-MPL](LICENSE-MPL))

at your option.
