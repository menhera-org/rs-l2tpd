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

The last release is 0.1.5. The tree is being rewritten against a complete
[specification](docs/spec/README.md); the rewrite ships as 0.2.0. The
[plan](docs/plan.md) says what is being built and in which order, and the
[current contract gaps](docs/spec/README.md#current-contract-gaps) list the
review corrections and their acceptance work. Configuration, kernel,
reconciler, runtime, service and process code exists; Phases 1–5 have scoped
verification records, including the
[Phase 5 conformance follow-up](audit/PHASE5_CONFORMANCE_FIXES_2026-10-30.md).
The binary runs on musl and glibc. The November 1 matrix passes all 27
normal scenarios on each of the five required kernels, including
fragmentation, 300 tunnels and the VRF reload regression. All five clock
profiles, both IPv6-absent boots and missing-driver recovery pass.
The matrix freezes production source `2051827`; later test-only additions
have separate qualification records.

Phase 6 remains open. Strict rule-map/source-link checks have passing CI
records, including ten-repetition qualification. Unprivileged Incus and
the root system-unit sandbox have passing local records. The approved MAC
and dependency-state contracts are applied. Broken `nix` signal wrappers
use checked `libc` calls under the documented exception. The
[latest Phase 6 record](audit/PHASE6_VERIFICATION_2026-11-01.md) gives coverage
and the remaining clause/resource/event-cost proof.
[Required-kernel behavior](docs/kernel-behavior.md) records each target's
differences, source evidence and limitations. The global gates remain open.
The known-gap tables describe historical commit `741117b`.

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
