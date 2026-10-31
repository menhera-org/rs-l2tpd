# rs-l2tpd

[![crates.io](https://img.shields.io/crates/v/rs-l2tpd.svg)](https://crates.io/crates/rs-l2tpd)

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
The binary runs on musl and glibc. All five required kernels passed the
recorded 18-scenario profile, including fragmentation. H15's newer
capability/netlink and missing-driver cases have passing host/guest records;
the current host subset passes 22 scenarios. H16 clock steps and monitored
pause/resume also pass on all five required kernels. The expanded normal
suite still needs a final matrix refresh. Phase 6 is underway: the source-link check,
unprivileged Incus case and root system-unit sandbox also have passing
local records. [Required-kernel behavior](docs/kernel-behavior.md) records
each target's differences, source evidence and limitations. The
[latest Phase 6 record](audit/PHASE6_VERIFICATION_2026-10-31.md) tracks the
approved errno distinction, readiness fix, boot-memory diagnosis and
remaining coverage/scenario/CI work. The global gates remain open.
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
- [Required-kernel behavior](docs/kernel-behavior.md): per-target differences, executed evidence and limitations
- [Packaging](docs/packaging.md): the implemented `--setup-systemd` installer and planned `musl-deb` packages
- [Specification](docs/spec/README.md): requirements, promises, architecture, behaviour in every condition

The audit reports and reviews behind the specification are in
[audit/](audit/).
