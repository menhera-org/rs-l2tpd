# rs-l2tpd documentation

[![crates.io](https://img.shields.io/crates/v/rs-l2tpd.svg)](https://crates.io/crates/rs-l2tpd)

rs-l2tpd turns a configuration into Linux kernel L2TPv3 tunnels and
Ethernet pseudowire sessions and keeps them that way. The
[specification](spec/README.md) says what it must do; these pages say how
it is being built to do it. They are the plan for roadmap steps 5 and 6
of `CONTRIBUTING.md` (the rewrite, then the proof), made into concrete
steps and designs. The source, the issue tracker and the audit reports
are in the [GitHub repository](https://github.com/menhera-org/rs-l2tpd).

| Page | Contents |
|---|---|
| [Plan](plan.md) | The rewrite as ordered phases with deliverables and exit criteria, what stops it (upstream needs), what is deleted |
| [Architecture](architecture.md) | The target crate: modules, the `Kernel` boundary that makes every rule testable, records, tasks and channels, the operation planner, how each specification page maps to code |
| [Interface](interface.md) | What the outside sees: configuration files, command line, signals, exit codes, logging, the systemd unit, the library API |
| [Dependencies](dependencies.md) | The supply chain after the rewrite, each crate with its reason, and what was removed |
| [Phase 6 instructions](phase6.md) | The proof phase as ordered work packages for coding agents: traceability, scenario suite, kernel matrix, coverage, Incus/LXD, the root unit sandbox, the record |
| [Testing](testing.md) | How 100 % coverage, one test per specification claim, determinism and live-kernel proof are reached: the fake kernel, the conformance suite, the container and QEMU matrices, the rule map |
| [Kernel evidence](kernel-evidence.md) | Every K fact classified as a shared operation, live host case, delegated requirement or source assertion |
| [Packaging](packaging.md) | The implemented `--setup-systemd` installer (feature `setup-systemd`) and the planned Phase 7 `musl-deb` builder for `amd64` and `arm64` |
| [Upstream iphost work](upstream-iphost.md) | Instructions for protocol bug fixes, optional failure fallback, compatibility and daemon integration gates |
| [Specification](spec/README.md) | The normative behaviour, with the known gaps of the historical pre-rewrite implementation that the rewrite closes |

Version 0.2.0 has not been released; the rewrite ships under that
number. The tree contains configuration, fake/real kernel, reconciler,
runtime, services and binary; Phases 1–5 have scoped verification records.
The latest Phase 5 evidence is repository file
`audit/PHASE5_CONFORMANCE_FIXES_2026-10-30.md`, following the initial
`audit/PHASE5_VERIFICATION_2026-10-29.md` record. The binary runs on musl
and glibc; fresh process tests pass on Ubuntu 6.8.0-147 and QEMU kernels
6.12.114, 6.18.59 and 7.3. Phase 6 is underway: source links, the
unprivileged Incus case and the root unit sandbox have passing local
records. The partial scenario suite and required matrix driver exist.
Repository file `audit/PHASE6_VERIFICATION_2026-10-31.md` records a kernel
errno distinction awaiting a maintainer decision, a fixed readiness race,
an unresolved guest boot failure and the remaining global gates.
The specification's
[known gaps](spec/README.md#known-gaps) describe historical commit
`741117b`, removed in Phase 0. The interface page describes the target.

These pages use relative Markdown links, so navigation works in a checkout
and on GitHub. The directory is the `/docs` source for GitHub Pages;
`_config.yml` enables the README-index and relative-link plugins.
