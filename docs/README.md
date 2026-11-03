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
| [Required-kernel behavior](kernel-behavior.md) | Observations for every required Ubuntu/vanilla/mainline kernel, errno and notification differences, fragmentation, manager/container limits and test scope |
| [Kernel evidence](kernel-evidence.md) | Every K fact classified as a shared operation, live host case, delegated requirement or source assertion |
| [Packaging](packaging.md) | The implemented `--setup-systemd` installer (feature `setup-systemd`) and the planned Phase 7 `musl-deb` builder for `amd64` and `arm64` |
| [Upstream iphost work](upstream-iphost.md) | Instructions for protocol bug fixes, optional failure fallback, compatibility and daemon integration gates |
| [Specification](spec/README.md) | The normative behaviour, with the known gaps of the historical pre-rewrite implementation that the rewrite closes |

Version 0.2.0 has not been released. The tree contains the configuration,
fake/real kernel, reconciler, runtime, services and binary. Phases 1–5 have
scoped verification records; [Phase 6](phase6.md) remains open.

Signed `e29c6f3` passes all three CI jobs, including the separate production
coverage job, and CodeQL. Its full required-kernel matrix passes all
thirteen profiles, with identical initial/final publication selections
and empty source patches. Every normal target passes 27 scenarios and
37 process cases; the five clocks and special boot profiles also pass.
Earlier parallel clock failures remain recorded.

The approved source checker passes 8,444/8,444 production lines and
1,838/1,838 condition outcomes, both locally and in CI. The CI artifact's
51 source fingerprints match the independent local rehearsal.
Allocation-peak checks pass ten GNU and ten musl repetitions; the integrated
dispatch-work runner passes 240 cases and rejects a configuration-wide scan.
Their actual CI qualification and the final clause assessment remain open. Repository file
`audit/PHASE6_VERIFICATION_2026-11-03.md` identifies the source, commands,
results and remaining work.

Strict traceability, unprivileged Incus and the root system-unit sandbox
have passing records with their scope stated. Released iphost 0.4.4 supplies
the tested anonymous Reply correction. The approved MAC/dependency-state
contracts and the [libc exception](dependencies.md#upstream-needs) apply.
[Required-kernel behavior](kernel-behavior.md) records every target's
differences, source evidence and limitations. The specification's
[known gaps](spec/README.md#known-gaps) describe historical commit `741117b`.

These pages use relative Markdown links, so navigation works in a checkout
and on GitHub.
 The directory is the `/docs` source for GitHub Pages;
`_config.yml` enables the README-index and relative-link plugins.
