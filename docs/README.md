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

Version 0.2.0 has not been released; the rewrite ships under that
number. The tree contains configuration, fake/real kernel, reconciler,
runtime, services and binary; Phases 1–5 have scoped verification records.
The latest Phase 5 evidence is repository file
`audit/PHASE5_CONFORMANCE_FIXES_2026-10-30.md`, following the initial
`audit/PHASE5_VERIFICATION_2026-10-29.md` record. The binary runs on musl
and glibc. The November 1 matrix passes all 27 normal scenarios on each
of the five required kernels, including fragmentation, 300 tunnels and the
VRF reload regression. All five clock profiles, both IPv6-absent boots
and missing-driver recovery pass. The matrix freezes production source
`584062d` with released iphost 0.4.4; later test-only additions have separate qualification records.

The current E27 correction fixes verification stopping while a session's
announced deletion is still queued. A delayed-work model witness fails on
the preceding implementation and passes with the correction. Repeated models,
GNU/musl live suites, three musl Incus runs and the root sandbox pass.
The required matrix passes all thirteen profiles on `584062d`, including
the E27 correction and released iphost 0.4.4.
The iphost 0.4.4 integration and standard-library boundary changes pass
common checks, ten native and instrumented seeds, three musl model runs,
GNU live/Incus, manager, task limits and the root sandbox. Three musl
scenario/Incus repetitions pass. The required matrix also passes all
thirteen profiles on frozen signed commit `584062d`. Later test-only
additions retain their separate execution records.

Phase 6 remains open. Released iphost 0.4.4 fixes V12's anonymous Reply
validation defect. Three live witnesses fail with 0.4.3 and pass with the
registry release. Local and required-kernel integration checks pass; the
specification remains unchanged. Strict rule-map/source-link checks have passing CI
records, including ten-repetition qualification. Unprivileged Incus and the
root unit sandbox have passing local records. The approved MAC and
dependency-state contracts are applied. Broken `nix` signal wrappers use
checked `libc` calls under the [documented exception](dependencies.md#upstream-needs).
[Required-kernel behavior](kernel-behavior.md) records each target's
differences, source evidence, execution scope and limitations. Repository
file `audit/PHASE6_VERIFICATION_2026-11-01.md` gives coverage and the remaining
clause/resource/event-cost proof and identifies each test package's source.
Fresh coverage for iphost 0.4.4 and the boundary changes is **97.70% of lines
and 91.74% of branches**, leaving 200 lines and 153 branches. Repeated model
and GNU/musl tests include
failure controls for session ownership and descriptor handover. The checked
reply decoder passes all thirteen required matrix profiles. Request handling
has complete line/branch coverage, including real buffer-force success. The global gates remain open.
The specification's
[known gaps](spec/README.md#known-gaps) describe historical commit
`741117b`, removed in Phase 0. The interface page describes the target.

These pages use relative Markdown links, so navigation works in a checkout
and on GitHub. The directory is the `/docs` source for GitHub Pages;
`_config.yml` enables the README-index and relative-link plugins.
