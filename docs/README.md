# rs-l2tpd documentation

[![crates.io](https://img.shields.io/crates/v/rs-l2tpd.svg)](https://crates.io/crates/rs-l2tpd)

rs-l2tpd creates and maintains Linux L2TPv3 tunnels and Ethernet pseudowire
sessions. The [specification](spec/README.md) defines behavior; these pages
describe the implemented tree, its interfaces and verification.
Version 0.2.0 is not released. Implementation phases 1–6 are complete;
[release packaging and publication](plan.md#phase-7--release) remain pending.

| Page | Contents |
|---|---|
| [Plan](plan.md) | Completed milestones, maintenance requirements and pending release work |
| [Architecture](architecture.md) | Actual modules, kernel boundary, identities, reconciliation and worker lifecycle |
| [Interface](interface.md) | Configuration, CLI, signals, logging, unit and library API |
| [Dependencies](dependencies.md) | Current crates/tools, upstream boundaries and checked-libc exceptions |
| [Phase 6](phase6.md) | Current status and the six gates, Incus/root-systemd checks and record requirements |
| [Testing](testing.md) | Commands, exact suite scope, determinism, coverage and moving kernel targets |
| [Kernel behavior](kernel-behavior.md) | Required/optional results, observed differences, source limits and userspace scope |
| [Kernel evidence](kernel-evidence.md) | All 43 active K facts classified by shared/live/delegated/source evidence |
| [Packaging](packaging.md) | Implemented systemd installer and the pending `musl-deb` design |
| [Resolver integration](upstream-iphost.md) | Released iphost contracts, daemon-owned policy and future upstream work |
| [Specification](spec/README.md) | Normative requirements, promises and behavior |

Production source `c599b1f` passes all three
[CI jobs](https://github.com/menhera-org/rs-l2tpd/actions/runs/41755915522)
and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41755915465).
Merged production coverage reaches 8,582/8,582 lines and 1,844/1,844 condition
outcomes. Strict maps cover all 333 active rules and 43 kernel facts;
semantic clause cases and actual live execution remain separate obligations.

All thirteen required kernel profiles pass, as do three fresh musl
scenario/Incus pairs and the unmodified root-systemd guest. All optional
profiles have run: Rocky 9/10 pass normal and clock checks; Debian 12
fails older MAC/UP-device rename assumptions. The
[qualification page](kernel-behavior.md) states the exact results and limits.
Repository file `audit/VERIFICATION.md` indexes current evidence.

Completed diaries and superseded audits remain in
[Git history](https://github.com/menhera-org/rs-l2tpd/tree/c599b1f9c2343a3ffe6be315a6d77c4b68106744/audit).
Current gating scripts live under `tests/`, `tools/` or the repository root;
`audit/` holds evidence. Fetched kernel.org HTML is not retained in commits.

Relative links work in a checkout and on GitHub. This directory is the
GitHub Pages source; `_config.yml` enables README-index and relative-link
handling.
