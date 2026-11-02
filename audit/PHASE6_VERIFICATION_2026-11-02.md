# Phase 6 verification, 2026-11-02

Phase 6 remains incomplete. The required-kernel matrix now passes with
mainline 7.4-rc1. Production coverage remains 98.01% lines / 92.01% branches;
the prepared test batch has not yet been merged or collected. The
[November 1 record](PHASE6_VERIFICATION_2026-11-01.md) retains the detailed
history, earlier scope and maintainer decisions.

| Requirement | Executed evidence | Still required |
|---|---|---|
| P1 rule/source maps | Common checks pass with 333 active rules cited and 43 kernel facts classified/cited; prior ten-run CI qualification is retained | Complete clause proof remains distinct from declaration traceability |
| P2 scenarios | Frozen 455eef7 passes all 27 normal scenarios on each current required kernel, including H20 fragmentation and H17 scale | Complete clause/history/resource/event-cost proof |
| P3 required kernels | All thirteen profiles pass; initial/final publication selections agree; both tracked-source patches are empty | Recheck whenever the published target set changes |
| P4 coverage | 8,514/8,687 lines (98.01%); 1,704/1,852 branches (92.01%); no production exclusions, mismatches or saturated regions | Cover the remaining 173 lines and 148 branches, then enforce the completed gate in CI |
| P5 Incus/LXD | Signed 1b3d876 passes GNU and three shipped-musl unprivileged system-container runs on Ubuntu 24.04 / 6.8.0-147 | Preserve that kernel/userspace scope |
| P6 root sandbox | Signed 419c9b1 passes the unmodified supplied unit on Ubuntu 24.04 / 6.8.0-147; three GNU manager/task-limit runs also pass | Other distribution userspaces remain untested |
| P7 docs/CI | Current kernel selection, source/build comparison and scoped behavior are documented; strict maps and workflow timeouts remain active; the parser self-test is now in common CI | Final complete proof and 100% coverage enforcement |

The [current matrix](phase6/matrix-20261102T011736Z-3377142/README.md)
freezes signed Rust/test source `455eef7`. Each normal guest passes
22 serial library, 24 Linux, five review, 65 ordinary binary, three selected
filesystem-permission, 29 process and 27 normal scenario cases. Eight daemon
setup faults pass. Five binary declarations remain ignored in the ordinary
suite; three execute separately. Later test-only additions retain their
separate qualification.

| Required target | Guest release | Normal scenarios | H16 clock/pause |
|---|---|---|---|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 27 pass | pass |
| Vanilla 6.8.12 | 6.8.12 | 27 pass | pass |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 27 pass | pass |
| Vanilla 7.0.14 | 7.0.14 | 27 pass | pass |
| Mainline 7.4-rc1 | 7.4.0-rc1 | 27 pass | pass |

Both mainline IPv6-absent boots and Ubuntu's missing-Ethernet-driver
recovery pass separately. The [RC source/build record](phase6/mainline-rc-qualification-20261102/README.md)
retains archive identities, both build identities and the 43-file source
comparison. All selected files match fresh archive extractions. The
[per-kernel behavior page](../docs/kernel-behavior.md) distinguishes actual
observations, source evidence and userspace limits.

The source/build and parser-hook commit `ba0a3a6` passes
[GitHub CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41374346801).
The full matrix consumed unchanged Rust and kernel-runner sources while
that documentation/CI-helper commit was made. No production Rust behavior
has changed during this resumed work.

The resolver/event/host boundary batch remains isolated pending integration
and coverage collection. Its records under `phase6/resolver-boundaries-20261102/`
retain controls, repeated models and targeted DHCP-only guest runs. The
K41 listener-control follow-up is being qualified separately. Neither
pending batch is counted toward current coverage. Bare-kernel guests do not
establish new udev/networkd or Incus results. Broader kernels and live
non-x86 architectures remain unrun.
