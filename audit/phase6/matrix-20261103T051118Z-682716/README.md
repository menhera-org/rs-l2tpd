# Required matrix on e29c6f3

All thirteen profiles pass on signed
e29c6f3055e9108e589f43edd673d2b4411dc34d; `result.log` records
`MATRIX_RESULT=0`. Both initial/final production/test patches are empty.
The initial and final publication selections are identical.

| Required kernel | Normal suite | Clock/pause |
|---|---|---|
| Ubuntu 6.8.0-147.147 | pass | pass |
| Vanilla 6.8.12 | pass | pass |
| Ubuntu 7.0.0-42.42 | pass | pass |
| Vanilla 7.0.14 | pass | pass |
| Mainline 7.4-rc1 | pass | pass |

Each normal profile passes 30 live library cases, 24 Linux conformance
cases, five review probes, 82 ordinary binary cases, three filesystem
cases, both signal task-limit cases, 37 process cases and 27 scenarios.
The scenarios include full-MTU fragmentation over both underlay families,
VRF bindings and the 300-tunnel/session workload. Each separate clock
profile has one passing case and controller-confirmed pause/resume.

Both IPv6-absent boots and missing-l2tp_eth recovery also pass. These
special profiles are scoped checks, not additional full normal suites.
Every profile has its required result markers in `run.log`; success is
not inferred from QEMU's exit status alone. Per-target directories retain
commands, kernel configs, artifact identities and complete output.

This is one complete current-source matrix, not ten matrix repetitions.
It does not erase the earlier parallel-QEMU clock failures or establish
their cause. Coverage, Incus, root systemd and clause proof remain separate
gates; this record alone does not complete Phase 6.
