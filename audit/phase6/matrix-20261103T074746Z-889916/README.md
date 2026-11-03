# Required matrix on f744335

All thirteen profiles pass on signed
`f74433551f294c3d1b224e053960923642ecc34d`; `result.log` records
`MATRIX_RESULT=0`. Both source patches are empty, and the initial and final
publication selections agree. The command used the system HTTPS client after
the two separately retained configured-client failures.

| Required kernel | Normal suite | Clock/pause |
|---|---|---|
| Ubuntu 6.8.0-147.147 | pass | pass |
| Vanilla 6.8.12 | pass | pass |
| Ubuntu 7.0.0-42.42 | pass | pass |
| Vanilla 7.0.14 | pass | pass |
| Mainline 7.4-rc1 | pass | pass |

Each normal profile passes all 37 process cases and 27 scenarios, including
full-MTU fragmentation, both underlay families, VRF bindings and the
300-tunnel/session workload. Every clock profile has both guest and controller
pause/resume markers. The two IPv6-absent boots and missing-Ethernet-driver
recovery also pass. Per-profile logs retain commands, kernel configurations,
artifact identities and result markers.

This is one matrix execution. It does not supply the plan's ten CI repetitions
or explain earlier parallel-QEMU clock failures. The later coverage-only
generation-guard refactor preserves behavior but changes production source, so
this record does not qualify that later revision.

