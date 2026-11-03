# Required kernel matrix on 9e6aae6

All thirteen profiles pass on signed commit
`9e6aae63ec43166941a14fed8883547ead7dc4f0`; `result.log` records
`MATRIX_RESULT=0`. Both source patches are empty. The initial and final
publication selections and mainline tag agree.

| Required kernel | Normal suite | Clock/pause |
|---|---|---|
| Ubuntu 6.8.0-147.147 | pass | pass |
| Vanilla 6.8.12 | pass | pass |
| Ubuntu 7.0.0-42.42 | pass | pass |
| Vanilla 7.0.14 | pass | pass |
| Mainline 7.4-rc1 | pass | pass |

Each normal profile passes all 37 process cases and 27 scenarios, including
full-MTU fragmentation over both underlay families and VRFs, manager races,
and the 300-tunnel/session workload. Every clock profile contains the guest
and controller pause/resume markers. The `ipv6.disable=1`, `CONFIG_IPV6=n`
and missing-Ethernet-driver recovery profiles also pass.

The per-profile directories retain the command, kernel configuration, build
identity and complete output. Earlier failed parallel-QEMU clock experiments
remain in their original records. This serial passing matrix neither removes
those failures nor assigns them a cause.
