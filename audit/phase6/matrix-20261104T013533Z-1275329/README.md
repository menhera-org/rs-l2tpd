# Required kernel matrix

`tests/docker/run.sh matrix required` passes all thirteen profiles;
[`result.log`](result.log) is `MATRIX_RESULT=0`.

| Kernel | Normal | Clock/pause |
|---|---|---|
| Ubuntu `6.8.0-147-generic` | [27 scenarios / 37 process pass](noble/run.log) | [Pass](noble-clock/run.log) |
| Vanilla `6.8.12` | [27 / 37 pass](vanilla-6.8.12/run.log) | [Pass](vanilla-6.8.12-clock/run.log) |
| Ubuntu `7.0.0-42-generic` | [27 / 37 pass](resolute/run.log) | [Pass](resolute-clock/run.log) |
| Vanilla `7.0.14` | [27 / 37 pass](vanilla-7.0.14/run.log) | [Pass](vanilla-7.0.14-clock/run.log) |
| Mainline `7.4.0-rc1` | [27 / 37 pass](vanilla-7.4-rc1/run.log) | [Pass](vanilla-7.4-rc1-clock/run.log) |

Mainline's [IPv6-disabled](ipv6-disable/run.log) and
[no-IPv6](no-ipv6/run.log) profiles pass. Ubuntu 7.0's
[missing-Ethernet-driver/recovery](no-ethernet/run.log) profile passes.
All five clocks require successful controller markers as well as guest results.

Initial/final parsed publication selections agree. The recorded base revision
plus [`source.patch`](source.patch) equals committed production/test source
`c599b1f`; [`final-source.patch`](final-source.patch) is identical. This matrix
began before that commit and completed after it, without changing its inputs.
Fetched HTML indexes were removed after parsing; published selections,
package/source identities, kernel configurations and execution logs remain.
