# Final-source container and root-unit checks

Signed commit `9e6aae63ec43166941a14fed8883547ead7dc4f0`
passes three consecutive complete musl scenario/Incus pairs and the supplied
root systemd unit. The initial and final production/test patches are empty.
`result.log` records
`THREE_MUSL_SCENARIO_INCUS_PAIRS_AND_ROOT_SYSTEMD_RESULT=0`.

| Repetition | Musl scenarios | Unprivileged Incus |
|---|---|---|
| 1 | 27 passed | complete system-container case passed |
| 2 | 27 passed | complete system-container case passed |
| 3 | 27 passed | complete system-container case passed |

The three scenario logs are retained in the sibling directories named by the
driver logs. Each Incus run uses `security.privileged=false`, no profile and no
network device, observes a real `SO_RCVBUFFORCE` refusal and working
`SO_RCVBUF` fallback, exercises systemd descriptor hand-over, bindv6only
correction, the concurrent and ordered persistent-MAC contracts, and the
configured-MAC authority policy. Every disposable container was deleted.

The root-systemd guest passes the supplied unit's private mounts, protected
root and tunables, the narrow writable tunable exception, exact capability
set, readiness ordering, crash adoption, CLI restart and cleanup. Its log ends
with `ROOT_SYSTEMD_RESULT=0`; no drop-in relaxes the shipped unit.

These are the required three local container repetitions and the final
root-unit qualification. Broader Debian and RHEL-family userspaces remain
desirable, non-gating coverage.
