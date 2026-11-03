# Current-source container and root-unit checks

Signed e29c6f3 passes three consecutive full musl scenario/Incus pairs and
the unmodified root systemd profile. Initial/final production/test patches
are empty. All runs observe Ubuntu 6.8.0-147-generic; the root guest uses
the stock Noble image and modules from the completed required matrix.

| Repetition | Scenarios | Unprivileged Incus |
|---|---|---|
| 1 | 27 pass | full system-container case and buffer fallback pass |
| 2 | 27 pass | full system-container case and buffer fallback pass |
| 3 | 27 pass | full system-container case and buffer fallback pass |

Every Incus run explicitly uses security.privileged=false, no profile and
no network device. Containers are deleted on exit. The scenario exercises
the approved concurrent/ordered persistent-MAC contracts, configured-MAC
authority, bindv6only correction and systemd descriptor hand-over. The
buffer check requires a real SO_RCVBUFFORCE refusal and working fallback.
Each driver log identifies its full scenario/Incus record directory.

The root-systemd guest passes the supplied unit's mount/capability sandbox,
tunable exception, readiness, crash adoption, CLI restart and shutdown
checks, with ROOT_SYSTEMD_RESULT=0. Its commands, config, journal and
artifact identities are under root-systemd/; no test drop-in relaxes the
supplied restrictions.

The shipped-musl daemon's Git blob identity remains identical after adding
the new test registrations and running the common checks. Production src/
is unchanged. Those new model/allocation tests have separate records;
these live runs do not claim to execute them.

This is the required local three-pair qualification, not ten CI executions
or broader distribution-userland testing. Earlier failures retain their
own records. These passes do not independently close the complete clause
and resource/event-cost proof.
