# Unprivileged system container with released iphost 0.4.3

`tests/docker/run.sh incus` passes the full P5 case with the unmodified
musl daemon on Ubuntu `6.8.0-147-generic`: one scenario in 11.91 seconds.
The disposable unprivileged container has no host network attachment and
is deleted afterward. The controller log is in the parent follow-up record's
`unmodified-incus-controller.log`.

The source is the working tree over `da65fc5`, identified by `revision`
and `initial-source.patch` in `../upstream-dhcp-queues-20261031/`.
All features are enabled. Scenario, manager, buffer and cleanup logs retain
the assertions. The later readiness test changes no production code;
the coverage-only GNU transport is a separate run.
