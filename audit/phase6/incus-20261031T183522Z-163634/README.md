# Unprivileged system container with released iphost 0.4.2

`tests/docker/run.sh incus` passes the full P5 case with the unmodified
musl daemon on Ubuntu `6.8.0-147-generic`: one scenario in 14.62 seconds.
The disposable unprivileged container has no host network attachment and
is deleted afterward. The controller log is in the parent upstream-netns
record's `unmodified-incus-controller.log`.

The source is the working tree over `729c9f2`, identified by `revision`
and `source.patch` in `../upstream-netns-20261031/`. All features are enabled.
Scenario, manager, buffer and cleanup logs retain the assertions. The
coverage-only GNU Incus transport remains a separate run.
