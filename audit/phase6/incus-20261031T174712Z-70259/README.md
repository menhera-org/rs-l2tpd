# Unprivileged system-container check after the resolver-index changes

`tests/docker/run.sh incus` passes the full P5 case with the unmodified
musl daemon on Ubuntu `6.8.0-147-generic`: one scenario in 18.04 seconds.
The disposable unprivileged container has no host network attachment and
is deleted after the run. The controller log is in the parent package's
`unmodified-incus-controller.log`.

The source is the working tree over `ba9faeb`, recorded by `revision`,
`source.patch` and `workers_cost.rs` in
`../resolver-cost-20261031/`. All features are enabled. The concurrent
udev/networkd race and the two ordered persistent-MAC creations follow
the approved H11 contract. This is separate from the GNU coverage-only
Incus transport. The runner's logs retain the exact assertions and cleanup.
