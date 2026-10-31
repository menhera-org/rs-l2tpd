# Unmodified musl Incus check

`tests/docker/run.sh incus` passes with all features on Ubuntu
`6.8.0-147-generic` in 26.43 seconds. The disposable unprivileged system
container has no NIC and is deleted after the run. Concurrent udev MAC
assignment receives EBUSY; the ordered creations get the same persistent
address. The parent record `audit/phase6/rename-cost-20261031/` identifies
the source and retains the controller log; local scenario, journal and
buffer logs contain the assertions.
