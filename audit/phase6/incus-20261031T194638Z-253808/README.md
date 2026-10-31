# Unmodified musl Incus check

`tests/docker/run.sh incus` passes on Ubuntu `6.8.0-147-generic` with
all features and the current identifier-index proposal. The disposable
unprivileged Ubuntu system container has no NIC; cleanup deletes it.
`buffer.log`, `scenario.log` and `journal.log` retain
the commands and checks. The parent record is
`audit/phase6/reconcile-lookups-20261031/`.
