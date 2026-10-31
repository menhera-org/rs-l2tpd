# Intermediate Incus check

This unprivileged system-container run passes with `INCUS_RESULT=0` and
successful deletion. It tests the DNS queue-storage fix before the outgoing
queue fix. [scenario.log](scenario.log), [buffer.log](buffer.log) and
[cleanup.log](cleanup.log) retain its results. The source is revision
`0903d55` plus the resource record's
[intermediate patch](../resource-history-20261031/worker-only/final-source.patch).

The subsequent [final Incus run](../incus-20261031T164656Z-11386/README.md)
tests both production fixes. Both runs use all features and unmodified musl
binaries, through `tests/docker/run.sh incus`.
