# Unmodified Incus after both queue-storage fixes

The full unprivileged system-container case passes on Ubuntu
`6.8.0-147-generic` in 22.38 seconds; `INCUS_RESULT=0` and container deletion
succeeds. [scenario.log](scenario.log) retains the manager/store/re-exec
assertions. [buffer.log](buffer.log) verifies the FORCE refusal with EPERM.
The concurrent MAC write receives EBUSY; both ordered creations receive the
same persistent address, preserving the approved H11 limitations.

Run `tests/docker/run.sh incus`. Features are `all`, target is
`x86_64-unknown-linux-musl`, with the unmodified daemon and unit.
The tested tree is revision `0903d55` plus the matching source patch in
[the resource record](../resource-history-20261031/source.patch).
