# Vanilla 7.0.14 after the H8 fixture correction

The full normal profile now passes all 26 scenarios in 449.00 seconds.
It also passes 11 live library cases, 19 kernel cases, five review cases,
38 ordinary binary cases plus privileged probes and all 27 process cases.
The separate H16 wall-clock/QMP-pause profile passes in 64.05 seconds.
Both boots report `GUEST_KERNEL_RELEASE=7.0.14` and all required zero
result markers; `VANILLA7014_REFRESH_RESULT=0` records controller success.

`revision` is `fb41979`, with an empty initial `source.patch`. The normal
and clock directories retain exact kernel, executable and userspace
identities, commands and guest logs. Features are `all`; target is
`x86_64-unknown-linux-musl`. The only functional test change from the
[earlier failed matrix](../matrix-20261031T133318Z-3943822/README.md) is
[the H8 measurement correction](../h8-counts-20261031/README.md).
Production daemon behavior is unchanged.

The failed matrix remains failed. This targeted run closes the observed
vanilla 7.0.14 failure and its skipped clock profile; it is not a fresh
five-target driver result. The final matrix must still run a consistent
final source snapshot with unchanged published targets.
