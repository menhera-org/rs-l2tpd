# Lifetime capture coverage follow-up

The `f744335` production-coverage job missed eight lines and six condition
outcomes introduced by the ordered S8 capture barrier. This change adds one
test covering barrier send refusal, a missing socket, generation loss,
successful completion, absent and failed replies, ambiguous registrations and
cleanup of a seen registration. The existing multicast test also covers reuse
of a removed index under the same name.

The duplicated generation guard is now `State::end_generation_if`. Direct
checks execute both its matching and stale-generation outcomes; the two
production callers retain their previous behavior.

`gnu.log` and `musl.log` each contain one passing focused test. `ci-gates.log`
is a complete successful `./test-ci-gates.sh` run, including both libcs and the
strict rule/source maps. A fresh ordinary-only instrumented collection covers
all new lifetime lines and outcomes. Its deliberately scoped checker report in
`focused-coverage.log` exits 1 overall because it has no live-guest profiles;
within `lifetime.rs`, only the pre-existing reader thread and joined-thread
paths are missing. Those paths were covered by the preceding full CI
collection, but that older success is not claimed for this changed source.

The next required evidence is full current-source CI coverage, followed by the
required kernel matrix, repeated unprivileged Incus scenarios and the root
systemd profile. Phase 6 remains open.

