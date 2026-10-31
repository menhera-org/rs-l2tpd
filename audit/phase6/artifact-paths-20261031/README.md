# Cargo artifact parsing with forced color

The first CI qualification attempt failed before QEMU started. The workflow
sets `CARGO_TERM_COLOR=always`, which inserts an ANSI reset between Cargo's
`Executable` label and the test name. The guest parser found no executable
path. Its relative-path handling turned the empty string into the checkout
directory, and `-x` accepted that searchable directory. `cp` then failed with
`-r not specified; omitting directory`.

[The failed job](https://github.com/menhera-org/rs-l2tpd/actions/runs/41205236792/job/124548855152)
and [ci-failure-excerpt.log](ci-failure-excerpt.log) retain the error. The rest
of that revision's run was cancelled after identifying this shared harness
bug. It does not count toward the ten passing repetitions, and no test
failure was retried into a passing qualification.

The QEMU, Docker and Incus runners now pass `--color never` to the captured
Cargo commands whose output supplies executable paths. Other Cargo commands
retain their existing color behavior. This controls the parser's input;
it is not output cleanup for rexec. All three runners also require regular
executable files, so an empty or unexpected parsed path cannot select a
directory.

## Verification

```sh
CARGO_TERM_COLOR=always tests/docker/run.sh scenarios promises::readiness_existence
CARGO_TERM_COLOR=always tests/kernel/run-guest.sh IMAGE MODULES CONFIG clock RECORD
./test-ci-gates.sh
```

The Docker run uses `6.8.0-147-generic` and the all-feature musl target. It
passes the focused promise scenario in 1.51 seconds, with
`SCENARIO_RESULT=0`, in
[the retained run](../scenarios-20261031T132628Z-3934831/run.log).
The forced-color [QEMU clock profile](../qemu-artifacts-color-20261031/run.log)
also passes: artifact preparation copies all seven test executables, and
the H16 case finishes in 64.78 seconds with all guest/controller markers zero.
This uses the corrected runner and the freshly prepared offline review image.
It is a clock-profile and artifact-preparation check, not a second full
normal scenario run.

An injected Cargo command that succeeds with empty output exercises the
directory-refusal path. Incus availability is stubbed to succeed for this
preparation-only check; no Incus container or QEMU guest starts. Each runner
must exit 1 with its missing-executable diagnostic, as asserted in
[empty-results.log](empty-results.log). The corresponding `empty-*.log`
files retain those errors. This does not claim a live Incus pass.

[ci-gates.log](ci-gates.log) records passing common checks; its map invocations
remain lenient. `revision` and `source.patch` identify the runner changes.
Cargo build durations are omitted. A full Incus profile and the required
five-kernel refresh remain separate Phase 6 work.

A full normal Ubuntu 24.04 guest run, started before this parser fix with
color unforced, passes all current Rust tests:
11 live library, 19 kernel-conformance, five review, 38 ordinary binary,
three explicit binary permission cases, 27 process and 26 scenario cases.
Nested child results are not added to the parent counts. The scenario suite
takes 590.84 seconds and the guest returns all three required zero-result
markers. [Its record](../qemu-promises-noble-20261031/run.log) is a current-source
Ubuntu profile, not the complete required matrix. Its image and artifact
hashes retain the run's identity.
