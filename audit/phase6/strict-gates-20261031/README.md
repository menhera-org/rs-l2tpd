# CI qualification and strict traceability gates

[CI run 41205847108](https://github.com/menhera-org/rs-l2tpd/actions/runs/41205847108)
completed successfully on its first attempt at source
`0f5292ea348d49d2fcd5ec8e397d5f99eece8e0a`. The ordinary build job and all
ten seeded fake/live jobs passed. [run.json](run.json), [jobs.json](jobs.json)
and [artifacts.json](artifacts.json) retain the GitHub results and published
artifact digests. Those digests describe GitHub's ZIP archives; the retained
text files below are normalized extracts, not those archives.

Each `seed-N` directory retains its revision, result marker, fake-suite log,
guest log, executable identities, guest image identity and QEMU command.
ANSI escapes and Cargo build durations are omitted. Image-build progress,
download progress and duplicate kernel configurations are not retained here;
the original workflow artifacts remain available for their 14-day retention
period. The GitHub connector supplied job/artifact metadata; `gh run download`
extracted the artifacts locally.

[qualification-checks.log](qualification-checks.log) records checks of every
seed, revision and result. Each seed ran 92 ordinary library cases, one fake
conformance case, 75 rule cases and 25 service cases. Each fresh Ubuntu
`6.8.0-147-generic` guest ran 11 live library cases, 19 kernel cases, five
review cases, the ordinary binary suite and privileged binary probes,
27 process cases and all 26 normal scenarios. Every required result marker
was zero. The same scenario executable is used by the Docker runner.
Incus, root-systemd and the five-kernel matrix remain separate profiles.

After retaining these ten passes, the shared `test-ci-gates.sh` sets
`RULEMAP_STRICT=1 SRCLINK_STRICT=1` for the map checks. Regular CI keeps one
complete fake/live guest job per push or pull request. This removes repeated
qualification jobs after the required initial ten passes; it keeps the full
live suite, bounded step/job/QEMU timeouts, failure logs and no automatic
retries. The new strict workflow still needs its own successful CI run.

The rule map links all 333 active rules. The source map covers 43 facts:
37 production-cited and six classified in the evidence map, with no uncited
Linux functions. These checks establish declaration traceability. The earlier
[traceability record](../conditional-promises-20261031/README.md) and subsequent
packages identify the added assertions and citations. They do not prove every
clause, complete coverage or support for every kernel target.

[ci-gates.log](ci-gates.log) records the full common checks with both strict
flags set. [docs-checks.log](docs-checks.log) checks local Markdown targets.
`source-identity.log` confirms that Rust sources, tests and the lockfile still
match the qualified revision; the Cargo manifest change removes only its
obsolete lenient-gate comment.

The separate current matrix found a vanilla 7.0.14 scenario failure: the
H8 capture has 36 total netlink requests before adding routes and 37 after,
including 15 versus 16 generic-netlink requests. Both captures have exactly
the two intentional fixture route queries. That failure is under
investigation and remains a failure; none of the ten CI jobs used that
kernel. Phase 6 is still incomplete, including the 100% coverage gate.
