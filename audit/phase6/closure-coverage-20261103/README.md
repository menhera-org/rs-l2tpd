# Complete local merged-source coverage

The local checker passes with exit **0**: **8,444/8,444 production source
lines and 1,838/1,838 condition outcomes**. Raw LLVM retains
**8,657/8,709 lines (99.40%) and 1,804/1,838 outcomes (98.15%)**.
No production exclusion is added. This is a local P4 measurement, not
Phase 6 completion or a passing CI result.

The signed base is c0a1b3b. Initial and final source patches match and
identify the same test-only changes. The first instrumented ordinary
collection captures the production source/mapping inventory before further
profiles are added. The compressed full export, inventory and digests retain
the measurement. No profile from a preceding collector is imported.

The collection includes:

- Ten instrumented ordinary suites, seeds 81 through 90.
- A full instrumented Ubuntu 7.0.0-42 guest: 59 ignored library, 24 Linux,
  five review, 82 ordinary binary, three filesystem, two signal-limit,
  37 process and 27 normal scenario cases, plus the buffer-force case.
- Both thread and both fork refusal fixtures in networkless containers.
- Three GNU real-daemon CLI restarts. Three stable musl repetitions also
  pass; only the instrumented GNU binaries produce coverage profiles.

The full guest's first successful revision uses guest-local profiles.
Its previous 9p failure and cancelled retry are retained in the
[collector qualification](../coverage-guest-20261103/README.md); their profiles
are not imported. The first successful guest still leaves main.rs:86
uncovered. The focused CLI check observes exit 0 from the actual restart
command, re-exec confirmation from the same daemon and clean shutdown.

A separate [CI rehearsal](../coverage-ci-rehearsal-20261103/README.md) starts
from a new collector to qualify the integrated guest CLI check and the exact
profile scopes of the new workflow. The required-kernel matrix, complete
clause/resource/event-cost proof and CI enforcement remain separate work.
