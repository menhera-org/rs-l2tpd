# Instrumented normal guest collector

The collector reuses tests/kernel/matrix-init.sh for the normal GNU
instrumented suites and adds the existing buffer-force case. Its integrated
revision also checks a successful real-daemon CLI restart. It requires the
expected guest kernel, passing conformance/scenario/coverage markers, no
LLVM profile errors and nonempty exported profiles. Test assertions and
convergence deadlines are unchanged.

A full guest passes 59 ignored library tests, 24 Linux tests, five review
tests, 82 ordinary binary tests, three filesystem cases, both signal
task-limit cases, all 37 process tests, all 27 normal scenarios and the
buffer-force case. That passing revision is retained in
normal-resolute-writable-profiles/, including its helper source.

The earlier full run fails one process test: LLVM cannot mmap and merge
profile files written directly through 9p. COVERAGE_GUEST_RESULT is 1;
none of its profiles is imported. The next attempt writes locally but was
cancelled after review found that UID-dropped fixtures also need directory
write access. Its profiles are excluded too.

The corrected helper writes into a guest-local directory with mode 1777,
then copies profiles through 9p at the end. Empty artifact logs and relative
paths are rejected before a sentinel Docker executable can run. Those
controls now run in compiler calibration. The repeated-guard fixture also
checks two generic executable copies. The common gates, extended calibration,
Actionlint and offline Zizmor checks pass.

The focused CLI fixture starts a real daemon with an empty configuration.
A shell init owns its PID file. The CLI must return 0, the same daemon must
confirm re-exec, and ordered shutdown must return 0. Three GNU and three
stable musl repetitions pass. Removing the CLI invocation makes the fixture
fail before any re-exec confirmation. The corrected control records exit 143
and successful cleanup. Its initial driver assumed GNU timeout's exit 124;
that driver failure is retained. The corrected check requires failure,
readiness and cleanup, and forbids a re-exec or success marker.

The [fresh CI rehearsal](../coverage-ci-rehearsal-20261103/README.md) qualifies
the integrated guest revision. Its first guest was cancelled after metadata
was edited during execution; none of those profiles is imported. The resumed
guest uses the fixed integrated-helper-source.txt and restart-cli-source.txt
revisions. The complete local rehearsal passes 8,444/8,444 production source
lines and 1,838/1,838 condition outcomes, checker exit 0. The first GitHub
execution remains pending.

