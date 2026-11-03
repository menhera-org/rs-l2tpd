# Local rehearsal of the separate coverage CI job

The fresh collection passes **8,444/8,444 production source lines and
1,838/1,838 condition outcomes**, checker exit **0**. No production
exclusion is added. Initial and final source patches match. The
source/mapping inventory was captured after the first ordinary collection,
before further profiles. Compressed full exports and digests are retained.

This uses the new workflow's profile scopes: ten ordinary collections
(seeds 1 through 10), the integrated instrumented Ubuntu 7.0.0-42 normal
guest with buffer-force and real CLI restart checks, and the four
thread/fork refusal cases. No profiles from the preceding successful
collector or other live scopes are imported.

The guest passes 59 ignored library tests, 24 Linux tests, five review
tests, 82 ordinary binary tests, three filesystem cases, two signal
task-limit cases, all 37 process tests and all 27 normal scenarios.
The extra checks require buffer-force completion, successful real-daemon
CLI restart, re-exec confirmation and clean shutdown. No LLVM profile
error is recorded.

The first guest was cancelled after collector metadata was edited during
execution; none of those profiles is imported. The resume command reuses
the completed native collections and starts the guest again with fresh
output directories and a fixed helper revision. Both command files and
the cancelled record remain available.

The common gates, extended calibration and Actionlint pass separately in
the collector qualification record. This qualifies the local collection
and workflow recipe. Its first GitHub execution, current-source full kernel
matrix and complete clause/resource/event-cost proof remain unfinished.
