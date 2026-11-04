# Optional kernel qualification

All six maintained profiles executed after signed 3dee493 was synced.
Production source and all executable hashes match the c599b1f qualification.
Initial/final source patches are empty; assertions and exclusions are unchanged.
The aggregate optional result is failure.

| Target | Release | Normal | Clock/pause |
|---|---|---|---|
| Debian 13 | 6.12.115+deb13.1-amd64 (6.12.115-2) | Fail: 26/27 scenarios, 37 process cases pass; H17 nlmon header rejection | Pass |
| Rocky 9 | 5.14.0-687.61.1.el9_8.x86_64 | Pass: 27 scenarios, 37 process cases | Pass |
| Rocky 10 | 6.12.0-211.72.1.el10_2.x86_64 | Pass: 27 scenarios, 37 process cases | Pass |

All normal guests pass 31 private live cases, 24 Linux cases, five review
cases, ordinary CLI cases and selected refusal cases. All clock guests pass
retry/refresh bounds, wall-clock steps and QMP pause/resume assertions.

Debian H17 exchanges frames through 300 sessions and verifies an identical
reload before the fixture rejects a packet header during unrelated link
events. A scoped H17 diagnostic passes all three expansion/shrink cycles.
Notification diagnostics pass 20 rounds each with one and two subscribers:
4,000 and 8,000 packets, without loss. They do not erase the full-run failure;
its cause remains unresolved and Debian 13 remains unqualified.
No malformed packet, assertion or loss check was waived.

Diagnostics use disposable copies of the maintained capture helper with
richer errors and the unchanged scale case, or 100 veth pairs per round
with ip monitor link subscribers and no daemons. The inherited boot banner
still says scale; the selected test and fixture source give the actual scope.
diagnostics/fixtures.txt preserves those disposable sources as historical
evidence, not current gating scripts. diagnostics/executables.log records
the actual replacement binaries; the base build manifest predates that
replacement and is not used to identify diagnostic executables.

Reproduce the maintained matrix with the recipe in tests/kernel/README.md:
fetch debian13, rocky9 and rocky10, then run tests/kernel/run-optional.sh.
The fixed selections and maintained runner are in signed 3dee493.
Package metadata/digests and extractor identities are retained here.
Commands, image/configuration identities and full results accompany each
guest. CHECKOUT replaces the local checkout path; download progress and
local build durations are omitted. No kernel.org HTML is retained.
Kernel-only results do not qualify distribution userspace or packages;
the complete optional source audit remains separate.
Debian 12 is outside the support target, with best-effort degradation.
