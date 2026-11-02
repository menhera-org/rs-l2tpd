# Combined coverage batch

This batch extends signed `651860a` with tests and test-only helpers.
Production function bodies are unchanged. `source.patch` records the
combined shipping changes, including the preceding resolver/host cases.

The new cases check:

- Installer refusal without root; missing `systemctl`; failed spawn and
  nonzero status at daemon-reload and enable; no enable after reload
  failure; no restart at any stage; the empty directory-parent boundary.
- Private descriptor-table unshare, duplication and relocation failures;
  each returns EIO and preserves the caller's descriptor and flags.
- Daemon stdin redirection failure before kernel startup. The existing
  fault table now checks nine setup failures and preserves the PID file.
- Wrong, expired and completed tunable acknowledgements; an explicit
  reload during an active conflict; an already absent unmatched session.
- Store refusals that preserve inherited/retiring authority; repeated
  submission of the same socket with spare capacity and a drained queue.
- ENODEV between proof/dump and deletion, both by identifiers and by name.
  The injected fake refusal does not itself delete the fixture session.
- Provisional socket cleanup after an option query or link lookup failure,
  and when bindv6only changes after the scratch check; subsequent recovery.

The first native instrumented run executes all ordinary suites. Nine more
instrumented native runs exercise the models, binary, fake kernel, rules,
service and startup suites with different TEST_SEED values. These are the
ten native model repetitions; a redundant second ten-run collection on
stable is omitted. Three stable musl model/binary repetitions pass.
GNU and musl each pass three networkless disposable-container process
runs; three further GNU instrumented process runs contribute live profiles.
Common CI checks, Rust 1.89 and aarch64, riscv64gc and powerpc64le musl
compile checks pass. Non-x86 runtime behavior is not established here.

Three failure controls fail at runtime at their intended assertions:
removing the duplicate-store guard, accepting an expired tunable completion
and matching the wrong syscall argument. The final duplicate-store test
drains the first request and leaves spare capacity so neither queue
coalescing nor the capacity guard can hide a second submission. Its
strengthened form passes instrumented collection and final common gates.
The controls run in the isolated candidate checkout and are restored.
Their source patches retain the exact changes.

The merged report covers **8,543/8,687 lines (98.34%)** and
**1,725/1,852 branch outcomes (93.14%)**. The combined November 2 work adds
29 covered lines and 21 branch outcomes to the preceding 98.01%/92.01%
report. This larger extension contributes 25 lines and 19 outcomes after
the resolver/host package's four lines and two outcomes. All 4,327 old
production mappings remain unchanged; four test-induced instantiations
were added. No production exclusion was added. The installer now has
complete line and branch coverage. Remaining gaps are listed in
`coverage.log`; **144 lines and 127 branch outcomes remain required**.

An isolated trace/export confirmed that the unshare refusal reaches its
intended branch. An initial concern about its collection was a mistaken
reading of the line numbers: the uncovered line was the separate SIGPIPE
restoration hook. No compiler or collector defect is claimed.

The full required-kernel matrix retains its separate frozen source and
scope. K41's five-kernel positive/negative control is recorded separately.
This batch adds no new Incus or root-unit qualification, and does not
complete Phase 6's coverage, clause/history/resource/event-cost or CI gates.
