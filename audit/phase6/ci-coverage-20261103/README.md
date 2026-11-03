# Production coverage in GitHub CI

[CI run 41582370103](https://github.com/menhera-org/rs-l2tpd/actions/runs/41582370103)
passes all three jobs on signed e29c6f3, attempt 1:
Build and check, Live conformance, and Production coverage (100%).
[CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41582370032)
also passes.

The production job reports **8,444/8,444 source lines and 1,838/1,838
condition outcomes**, with MERGED_SOURCE_GATE=PASS. Its required check step
succeeds. The retained raw LLVM summary is **8,657/8,709 lines (99.40%) and
1,805/1,838 outcomes (98.20%)**. No production exclusion is added.

The downloaded artifact's 51 source fingerprints match the independent
local rehearsal exactly. Its revision is e29c6f3 and its initial/final
source patches are identical and empty. The full compressed LLVM export,
source/mapping inventory, raw and merged reports, job/step results and
guest summary are retained here. Counts and paths in these artifacts are
unchanged; no path relocation or counter rewriting was used.

The job collects ten ordinary suites with different seeds, the full GNU
instrumented normal guest, buffer-force and actual CLI restart checks,
and both thread and both fork refusal fixtures. The guest summary records
the observed kernel and actual suite results. This is the first completed
run of the new job, not ten CI repetitions of this revision.

P4's local measurement and separate CI enforcement acceptance pass.
The complete required-kernel matrix and clause/resource/event-cost proof
remain separate work. This record does not complete Phase 6.
