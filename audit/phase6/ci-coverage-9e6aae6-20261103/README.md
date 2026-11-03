# Production coverage for the final Phase 6 source

[CI run 41607623091](https://github.com/menhera-org/rs-l2tpd/actions/runs/41607623091)
passes all three jobs on signed commit
`9e6aae63ec43166941a14fed8883547ead7dc4f0`: Build and check, Live
conformance, and Production coverage (100%).
[CodeQL run 41607623178](https://github.com/menhera-org/rs-l2tpd/actions/runs/41607623178)
also passes on the same commit.

The required coverage job reports **8,486/8,486 merged production source
lines and 1,852/1,852 condition outcomes**, with
`MERGED_SOURCE_GATE=PASS`. The retained raw LLVM summary reports
8,699/8,751 lines (99.41%) and 1,819/1,852 outcomes (98.22%). The raw
summary counts compiler mappings; the gate merges exact source spans and
condition outcomes across executable copies. Both reports are retained.

The downloaded artifact contains the exact revision, empty initial and final
source patches, raw and merged reports, the compressed LLVM export, the
compressed source/mapping inventory, the instrumented guest log and the
workflow result. No production exclusion was added.

This run qualifies the final production source after the S8 lifetime-capture
fix. The earlier ten-seed CI qualification remains the determinism evidence
used before the strict gates were enabled; this record is one exact-source CI
execution and does not describe it as ten executions of this revision.
