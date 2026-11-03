# Coverage summaries and duplicate functions

The P4 gate is unchanged: the raw report must reach 100% of production
lines and branch outcomes. This investigation adds no exclusion and
does not establish that gate.

The starting snapshot's capability reporter illustrates a difference
between the merged source display and the summary. Its test-binary copy
executes the capget error arm but misses the successful capability check.
The daemon copy executes that check but misses the error arm. The merged
source display gives every counted segment a positive count; the file
summary still reports 34/35 lines. `baseline-caps.json` retains the
exported records. The new privileged-unit and daemon-failure cases cover
both copies sufficiently to remove that particular summary miss.

LLVM's [summary merge methods](https://github.com/llvm/llvm-project/blob/main/llvm/tools/llvm-cov/CoverageSummaryInfo.h)
take the maximum covered and total counts across instantiations.
[Instantiation-group aggregation](https://github.com/llvm/llvm-project/blob/main/llvm/tools/llvm-cov/CoverageSummaryInfo.cpp)
uses those methods. Thus complementary sets of executed lines can leave
the summary below the coverage shown by merged source coordinates.
Those links describe the reference implementation; the fixture below
independently checks the installed LLVM 23.1.4 tool.

`coverage-summary-fixture.rs` calls two generic instantiations. In the
`complementary` run, one takes only the true arm and the other only the
false arm. Each reports 80% lines and 50% branch outcomes, although the
combined source view executes both arms. In the `both` control, each
instantiation takes both arms and each reports 100% for both metrics.
The fixture's own main function has separate uncovered paths; the claim
concerns `choose`, not the whole fixture.

`commands-summary-fixture.txt` records compilation, execution and export.
The two JSON exports, summary logs and detailed text views retain the
evidence. No new reporting tool or dependency is introduced. These
artifacts diagnose aggregation; they do not replace P4's raw summary.

The final project report still has four source positions in its
`--show-missing-lines` section, while its summary reports 57 missed
lines. The difference must remain explicit. It neither proves those
four paths are the only remaining behavioral cases nor authorizes
silently substituting a different coverage metric.
