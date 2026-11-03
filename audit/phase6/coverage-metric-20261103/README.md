# P4 merged-source coverage decision

The maintainer approved this definition on 2026-11-03: “Use merged source
coverage.” The reviewed `proposed.patch` is applied to `docs/phase6.md`.

The [calibrated LLVM reproducer](../remaining-paths-20261103/coverage-measurement.md)
shows complementary instantiations covering both source arms while the
raw summary retains the maximum covered count from either copy.

P4 now requires merged production source lines and each condition's true
and false outcomes at its exact source span across executable copies and
generic instantiations. Different spans remain separate. LLVM determines
which outcomes are executable. The existing production exclusion policy
is unchanged. Unsupported schemas and inconsistent mappings must fail.
Raw LLVM summaries and per-instantiation diagnostics remain required.

The definition is approved; the checker and its calibration are still in
progress. This decision does not establish 100% coverage or pass Phase 6.
