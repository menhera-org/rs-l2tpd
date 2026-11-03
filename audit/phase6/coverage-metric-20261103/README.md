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

Signed `db7c1d2` implements the checker in `tools/coverage`. Eight tests
pass on GNU and musl; Rust 1.89 checks and the compiler-generated
calibration pass. The calibration requires complementary copies to cover
both source arms while missing-arm, repeated-guard and changed-source
controls fail. CI's Build and check job passes with that calibration.
The production report still exits 1 with six missing condition outcomes.
Its post-collection inventory does not establish a before-build snapshot.
The full production 100% CI job and Phase 6 remain unfinished.
