# Merged-source coverage checker

This verification tool implements the maintainer's P4 measurement decision.
It adds no daemon dependency. Its separate lockfile pins the JSON decoder.

After building all instrumented executables from unchanged sources, retain
a full LLVM JSON export and capture its inventory:

```sh
cargo build --locked --manifest-path tools/coverage/Cargo.toml
tools/coverage/target/debug/phase6-coverage snapshot "$PWD" target/coverage-sources.json target/coverage-initial.json
```

Collect further profiles without editing the sources or rebuilding a different
configuration. Export the combined profiles and check them:

```sh
tools/coverage/target/debug/phase6-coverage check "$PWD" target/coverage-sources.json target/coverage-combined.json
```

Exit 0 means complete merged source coverage; 1 means coverage is missing;
2 means invalid input, changed sources/mappings or an unsupported format.
The snapshot records every Rust source file under `src/` by Git blob ID
and the exported production file/function mappings without execution counts.
It detects changed contents, missing files/functions and changed source spans.
Capture it against a known, unchanged build; LLVM's JSON does not itself
identify the source contents used to build an executable. The checker cannot
repair mixed profiles or establish their provenance.

Line counts follow LLVM's `LineCoverageStats`: the wrapped count and
non-gap region entries determine a mapped line's count. A positive merged
count covers that source line. Each condition keeps its function's source
owner, exact span and occurrence within that span. This preserves repeated
match guards that LLVM maps to the same coordinates. Counts merge only
across matching conditions; each true and false outcome must execute.

The supported input is LLVM JSON 3.1.0 with one combined mapping, single-file
functions, ordinary code/branch regions and no macro expansions or MC/DC.
Different nonempty branch layouts at one owner fail. Completely omitted
branches in unused executable copies are allowed. JSON omits LLVM's folding
flags, so the checker reconciles its executable outcome denominator against
LLVM's per-file summary and rejects a discrepancy, including partial folding
it cannot identify safely. These are supported-format limits, not exclusions.

Retain the full JSON export for per-instantiation diagnostics and the raw LLVM
summary beside the merged report. No production exclusion is added here.
Compiler instrumentation determines the existing exclusions.

`test-ci-gates.sh` runs formatting, Clippy and the checker's eight tests on
GNU and musl. After installing the pinned nightly and LLVM tools,
`sh tools/coverage/calibrate.sh RECORD` compiles a real fixture, checks
complementary generic copies against the raw LLVM report, and requires missing
arms, repeated-guard misses and changed sources to fail. CI runs this
calibration before generating its existing coverage upload. The full production
100% CI job remains a separate, unfinished Phase 6 requirement.
