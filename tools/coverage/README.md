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
and the exported production file/function mappings and mapped source-line
inventory without execution counts (inventory format 2). Git clean filters
are disabled so that the fingerprints identify the actual source bytes.
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

`test-ci-gates.sh` runs formatting, Clippy and the checker's ten tests on
GNU and musl. After installing the pinned nightly and LLVM tools,
`sh tools/coverage/calibrate.sh RECORD` compiles a real fixture, checks
complementary generic copies against the raw LLVM report, and requires missing
arms, repeated-guard misses and changed sources to fail. CI runs this
calibration before generating its existing coverage upload. Calibration also
requires missing artifact logs and relative guest paths to fail before Docker.

The separate production-coverage workflow job collects ten ordinary suites,
a full GNU instrumented guest and thread/fork refusal profiles, then requires
both merged totals to reach 100%. A fresh local rehearsal passes 8,444/8,444
source lines and 1,838/1,838 condition outcomes. Its first GitHub execution
remains pending; the workflow's presence alone does not pass P4.


`sh tools/coverage/run-guest.sh NATIVE_LOG KERNEL_ROOT RECORD PROFILES` requires
absolute paths, actual executable artifacts and fresh output directories.
It reuses the normal matrix init unchanged, adding buffer-force and successful
CLI restart checks. LLVM writes guest-local profiles because its mmap-based
merge cannot operate through 9p; the guest copies them out after the suites.
The caller imports profiles only after all result markers pass and no LLVM
profile error appears. `restart-cli.sh` starts a real daemon, requires the CLI
to return 0, observes re-exec confirmation and requires clean shutdown. Run it
only in a disposable test container or guest.
