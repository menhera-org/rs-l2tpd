# Earlier merged coverage, including inline test code

The later approved production-code scope is measured in the separate
[production baseline](../coverage-production-20261031/README.md). This record
retains its original denominator and results. Its collection helpers accept
`PHASE6_COVERAGE_RECORD` and `CARGO_LLVM_COV_TARGET_DIR` overrides for new
records; their default paths and commands below remain unchanged.

Rust source: `0f5292e`, all features, `x86_64-unknown-linux-gnu`,
cargo-llvm-cov 0.9.1 and nightly-2026-10-28 branch instrumentation.
The [artifact hashes](artifacts.log), [image IDs](images.log), `revision` and
`source.patch` identify this run. Shipped and ordinary kernel-matrix builds
remain musl. All instrumented suites below pass.

[merged.log](merged.log) reports **92.26% lines (9,586/10,390) and 78.16%
branches (1,460/1,868)**. There are 804 missing lines and 408 missing branches.
No source or test helper is excluded. This does not pass the 100% gate.

## Executed profiles

| Profile | Result | Evidence |
|---|---|---|
| Native library | 92 ordinary cases pass; 11 live cases run separately | [native.log](native.log) |
| Native binary | 38 ordinary cases pass; four live cases run separately | [native.log](native.log) |
| Fake conformance, rules and services | 1, 75 and 25 pass | [native.log](native.log) |
| Native process | Nine ordinary cases pass; live cases run separately | [native.log](native.log) |
| Native maps | Three rule-map and four source-link cases pass, lenient flags | [native.log](native.log) |
| Native scenario parser | One case passes; live scenarios run separately | [native.log](native.log) |
| Container library/kernel/review | 11, 19 and five pass | [live.log](live.log) |
| Container binary permissions | Three explicit parent cases pass | [live.log](live.log) |
| Container process | All 27 pass | [live.log](live.log) |
| Container host scenarios | All 26 pass in 157.73 seconds | [live.log](live.log) |
| Real user manager | One actual FD-store/processing/address-family case passes | [manager.log](manager.log) |
| Unprivileged Incus buffer | One case passes and requires `FORCE_RESULT=EPERM` | [incus-buffer.log](incus-buffer.log) |
| Unprivileged Incus system-manager scenario | One case passes in 19.85 seconds; seven daemon-process profiles exported | [incus.log](incus.log), [incus-scenario.log](incus-scenario.log) |

[counts.log](counts.log) retains the suite result lines and commands. Nested
child results are not added to parent counts. The live kernel is
`6.8.0-147-generic`. All Docker invocations use `--network none`; the Incus
container inherits no profiles or host network interface and is deleted on
success or failure. The completed container suite prints
`LIVE_COVERAGE_RESULT=0`; the final Incus run prints
`INCUS_DAEMON_PROFILES=7` and `INCUS_COVERAGE_RESULT=0`.

## Reproduction

From the repository root, with the coverage tool on PATH:

```sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-current-20261031"
cargo +nightly llvm-cov --color never --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
docker build --network none -f audit/phase6/coverage-current-20261031/Dockerfile -t rs-l2tpd-coverage:phase6 audit/phase6/coverage-current-20261031
sh audit/phase6/coverage-current-20261031/run-live.sh
sh audit/phase6/coverage-current-20261031/run-incus.sh
cargo +nightly llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```

The real user-manager command and its properties are in manager.log.
The prepared review image and archived interoperability peer are reused.
Only the profile directory is writable in ordinary coverage containers;
the checkout stays read-only. Export makes restrictive-umask profiles
readable before merging them.
The successful run precedes only a missing-artifact guard correction in
`run-live.sh`: an explicit `if` now stops before Docker when Cargo output
has no executable. [empty-artifact.log](empty-artifact.log) verifies that
failure path with an empty build log and a Docker sentinel.

## Incus profile transport

The complete existing Incus scenario runs against the instrumented GNU
binary. Its fixture checks capabilities, the tunable, actual descriptor
storage, restart/adoption, re-exec, networkd, both MAC-policy orderings and
cleanup. The source fixture is unchanged.

A coverage-only systemd drop-in writes profiles into the unit's existing
writable runtime directory and sets `RuntimeDirectoryPreserve=yes` so that
profiles survive stop for export. It adds no writable path or capability.
This profile transport is separate from the unmodified musl Incus gate and
the root-unit sandbox acceptance profile.

The first run passed the fixture but systemd expanded LLVM's `%p` and `%m`
in the profile filename. Its log and diagnostic merged report are retained
with `before-specifier-correction` names. The helper now uses `%%p`/`%%m`
and requires at least two distinct per-process daemon profiles. Old Incus
profiles were removed before the final collection; seven daemon profiles
were exported, along with the buffer and fixture/installer profiles. Each
single-file pull and container deletion must succeed.

The native/container host-only report was 91.87% lines / 78.16% branches.
The final report includes the manager and corrected Incus collection.
It still lacks boot-only and full root-systemd sandbox profiles. Reachable
missing paths throughout `src/` and compound assertions in inline tests
also remain to be covered or simplified without weakening their checks.
For example, the two missing branches at
[deadlines.rs](../../../src/reconciler/deadlines.rs) line 70 are the false
sides of a test's compound empty-index assertion. The gate still requires
100% and permits exclusions only for justified unreachable Linux branches;
none is claimed here.
