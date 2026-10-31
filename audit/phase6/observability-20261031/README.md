# Configuration diagnostics retain known identifiers

The O4 process regression reproduces missing identifiers in diagnostics for
entries omitted from the accepted configuration. The binary previously looked
up IDs in that accepted configuration: a left-out entry had no record to query,
session messages included only `session_id`, and unknown-key messages included
neither ID. [before.log](before.log) fails on a valid tunnel ID with an invalid
bind-interface name: the diagnostic names the entry and field but loses ID 10.

## Fix and assertions

Conversion now retains valid identifiers from the merged input in each
`Problem`. Both its human-readable display and strict-conversion error include
them. Session diagnostics include their tunnel's known ID and their session ID;
an absent or invalid identifier is not invented. Unknown-key problems within
tunnel/session tables receive the same context. The metadata is numeric only;
cookie values are still redacted. Its temporary lookup maps are bounded by the
current input and are released after conversion, not retained across events.

The binary now logs the shared `Problem` display directly. Startup, check and
reload reporting no longer reconstruct context from accepted entries, and the
library's diagnostic contains the same identifiers. No public signature or
dependency changes. Four existing exact-message assertions now require the
identifiers rather than the old incomplete text; the initial run before those
expectation updates remains in [after-first.log](after-first.log).

`configuration_diagnostics_keep_known_identifiers_for_omitted_entries` in
[process.rs](../../../tests/process.rs) covers nine check-mode inputs:
left-out tunnel, corrected session, left-out session with an invalid cookie,
unknown tunnel/session keys, missing tunnel ID, invalid tunnel/session IDs,
and an unrelated host key. Each requires one diagnostic, the name and field,
exactly the known ID fields, cookie redaction and no PID-file side effect.

`completion_report_counts` in
[completion.rs](../../../tests/rules/completion.rs) now also requires the exact
tunnel/session label on all creation refusals: configuration name, tunnel ID
and session ID where relevant. It retains the existing 16 errno/creation-kind
severity, silent-retry and recovery assertions. Both declarations cite O4.

[focused.log](focused.log) passes those two cases. [after.log](after.log)
passes the ordinary library/process suites after the formatter update and
before the final expanded input table.

| Final record | Result |
|---|---|
| [ci-gates.log](ci-gates.log) | Shared formatting, ShellCheck, warning-denied Clippy/docs, feature builds, native/musl ordinary suites and four strict source-link cases pass |
| [fake-ten.log](fake-ten.log) | Each of ten seeds passes 92 ordinary library cases (11 live ignored), 75 rule cases, 25 service cases and nine ordinary process cases (18 live ignored) |
| [live.log](live.log) | All 27 process cases pass in the privileged musl container |
| [Full host run](../scenarios-20261031T123212Z-3860569/run.log) | All 25 scenarios pass in 163.38 seconds; controller.log retains `SCENARIO_RESULT=0` |

## Commands and remaining scope

```sh
cargo test --locked --all-features --test process configuration_diagnostics_keep_known_identifiers -- --nocapture
cargo test --locked --all-features --test rules completion_report_counts -- --nocapture
./test-ci-gates.sh
# Each TEST_SEED=1..10:
cargo test --locked --all-features --lib --test rules --test service --test process -- --nocapture
RULEMAP_STRICT=1 cargo test --locked --all-features --test rulemap -- --nocapture
cargo test --locked --all-features --target x86_64-unknown-linux-musl --test process --no-run
# Disposable privileged Docker with --network none and a read-only checkout:
process --include-ignored --test-threads=1 --nocapture
tests/docker/run.sh scenarios
```

The static live artifacts use `x86_64-unknown-linux-musl` on
`6.8.0-147-generic`; ordinary seeded suites use the native target. Every Cargo
command uses `--locked --all-features` except feature-specific shared CI checks.
The [strict rule map](rulemap.log) remains red, exit 101: 343 total /
333 active / 315 cited / 18 missing. O4 gains executable traceability, not
global completion. Ten-seed ranges in the planner overlap.

`revision` and `source.patch` identify the final source; source-identity.log
checks that snapshot. docs-checks.log checks local Markdown file targets and
whitespace, excluding web URLs and anchors. Cargo build durations are omitted.

This package does not refresh the other four required kernels, Incus or root
systemd profiles. Complete clause/resource/event-cost proof, merged coverage,
remaining citations, final matrix/manager runs and strict CI remain open.

## Separate requested CodeQL configuration

The maintainer requested disabling `rust/cleartext-logging` entirely through
CodeQL configuration because it mistakes public identifiers for credentials.
Commits `f42e841` and `bcd283b` add the exact query exclusion and wire it into
an advanced Rust/Actions workflow with the extended suite and pinned actions.
The original ordinary CI workflow is unchanged.

The default-setup custom-property path was attempted first; creating the
required organization property was denied for missing `admin:org`. No property
was created or set. Repository-level advanced setup used the existing available
permissions instead; default setup is now `not-configured` so it does not
override the custom workflow. No organization-wide scanning change was made.

[The GitHub run](https://github.com/menhera-org/rs-l2tpd/actions/runs/41201228279)
at `bcd283b` succeeds and uploads results. Its log explicitly loads
`.github/codeql-config.yml`, selects `security-extended`, and lists the
`rust/cleartext-logging` exclusion. An API check after that run finds no open
alerts for that query. This is separate from the O4 product fix and does not
relax cookie-redaction tests or any Phase 6 gate.
The relevant [run-log excerpt](codeql-excerpt.log) and
[open-alert API result](codeql-alerts.json) are retained.
