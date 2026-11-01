# Deletion recovery, stale completions and parser guards

Four test-only edits qualify these existing behaviors:

| Contract | Controlled input | Required result |
|---|---|---|
| T9, O3, O4 | The fake owner socket is closed and settled, leaving its configured tunnel absent; three deletion announcements or three L2TP losses follow | One error identifies the tunnel and unsupported outside deletion; no replacement operation occurs |
| E20, S27 | An operator-deleted fake session is settled before L2TP loss is delivered | Recovery creates one replacement session, keeps its parent socket, and a second loss preserves the replacement |
| L12 | A completion has the wrong incarnation, or the matching incarnation arrives exactly at the five-second deadline before the timer event | No tunnel registers early; the existing valid-completion and timeout-fallback assertions still pass |
| K7, A5 | The address parser receives foreign families with an otherwise IPv4-sized attribute | It refuses them instead of interpreting the attribute as IPv4; existing dump filtering and valid IPv4/IPv6 cases still pass |
| L13, P14, G20 | A real pending withdrawal is handed to the helper with forwarding disabled | The no-store answer completes cleanup immediately and sends no host event |

The last case announces nonzero capacity solely to obtain a pending withdrawal
before exercising the disabled-forwarding helper. It is not a live manager
processing-barrier result. The T9 fixture establishes policy after confirmed
absence by closing the fake owner; it is not a live operator-delete experiment.
Parser inputs and fake-clock completions establish no malformed kernel reply
or wall-clock scheduling bound.

Six independent controls fail at the intended assertions: wrong deletion-report
severity, omitted loss recovery, omitted incarnation check, omitted deadline
check, foreign-family IPv4 interpretation, and an unprocessed no-store
withdrawal. The controls run against the final formatted tests and are never
merged into coverage.

Ten native and instrumented model/rule/service/startup repetitions, three
musl model runs, the full native suite, common gates, Rust 1.89 and additional
ARM64/RISC-V64/PowerPC64LE musl compile checks pass. Production code is
unchanged from `revision`; the before/after source patches agree.

Coverage reaches **8,500/8,687 lines (97.85%) and 1,702/1,852 branches
(91.90%)**, leaving 187 lines and 150 branches. All 4,327 production mappings
remain identical. No production exclusion, profile mismatch or saturated
region is present. Earlier production implementations remain excluded
from the collector.

`commands.sh` records positive commands; `fixture-notes.md` records corrections
made before qualification. Live kernel, Incus, manager and matrix results
retain their separately recorded source scopes. Complete clause proof and
the 100% coverage gate remain open.
