# Refused monitor filters and descriptor exhaustion

This package supplies live R6/R9 cases and corrects two creation-reporting
defects. It adds no dependency and changes no retry interval or public API.

## R6: the monitor works without its classic filter

The new scenario refuses only
`setsockopt(SOL_SOCKET, SO_ATTACH_FILTER)` in the daemon child with a
seccomp filter. It requires one warning, readiness, real bidirectional
session traffic, survival of 100 unrelated dummy-device create/delete
cycles, disconnection after source removal and recovery after restoring
the source. The session index is unchanged; a reload emits no second
filter warning. The unrestricted peer must emit no such warning.

The warning now includes the kernel errno name, `EPERM`, as O6 requires.
The previous warning contained only the generic OS description. This
logging follow-up changes neither filter attachment nor fallback policy.
The existing fragmentation-option refusals use the same extracted test
helper; each still denies one socket option and permits other syscalls.
The fixture retains its existing x86_64/aarch64 ABI checks.

The first R6 fixture used a nonexistent expected disconnection message
and timed out after the actual `ENETUNREACH` report. It also planned a
different restored address without updating the peer. The final fixture
waits for the actual pending-peer report and restores the original source.
[That original run](../scenarios-20261031T111538Z-3759543/run.log) remains a
fixture failure, not evidence of a broken fallback.

## R9: real EMFILE, partial progress and recovery

The new scenario starts one daemon with `RLIMIT_NOFILE=32:256` and 40
configured tunnels. The first tunnel also has a session and an actual
peer. Real kernel `EMFILE` must occur, readiness must remain withheld
over a 2.2-second negative window, and some tunnels must already exist.
The created session carries real frames while other entries are missing.
Every missing tunnel has one warning; repeated retries add no reports
at the default log level. No error-level message is permitted.

`prlimit` raises only this child's soft limit to its existing hard limit
of 256. Without a reload, the daemon reaches readiness and all 40 tunnels
exist. The original session retains its index and still carries frames.
Both daemons then shut down successfully with no tunnels or sessions left.
Host process limits, networking and kernel settings are not changed.

[The original live run](../scenarios-20261031T111538Z-3759543/run.log)
fails because creation reports `EMFILE` at error level. Tunnel creation
previously classified all ordinary failures as host defects; session
creation already distinguished support/privilege failures from transient
ones. Both now use one reporting helper: `EPERM`, `EACCES`,
`EPROTONOSUPPORT` and `EOPNOTSUPP` are errors; transient creation failures
are warnings. Existing episode keys, promotion to error, recovery reports
and readiness/retry behavior are preserved.

## Kernel EAGAIN versus the internal tunable wait

The expanded reporting regression covers tunnel registration and session
creation separately, with four host-defect errnos and `EAGAIN`, `ENOMEM`,
`ENOBUFS`, `EMFILE` as transient errors. Each injects three failures,
asserts one report at the expected level and none at the other, withholds
readiness through two ticks, then recovers on the next tick without
another failure report.

[The first executable regression](severity-before.log) fails because a
kernel `EAGAIN` produces no warning. The general `WouldBlock` arm had
mistaken it for the internal tunable-handshake wait. Merely sharing the
severity helper does not fix this:
[the intermediate failure](severity-before-wouldblock-fix.log) is retained.
That arm now applies only while a tunable handshake is actually pending.
[The final focused case](severity-after.log) passes all 16 combinations
and the existing escalation, episode and recovery assertions.
An initial mis-scoped test edit failed compilation; it is separately
retained in severity-fixture-compile.log and ran no tests.

## Executions and traceability

All Cargo checks use `--locked --all-features` unless the common gate
explicitly checks another feature set. Scenario artifacts use
`x86_64-unknown-linux-musl` and run in disposable privileged containers
with `--network none` on `6.8.0-147-generic`.

Commands:

```sh
cargo test --locked --all-features --test rules completion_report_counts -- --nocapture
tests/docker/run.sh scenarios capabilities::
tests/docker/run.sh scenarios
./test-ci-gates.sh
SRCLINK_STRICT=1 cargo test --locked --all-features --test srclink -- --nocapture
RULEMAP_STRICT=1 cargo test --locked --all-features --test rulemap -- --nocapture
```

| Newly cited rule | Test declaration | Assertion |
|---|---|---|
| R6 | [capabilities.rs](../../../tests/scenarios/capabilities.rs), `refused_monitor_filter_warns_once_and_address_events_still_reconnect` | Actual filter refusal, one warning, unfiltered source recovery and real frames |
| A18 | Same declaration; existing filtered-monitor/BPF cases remain separate | Correctness survives filter refusal and unrelated link churn |
| R9 | [capabilities.rs](../../../tests/scenarios/capabilities.rs), `descriptor_exhaustion_is_transient_and_recovers_after_the_limit_is_raised`; [completion.rs](../../../tests/rules/completion.rs), `completion_report_counts` | Real EMFILE, partial progress, silent retries, readiness withholding, limit increase and recovery; exact virtual-tick severity cases |

[The focused host run](../scenarios-20261031T111834Z-3765479/run.log)
passes all six capability/filter/limit cases in 21.49 seconds.
[The first full host run](../scenarios-20261031T112040Z-3767432/run.log)
passes all 25 scenarios in 163.11 seconds. These runs precede only the
filter-warning errno-display follow-up and its strengthened assertion.
Their controller summaries are retained separately.
[The final-source full run](../scenarios-20261031T112604Z-3785795/run.log)
passes all 25 scenarios in 161.26 seconds, including the required EPERM
warning. final-controller.log retains its `SCENARIO_RESULT=0` marker.

`ci-gates.log` records the first successful common gate;
`ci-gates-final.log` repeats it after the errno-display follow-up.
The common gate includes formatting, ShellCheck, warning-denied Clippy,
feature builds, native/musl ordinary tests and warning-denied docs.
[Final strict source links](srclink-final.log) pass four cases.
[The strict rule map](rulemap.log) still fails honestly, exit 101:
343 total / 333 active / 278 cited / 55 missing. R6, R9 and A18 gain
declaration citations, not global proof closure.

[Ten seeded rule runs](rules-ten.log), `TEST_SEED=1..10`, each pass 74
cases after the creation-reporting fixes. The planner's 32-seed ranges
overlap. These repetitions precede the display-only monitor follow-up;
all rule/reconciler code is identical. This is scoped determinism evidence,
not permission to enable global strict flags.

`revision` and `source.patch` identify the first passing source;
`final-source.patch` includes the errno-display follow-up.
`source-identity.log` verifies the final snapshot. `docs-checks.log` checks
local Markdown file targets and diff whitespace, excluding URLs/anchors.
Cargo build durations are omitted from archived logs.

The new cases have not run on the other four required kernels or in
Incus. The full latest-target matrix, remaining 55 citations, complete
event-cost/history proofs, coverage, final manager profiles and strict
CI remain open. No Phase 6 gate is declared globally complete here.
