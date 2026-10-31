# Library requirements, ownership and runtime errors

This package adds requirement tests and fixes two demonstrated library defects.
It adds no dependency. Synchronous constructors retain ownership-preserving
`StartResult`; synchronous event preparation retains its caller-thread contract.

## Dropping an owner with a shared backend

[The failing service run](drop-before.log) leaves session 110 alive after
dropping its runtime: the custom kernel backend outlives the runtime, so merely
dropping the backend field does not close sockets. `Reconciler::drop` now closes
owned active and retiring sockets. It performs no ordered session deletion or
external store withdrawal. Explicit shutdown remains necessary to observe those
protocols, cleanup completion and errors, especially with external socket copies.

The [final service run](service-final.log) passes both active and retiring
variants. Assertions require exactly one socket close, no ordered delete
operations, no remaining owned objects and closed control admission. A second
service test gives two runtimes the same identifiers and shared backend: the
nonowner withholds readiness and cannot remove or replace the owner's objects.

The live counterpart creates a separate foreign tunnel/session, then drops an
active or retiring program-driven runtime. Both owned tunnel and session must
disappear; the foreign objects and interface index must remain unchanged.
The process SIGKILL test now requires session absence as well as tunnel absence.

## Missing Tokio returns an error

[The original context regression](context-before.log) catches an actual panic
from constructing a Tokio timer outside a runtime. The waiting future now checks
for context before constructing its timer and yields `ControlEvent::Failed` on
failure. Forwarding that event to `handle_event` returns its error. The event enum
was already non-exhaustive; the existing `next_event` return type stays intact.

The test first exercises reload and host-completion channel futures without
Tokio and forwards their queued events successfully. It then installs a future
cleanup deadline and polls once outside Tokio: the poll must not panic, and
forwarding the failure must return `Error::Other`. No wall-clock sleep is needed.
Channel-only futures need no Tokio executor. `next_event` synchronously prepares
injected kernel callbacks on the caller's thread and returns the asynchronous
wait. Constructors remain synchronous so failures immediately return adopted
descriptors. These exceptions preserve API usefulness rather than adding async
wrappers without work to await.

## Requirement assertions and citations

| Newly cited rule | Test declaration | Observable assertion |
|---|---|---|
| A2 | Existing blocking/Tokio service convergence and reload cases in [service.rs](../../../tests/service.rs) | Both service forms drive the common ownership/reconciliation contract |
| A21 | `event_wait_without_tokio_reports_an_error_and_channels_remain_usable` in [runtime/tests.rs](../../../src/runtime/tests.rs) | Program-driven events and channel completions remain usable; failed waiting returns an error |
| G9, R40 | `runtime_drop_closes_owned_sockets_without_ordered_session_deletion` in [service.rs](../../../tests/service.rs); live `library_runtime_drop_closes_active_and_retiring_tunnels_without_touching_foreign_ones` in [linux.rs](../../../tests/kernel/linux.rs); process crash cases | Active/retiring ownership closes without ordered deletion; foreign objects survive; SIGKILL removes an unstored tunnel and session |
| G14 | New runtime, service and live declarations below | Missing requirements, owner overlap and cleanup exercise the same library contract; this tag does not prove every G14 clause |
| R22 | `crash_without_store_closes_tunnel` in [process.rs](../../../tests/process.rs) | SIGKILL without a socket store leaves neither tunnel nor session |
| R37 | Constructor failure assertions in [service.rs](../../../tests/service.rs), the context test and live `library_constructors_reject_missing_tokio_and_preserve_adopted_descriptors` | Exact error class, preserved adopted names/descriptors, and successful blocking service without caller Tokio |
| R38 | Live `library_missing_net_admin_withholds_readiness_and_shutdown_still_succeeds`; fake logger-disabled case | Effective capability removal prevents tunnel creation/readiness, yet shutdown succeeds; injected refusal recovers |
| R39 | `a_dropped_source_removal_stays_stale_until_resync_is_forwarded` in [runtime/tests.rs](../../../src/runtime/tests.rs) | Deliberately omitted source removal stays stale until forwarded loss/resync disconnects it |
| R41 | `absent_log_sink_does_not_change_kernel_refusal_or_recovery` in [runtime/tests.rs](../../../src/runtime/tests.rs) | No global logger is installed; creation refusal withholds readiness and a later tick recovers |
| R42 | `overlapping_runtimes_conflict_and_the_nonowner_cannot_remove_the_owner` in [service.rs](../../../tests/service.rs) | Shared namespace/identifiers conflict; nonowner shutdown preserves the owner's socket and session index |

The capability fixture drops only its own test thread's effective NET_ADMIN.
A preexisting observer thread retains it to verify kernel object absence:
L2TP GET itself requires NET_ADMIN. The fixture does not change host capabilities,
networking or process limits. All live work runs in disposable privileged Docker
containers with `--network none` and a read-only checkout.

## Executions

Cargo commands use `--locked --all-features` except feature-specific checks in
the shared gate. Native ordinary runs use the default target; live artifacts
are `x86_64-unknown-linux-musl`. The live kernel is `6.8.0-147-generic`.

```sh
cargo test --locked --all-features --lib runtime::tests -- --nocapture
cargo test --locked --all-features --test service -- --nocapture
./test-ci-gates.sh
SRCLINK_STRICT=1 cargo test --locked --all-features --test srclink -- --nocapture
RULEMAP_STRICT=1 cargo test --locked --all-features --test rulemap -- --nocapture
# Each TEST_SEED=1..10:
cargo test --locked --all-features --lib --test rules --test service -- --nocapture
cargo test --locked --all-features --target x86_64-unknown-linux-musl --test kernel-linux --test process --no-run
# In the disposable container, using the built executables:
kernel-linux --ignored --test-threads=1 --nocapture
process --include-ignored --test-threads=1 --nocapture
tests/docker/run.sh scenarios
```

| Record | Result |
|---|---|
| [runtime-final.log](runtime-final.log) | 17 runtime cases pass; subsequent shared/seeded runs include the final channel-completion extension |
| [service-final.log](service-final.log) | 25 service cases pass, including active and retiring drop |
| [live.log](live.log) | Three new live library cases pass |
| [live-process.log](live-process.log) | All 19 kernel cases and 26 process cases pass |
| [Full host run](../scenarios-20261031T115842Z-3809147/run.log) | 25 scenarios pass in 161.19 seconds; controller.log retains `SCENARIO_RESULT=0` |
| [ci-gates.log](ci-gates.log) | Formatting, ShellCheck, warning-denied Clippy/docs, feature builds and native/musl ordinary tests pass |
| [fake-ten.log](fake-ten.log) | Ten seeds each pass 92 ordinary library cases (11 live ignored), 74 rule cases and 25 service cases |
| [srclink.log](srclink.log) | Four strict cases pass; 43 facts, 37 production citations, six classified facts, no uncited Linux functions |
| [rulemap.log](rulemap.log) | Strict gate remains red, exit 101: 343 total / 333 active / 289 cited / 44 missing |

The planner's 32-seed ranges overlap. These repetitions provide scoped
determinism evidence, not permission to enable global strict flags.

Initial live fixtures failed separately: [live-fixture.log](live-fixture.log)
used a peerless tunnel without explicit IPv6 and was correctly rejected;
[live-observer-fixture.log](live-observer-fixture.log) tried L2TP GET after
dropping NET_ADMIN and received EPERM. The final fixture uses explicit IPv6 and
the privileged observer. Neither earlier run is counted as a passing test or
a product defect. The two product failures remain in their separate logs.

`revision` plus `source.patch` identify the tested Rust source. Source identity,
artifact hashes and the host controller marker are recorded separately.
`docs-checks.log` checks local Markdown file targets and diff whitespace;
it does not check web URLs or anchors. Cargo build durations are omitted.

The new live cases have not run on the other four required targets or in Incus.
The remaining 44 citations, full event-cost/history proof, current combined
coverage, final matrix/manager refreshes and strict CI remain open. This package
does not declare Phase 6 complete.
