# Phase 4 audit remediation — 2026-10-29

Addresses every finding F1–F7 in the
[audit](PHASE4_AUDIT_2026-10-29.md), including its added blocking contracts
and the L7/L8 amendments in `54d68aa`. The audit's findings describe the
`93b5052` baseline; they are preserved as written.

## Resolutions and regression evidence

| Finding | Resolution | Executed regression |
|---|---|---|
| F1 — must | The reload thread posts a private `Reloaded` action through the bounded input channel. The owner keeps processing kernel events, timers and host acknowledgements while the callback runs. It retains only the latest pending reload, restores the callback on completion, and discards superseded results. A panic also persists outside the queue so cleanup cannot hide a queued panic result. | `retry_timer_keeps_running_during_a_blocked_reload`, `tunable_completion_is_processed_during_a_blocked_reload`, `withdrawal_completion_is_processed_during_a_blocked_reload`, `superseded_reload_is_discarded_and_the_latest_runs_next` (two queued superseding reloads, exactly two total callback invocations), and `panic_completion_during_shutdown_is_reported_after_cleanup`. Existing blocked-callback shutdown and panic cleanup cases pass. |
| F2 — should | Requests accepted between convergence and run are retained in acceptance order, including every restart. Reloads accepted during convergence remain ignored even when a blocking operation delays their dequeue until after readiness. Operator deferral is bounded by admission slots held until completion; background work is interleaved with draining deferred requests. | `requests_between_converge_and_run_keep_their_order` covers both reload/restart orders and repeated restarts; `reload_accepted_during_convergence_is_ignored_even_when_dequeued_after_readiness`; `deferred_restarts_are_bounded_and_each_accepted_request_runs`; admission cancellation/dequeue cases in runtime tests. |
| F3 — should | Full, closed or disabled host delivery refuses the never-submitted store record, releases capacity and leaves local ownership. Shutdown also refuses store requests it cancels before delivery. Refusal stays on a private synchronous owner-thread path, so a delayed external name-only reply cannot release a later incarnation. | `refused_host_delivery_releases_capacity_and_needs_no_withdrawal`: capacity one, pre-filled undrained receiver; also closed and disabled receiver cases. Another tunnel can use the released slot, readiness remains true, and shutdown emits no withdrawal for refused sockets. |
| F4 — should | Added `tunable_written_blocking` and `socket_forgotten_blocking` using the channel's blocking send directly. Documented `Receiver::blocking_recv`; synchronous helpers do not read the caller's Tokio handle. | The existing blocking host integration test now uses an ordinary thread with no runtime; `blocking_completions_work_inside_spawn_blocking` and the complete blocking-service/callback test below. |
| F5 — minor | Shutdown updates the shared accepted-config snapshot to the reconciler's empty configuration. | `run_after_shutdown_reports_the_completed_cleanup` and blocked-callback shutdown assertions. |
| F6 — minor | Tokio service drop only sets persistent shutdown; it does not join on an executor worker. The blocking service's owned supervisor keeps its subscription runtime driving events until owner cleanup completes, then its outer drop joins. Type and interface docs distinguish the contracts. | `tokio_drop_returns_without_blocking_host_request_processing`: un-drained requests at drop, prompt return, same current-thread executor subsequently handles withdrawals, owner completion observed and kernel objects absent. Existing blocking drop-before/after-run cases remain green. |
| F7 — cosmetic | Retained the public `ResolverAnswers` variant and documented it as reserved, handled like `Tick`; current resolver answers are polled by the policy timer. | Warning-free rustdoc; dispatch behavior is unchanged. |

The primary cases are in [service integration tests](../tests/service.rs),
[service unit tests](../src/service.rs), and
[runtime tests](../src/runtime/tests.rs). Timers and delayed callbacks use
virtual time and channel gates; no fixed sleeps were added.

## Updated blocking contracts

`spawn_blocking_callers_and_injected_callbacks_can_own_their_runtimes`
runs construction, configuration of storage, host-request receiver access,
convergence, synchronous control operations, run and drop inside
`tokio::task::spawn_blocking`. Its supplied kernel and resolver callbacks,
plus reload and restart callbacks, actually create and drive their own Tokio
runtimes. This includes subscription creation, clock/deadline preparation,
resolver polling and cleanup, and restart descriptor duplication.

To keep those callbacks out of Tokio context, subscription initialization
runs on an owned temporary thread. `Runtime::next_event` prepares policy
time on its owner thread and returns a future that only waits on channel,
notification and timer readiness. The service prepares that future before
entering `block_on`, including its nonblocking background poll between
deferred requests. This avoids moving callback invocations into a nested
runtime while fixing F1.

## Verification

Saved logs: [ordinary suites](phase4-remediation/tests.log),
[ten repetitions](phase4-remediation/repeats.log),
[live host](phase4-remediation/linux-host.log),
[build/warning gates](phase4-remediation/gates.log), and
[traceability](phase4-remediation/traceability.log).
Only PTY whitespace and carriage returns are normalized.

- `cargo test --locked --all-features --target x86_64-unknown-linux-musl`:
  **64** ordinary library tests (including 14 runtime and two service unit
  cases), **22** service integration tests, **63** rules/property tests,
  one fake conformance wrapper (15 shared bodies), five tool tests and six
  doc tests passed. Privileged suites remain ignored in this ordinary run.
- Ten repetitions with `TEST_SEED=1..10` selecting
  `--lib --test service --test rules --test kernel-fake`: passed.
  Seeds vary the property sequences; concurrency fixtures repeat unchanged.
- Isolated Docker host suites on **6.8.0-147-generic**, with no networking
  and read-only executable mounts: **9** library live cases, **12**
  kernel-linux cases and **5** review cases passed. This includes both live
  service implementations and unordered runtime drop. The runner is in
  [kernel instructions](../tests/kernel/README.md).
- `cargo clippy --locked --all-targets --all-features --target x86_64-unknown-linux-musl -- -D warnings`: passed.
- No-default and serde-only musl builds, warning-denied all-feature rustdoc,
  and `cargo fmt --check`: passed.
- `cargo +1.89.0 check --locked --all-features --target x86_64-unknown-linux-gnu`:
  passed on the declared minimum Rust version. This additional check used
  its installed GNU target; the executable tests and other builds used musl.
- Global rule/source mapping remains lenient until Phase 6; its report is
  traceability, not behavioral coverage.

The full required QEMU matrix, coverage gate, actual binary store/re-exec
protocol and whole-daemon scenarios were not re-run or claimed here.
The binary remains the Phase 5 stub. No dependency was added.
