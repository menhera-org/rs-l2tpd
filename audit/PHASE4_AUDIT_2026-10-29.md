# Phase 4 audit — 2026-10-29

Scope: the Phase 4 deliverables of [the plan](../docs/plan.md#phase-4--runtime-and-services)
(`src/runtime.rs`, `src/service.rs`, `src/blocking.rs`, `src/lib.rs`) against
[library](../docs/spec/library.md) L5–L13 and
[architecture](../docs/spec/architecture.md) A6, A7, A13, A14, on clean `main`
at `93b5052`. The reconciler internals (Phase 3) and the live Linux suite were
not re-audited.

Gates re-run and green on this checkout: `cargo build --no-default-features`,
`cargo build --no-default-features --features serde`,
`RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps`,
`cargo test --all-features --lib runtime::` (12), `--test service` (14), `--doc`.

Each finding below states the rule, the code, the defect, the required fix and
the test that must exist afterwards. Items are ordered by severity. Fix F1
first; F2 is cheapest to fold into the same change.

## F1 (must fix) — the reconciler loop stalls while a reload callback runs

- **Rules**: L7 ("runs on a thread that may block"), A14 ("every retry is a
  message or a timer in the loop, never a nested wait"), A6, L12, L13, M14.
- **Code**: [`src/service.rs:299-350`](../src/service.rs#L299-L350). After
  spawning the `l2tp-reload` thread, the worker calls `engine.block_on` on a
  future that only completes when the callback answers or shutdown is set.
- **Defect**: while the callback blocks, the worker dequeues nothing. Timers
  (`Runtime::next_event` ticks) do not fire, so E12/E13/E14 retries and the
  V4 resolver poll stop; `TunableWritten` and `SocketForgotten` answers sit in
  the queue until the L12 five-second and L13 two-second deadlines expire,
  turning a slow reload into T26 fallbacks and withdrawal timeouts; kernel
  notices fill the 1,024-entry queue and overflow into a loss and a full E20
  resync. The existing test
  `shutdown_does_not_wait_for_blocked_callback_or_apply_its_result` only
  checks the shutdown escape, so this passed.
- **Fix**:
  1. Add a private variant to `Action` in `src/service.rs`, e.g.
     `Reloaded { generation: u64, reload: Reload, result: Result<Result<Config>> }`
     (inner `Result` from `catch_unwind`, mapped to `Error::ReloadPanicked`).
  2. The `l2tp-reload` thread sends that action back with
     `control.tx.blocking_send(ControlEvent::Service(Operation(..)))` instead
     of a oneshot. Remove the nested `block_on`, `cancelled()` and `answer_rx`.
  3. Keep `serving` populated. Replace `serving.take()` with an
     `in_flight: Option<u64>` holding the running generation; the `Reload`
     closure travels with the thread and returns inside `Reloaded`.
  4. On `Reload { generation }` while `in_flight.is_some()`: do not run the
     callback and do not drop the request; remember the latest generation in
     `pending: Option<u64>`. On `Reloaded`: restore the closure, apply the
     result only if `generation == shared.generation` (as now), then if
     `pending` is newer start the next callback. This keeps P13's "latest
     request runs next".
  5. A `Reloaded` arriving after shutdown is ignored except that a panic still
     records `Error::ReloadPanicked` as the run failure (L7).
  6. `Control::cancelled` becomes unused; delete it.
- **Tests to add** in `tests/service.rs`:
  - `/// spec: L7, A14, M14`: gate the reload callback (as the existing
    `Gate` does), advance the fake clock past one second, and assert the
    reconciler issued a retry or kernel operation while the callback is
    still blocked (observe `host.with(|k| k.ops())` or dump count).
  - `/// spec: L12, L7`: with `bindv6only` set, answer `WriteTunable`
    through `Control::tunable_written` while a reload callback is blocked;
    assert the tunnel registers before the five-second deadline.
  - Extend `superseded_reload_is_discarded_and_the_latest_runs_next`: send
    two reloads while the first callback is blocked; assert exactly one more
    callback runs afterwards and `control.config()` reflects it.

## F2 (should fix) — reload and restart requests between `converge` and `run` are dropped

- **Rules**: L5, L6 ("requests accepted through the handle are processed in
  order of acceptance"), P12.
- **Code**: [`src/service.rs:291-294`](../src/service.rs#L291-L294) and
  [`:352-355`](../src/service.rs#L352-L355), guards `serving.is_some()`.
  When the guard fails the event falls to `Runtime::handle_event`, whose
  wildcard arm discards it.
- **Defect**: a reload or restart accepted after convergence but before
  `run` was called is lost. The binary (Phase 5) calls `converge` then
  `run`; a `SIGHUP`/`SIGUSR2` in that window vanishes.
- **Fix**: when `converged && serving.is_none()`, record `pending_reload =
  Some(generation)` / `pending_restart = true`; when `Action::Run` arrives,
  re-inject them (reload first if its generation is still current, then
  restart) before serving the queue. During convergence (`!converged`)
  reloads remain ignored as L5 requires. Combine with F1's `pending`.
- **Test**: `/// spec: L5, L6`: converge, call `control.reload()` and
  `control.restart()`, then `run`; assert the callback ran once with the
  accepted config and the restart callback was invoked.

## F3 (should fix) — a full host-request receiver silently consumes a store record

- **Rule**: L13 ("if full, report storage unavailable for new sockets and
  keep them locally owned; do not accumulate untracked submissions").
- **Code**: [`src/service.rs:210-213`](../src/service.rs#L210-L213):
  `host.try_send(event)` failure only logs; the `StoreSocket` duplicate is
  dropped and the reconciler keeps the reservation and treats the name as
  stored.
- **Defect**: the capacity slot is spent on a socket the manager never saw;
  shutdown later withdraws a name the store does not hold, and the socket is
  not reported as locally owned.
- **Fix**: add a reconciler entry point (e.g. `Reconciler::store_refused(name)`
  releasing the record and logging "storage unavailable") and a matching
  `Request`/event path; call it from `host_request` when `try_send` fails
  for `StoreSocket`. `ForgetSocket`/`WriteTunable` on a full receiver can
  keep the current behaviour (their deadlines bound them).
- **Test**: `/// spec: L13`: set store capacity 1, take the requests
  receiver and never drain it after filling it; assert the reconciler
  reports the name as not stored and no `ForgetSocket` is issued for it at
  shutdown.

## F4 (should fix) — no blocking completion path for `blocking::Service` embedders

- **Rules**: L8, L12, L13.
- **Code**: [`src/runtime.rs:228-237`](../src/runtime.rs#L228-L237):
  `Control::tunable_written` and `Control::socket_forgotten` are `async`
  only. `blocking::Service::take_requests` hands out a Tokio `Receiver`.
- **Defect**: a program using the blocking service must still build a Tokio
  runtime to answer host requests (the test does exactly that at
  [`tests/service.rs:518`](../tests/service.rs#L518)). L8 promises the same
  service "as ordinary blocking functions".
- **Fix**: add `Control::tunable_written_blocking` and
  `Control::socket_forgotten_blocking` using `Sender::blocking_send`, and
  document `Receiver::blocking_recv` on `take_requests`. No new types.
- **Test**: rewrite the host thread in
  `blocking_service_exposes_host_requests_and_waits_for_processing_acknowledgement`
  without `engine().block_on`.

## F5 (minor) — `Control::config` is stale after shutdown

- **Rule**: L6 ("`config` returns the accepted configuration").
- **Code**: the snapshot in `Shared::config` is written only at
  [`src/runtime.rs:367`](../src/runtime.rs#L367). `Reconciler::shutdown`
  sets its accepted configuration to empty but the handle keeps the old one.
- **Fix**: in `Runtime::shutdown`, after `self.reconciler.shutdown()`, store
  `self.reconciler.accepted().clone()` into `shared.config`.
- **Test**: extend `run_after_shutdown_reports_the_completed_cleanup` with
  `assert_eq!(control.config(), Config::new())` after `run` returns.

## F6 (minor) — `Service::drop` blocks the caller's executor

- **Rules**: L8 (drop semantics are specified only for `blocking::Service`),
  A14.
- **Code**: [`src/service.rs:195-202`](../src/service.rs#L195-L202) joins
  the reconciler thread inside `Drop`, which may run on a Tokio worker.
- **Defect**: on a current-thread runtime that also drains the host
  requests, withdrawal answers cannot be delivered during the join; cleanup
  then fails after the bounded four seconds instead of succeeding. Not a
  hang, but the doc line "Dropping requests shutdown and joins the owner"
  overstates what the drop achieves.
- **Fix**: either document that `Service` (Tokio) must be shut down through
  `run` or `control().shutdown()` plus `run` and that `Drop` only requests
  shutdown (and stop joining), or keep the join and state the limitation in
  the type docs. Prefer the first: it removes code. `blocking::Service`
  keeps its join (L8 requires it).
- **Test**: `/// spec: L8`: drop a Tokio `Service` inside
  `engine().block_on` with the request receiver taken and un-drained; assert
  the drop returns promptly and the kernel objects are gone after the
  worker finishes (join via a completion channel).

## F7 (cosmetic) — `ControlEvent::ResolverAnswers` is never produced

- [`src/runtime.rs:110-111`](../src/runtime.rs#L110-L111). Answers are
  polled from `Reconciler::tick`. Either remove the variant (it is public
  API already; keep it and document "reserved, treated as `Tick`") or have
  the resolver worker send it. Keeping it costs nothing; document it.

## Verified as conforming (no action)

- L5: startup failure returns adopted descriptors with exact names
  (`Runtime::new`, `with_kernel`, both services); `run` without `converge`
  converges first; converge ignores reloads and returns the left-out list,
  also on shutdown.
- L6: `reload` is `try_reserve`, `reload_wait` reserves outside the
  acceptance lock, `shutdown` is a persistent flag plus `Notify`, generation
  numbers serialise acceptance; restart callback gets duplicates and the
  service resumes if it returns.
- L7: callback error logged and configuration kept; panic yields
  `Error::ReloadPanicked` after cleanup; shutdown does not wait for a
  blocked callback.
- L9/L10: `handle_event` has the wildcard arm; `Drop` aborts both
  subscription tasks; the queue closes.
- L12/L13 at the runtime boundary: requests carry incarnation and absolute
  deadline, late answers are ignored, withdrawal and T8 windows are separate,
  residual references end `shutdown` with an error after four seconds.
- A6: per-source loss flags outside the queue, consumed before dequeue;
  producers never block.
- A7: the lifetime subscription has its own socket and thread in
  `kernel::linux::lifetime`, outside the event channel.
- L3: `Receiver` re-exported; enums `#[non_exhaustive]`; boundary records
  have private fields.
