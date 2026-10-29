# Phase 4 verification — 2026-10-29

Phase 4 is complete within its library/runtime scope. The starting checkout
was clean `main` at `c8058b4`, already pushed to `origin/main`; that commit
contains the [Phase 2–3 evidence](PHASE23_VERIFICATION_2026-10-29.md).

The runtime owns the bounded input queue, independently drained monitor and
L2TP subscriptions, policy deadlines and persistent loss/shutdown state.
Services own a reconciler thread; the blocking service also owns the
subscription runtime. Reload callbacks execute on a separate thread and may
finish after shutdown. Superseded results are discarded. Restart callbacks
receive duplicate descriptors and normal operation resumes if they return.

The library delegates host writes and store protocols to the caller. Service
host integration uses `set_store_capacity`, `take_requests` and `Control`
completions. Without it, tunable writes are declined and sockets remain locally
owned. The lower-level runtime exposes every event through `next_event`.
Shutdown is incremental: forward events and call `shutdown` until complete.
Two-second store withdrawal and kernel deletion windows are separate.
A remaining reference is an error, not successful cleanup.

## Executed acceptance cases

| Rules | Evidence |
|---|---|
| L1–L2 | Library source boundary assertions and crate unsafe-code denial; host writes/store actions performed only by the test embedding program. No new dependency, filesystem access, environment access or signal handler in production library code. |
| L3 | Private boundary-record fields, constructors/getters, non-exhaustive public enums; external API re-export test; rustdoc negative compile cases for exhaustive event matching and public field construction. |
| L4 | Existing configuration constructor, insertion, strict/lenient conversion and serde tests re-executed with all features. |
| L5 | Conflict convergence under a continuously ready input queue; reloads ignored during convergence; implicit convergence by Tokio `run`; startup failure returns exact names and live descriptors; verified adoption reuses the tunnel; malformed names and valid names with refused descriptors retire without claiming them. |
| L6 | Full queue refusal, pending `reload_wait` released by a dequeue, shutdown priority over queued reloads; accepted config snapshots, serialized callbacks, superseded result discarded, latest callback next; restart duplicates and resume after callback failure. |
| L7 | Reload error retains config; callback panic returns `ReloadPanicked` after cleanup; a channel-blocked callback does not hold up shutdown or apply its eventual result. |
| L8 | Blocking convergence/run, use inside another Tokio runtime, drop before run and after convergence; session deletion precedes tunnel close. |
| L9–L10 | Program-driven event forwarding for both kernel sources, ticks, tunable/store requests and completions; both loss flags persist outside a full channel; runtime drop stops both tasks and closes input. Live runtime drop closes tunnel sockets without an orderly wait. |
| L11 | Preserved errno, startup/closed/full queue errors and invalid timing calls; bounded cleanup failure with an externally retained socket. |
| L12 | Named/value/deadline request, no registration while pending, successful fresh-socket readback, exact deadline and late answer, timer progress under queue flood, shutdown cancellation. Phase 3's failure/still-only/multiple-waiter cases also re-executed. |
| L13 | Exact store names, storage-before-withdrawal order, processing acknowledgements, stale incarnation, bounded missing acknowledgement, rejected adoption, capacity, separate withdrawal/deletion windows. Existing Phase 3 replacement/uncertainty/retry cases re-executed. |
| A6–A7, A13–A14 | Subscription task demonstrably drains while owner is blocked inside a gated kernel dump; queue filled meanwhile, second loss during resync triggers another dump. Lifetime proof/rename succeeds with full event queue; persistent shutdown wakes independently. Existing live proof/deadline/overflow cases re-executed. |

Concrete cases are in [runtime tests](../src/runtime/tests.rs),
[service tests](../tests/service.rs), existing [rule tests](../tests/rules/),
and `services_converge_and_orderly_shutdown_on_linux` in the
[live suite](../tests/kernel/linux.rs). Virtual clocks and channel gates
control delayed policy/callback behavior; the tests use no fixed sleeps.

Two defects found by these cases were corrected: an always-ready channel
could starve a due Tokio timer, and service shutdown needed explicit kernel
absence confirmation rather than treating local close as completion.

## Commands and results

All builds/tests used `x86_64-unknown-linux-musl`. The final command logs are
[ordinary tests](phase4/tests.log), [ten repetitions](phase4/repeats.log),
[build/warnings gates](phase4/gates.log), [live host](phase4/linux-host.log),
and [traceability reports](phase4/traceability.log). PTY progress whitespace
and carriage returns are normalized in the saved logs.

- `cargo test --locked --all-features --target x86_64-unknown-linux-musl`:
  60 ordinary library tests, 63 rules/property tests, 14 service tests,
  one fake conformance wrapper (15 shared bodies), five tool tests and six
  doc tests passed. Privileged cases remained ignored in this command.
- Ten repetitions with `TEST_SEED=1` through `10`, selecting
  `--lib --test service --test rules --test kernel-fake`: all passed.
  The seed changes the property sequences; service concurrency cases are
  repeated with their fixed fake fixtures.
- `cargo clippy --locked --all-targets --all-features --target x86_64-unknown-linux-musl -- -D warnings`: passed.
- `cargo build --locked --no-default-features --target x86_64-unknown-linux-musl`, with and without `--features serde`: passed.
- `RUSTDOCFLAGS='-D warnings' cargo doc --locked --all-features --no-deps --target x86_64-unknown-linux-musl` and `cargo fmt --check`: passed.
- Isolated Docker, `--network none --privileged`, read-only mounts of the
  three test executables, image `rs-l2tpd-audit-vm:local`, host kernel
  **6.8.0-147-generic**: nine library live cases, twelve `kernel-linux`
  cases and five review cases passed. The new case runs both service
  implementations and verifies immediate absence on orderly return, then
  exercises unordered `Runtime` drop. See the
  [runner instructions](../tests/kernel/README.md) for exact mount commands.
- Rule map/source-link reports remain lenient globally, as planned until
  Phase 6. Every L rule has test citations; this table and execution results,
  rather than citations alone, record Phase 4 acceptance.
  The global report has 134 active rules without citations and five K facts
  not cited by `kernel::linux` (K13, K14, K33, K38, K40); no adapter function
  lacks a source citation. These are not reported as strict gate passes.

## Remaining scope

The binary still exits 2. Files, signals, daemonization, PID handling, actual
host writes, systemd store protocol and exec belong to Phase 5. The existing
Phase 2–3 real-manager reference evidence remains applicable; its two halves
were not re-run here. Fake host integration does not claim a real process
crash/re-exec test.

The required current kernel matrix, whole-daemon scenarios, 100% path coverage
and strict global gates remain Phase 6. This change re-runs the host suites;
it does not claim a new QEMU matrix run or replace earlier per-kernel evidence.
