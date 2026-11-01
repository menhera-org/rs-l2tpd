# Service queue ordering and admission

Two test-only additions check the existing worker's deferred operator queue.
Production code is unchanged from `revision`; `source.patch` and
`final-source.patch` agree.

The stale-reload case queues a restart, reload and second restart before
serving begins. The first restart queues one background tick and a newer
reload through `Control::reload()`. The older deferred reload must be
rejected. The second restart fills the remaining admission slots and checks
that the stale request returned its slot. The newer callback then runs once
and requests shutdown. Exactly two restarts and one reload must run.

The background-error case makes a failure ready after the first of two
pending restarts. The worker must handle that failure before another
restart, preserve its error, and complete cleanup. A second callback fails
the test.

Ten native and instrumented model/rule/service/startup repetitions and three
musl model repetitions pass. All eight service unit cases pass three focused
GNU and three musl runs. Common gates, Rust 1.89 and ARM64/RISC-V64/PowerPC64LE
musl compile checks pass. The three uninstrumented controls each fail only
the intended new case: accepting stale work, leaking its admission slot,
and discarding a ready background event. The controls leave seven passing
service unit cases.

The merged report reaches **8,464/8,687 lines (97.43%) and 1,693/1,852
branches (91.41%)**, leaving 223 lines and 159 branches. All preceding 4,311
production mappings remain unchanged; eight service instantiations are
added by the test callers. `worker-counters.json` confirms both generation
outcomes within the same fake-worker instantiation and execution of the
ready background branch. No production exclusion, profile mismatch or
saturated region is present. The collector continues the unchanged
checked-reply implementation's profiles; profiles from earlier production
implementations are not merged.

These cases use fake kernel state and real threads/Tokio queues on the
local Ubuntu 6.8.0-147 host, with GNU and musl executables. They add no
per-distribution manager, system-container or non-x86 live qualification.
The required 3f503cd matrix still identifies the unchanged production
implementation. The global coverage and complete clause-proof gates remain
open.
