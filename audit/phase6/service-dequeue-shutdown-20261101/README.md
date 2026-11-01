# Service dequeue/shutdown ordering and capacity acknowledgement

A blocked sender's waker requests shutdown when the worker dequeues the
first queued command. The test checks that the wake actually occurred;
there is no sleep, scheduling guess or production hook. It exercises queued
capacity, convergence and run commands. Capacity/convergence replies are
closed, accepted configuration stays empty, and a test resolver panics if
configuration starts DNS work after shutdown.

A second public API case acknowledges store capacity before convergence
and preserves the exact refusal afterward. Shutdown completes normally.

`revision` identifies signed d4c6dea; `source.patch` adds only these two
tests and their local helpers. No production or specification changes.
Ten native and instrumented seeds, three musl library runs and all common
gates pass. The ordinary library has 244 passing cases and 19 ignored;
the instrumented library has three additional serial-only startup cases.

## Controls and calibration

Five controls fail: omitting the capacity shutdown guard, omitting the
convergence guard, bypassing both run/reconciliation shutdown safeguards,
refusing capacity too early, and accepting it after convergence. Each
patch applies after source.patch. All mutations are isolated and restored;
failed controls never contribute profiles.

Removing the run guard alone passes. That result and patch are retained as
run-single-guard-control: Runtime::reconcile independently refuses the new
configuration. The combined run control bypasses both safeguards and fails
at the resolver assertion. The private convergence-reply assertion checks
dispatch cancellation; the public API separately tolerates shutdown while
waiting for convergence. No claim is made that every guard is independently
necessary for the same public outcome.

The first auxiliary driver selected the public converge constructor rather
than its dispatch arm and stopped before applying that mutation. Its final
selector starts at the worker definition. The source was restored before
subsequent controls.

## Coverage and limits

The merged report remains **8,421/8,671 lines (97.12%)** and
**1,670/1,850 branches (90.27%)**, leaving 250 lines and 180 branches.
The executed false guards appear in the FakeKernel worker's counters;
LLVM's aggregate across generic instances does not increase here. No
coverage gain is claimed. All 4,302 preceding complete mappings remain
identical; two additional default Resolve-method instances belong to the
test resolver. No production exclusion, profile mismatch or saturated
region is present.

The required matrix passes all thirteen profiles on frozen 584062d and does not execute
these later declarations. This package adds no live kernel result.
Complete clause/history/resource proof and the 100% coverage gate remain
open.
