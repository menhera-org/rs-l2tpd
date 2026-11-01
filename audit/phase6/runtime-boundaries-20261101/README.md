# Runtime admission, shutdown and inherited names

Four test-only cases exercise these boundaries:

- Adopted identifiers require canonical nonzero names. The table includes
  zero, leading zero, sign, wrong prefix, whitespace, overflow and u32::MAX.
  Every original name and descriptor is retained; real Unix-stream data
  still passes after ownership is returned.
- Both a shutdown request and already-started shutdown refuse new
  reconciliation, preserving accepted configuration without kernel calls.
- A closed admission semaphore returns its original errors without changing
  generation, admission count, capacity or the event queue. Closing that
  semaphore is a private harness action; no public close API is claimed.
- Shutdown discards a tunable request before the program has received it.
  The model's tunable remains unchanged and cleanup completes.

`revision` identifies signed f6c7e86; `source.patch` appends only the tests.
The focused runtime suite passes 24 cases, with one ignored. Final full
library qualification passes ten native and instrumented seeds using
TEST_SEED=1 through 10, three musl runs and all common gates. The ordinary
library has 242 passing cases and 19 ignored; instrumentation adds three
serial-only startup cases. Previously qualified live profiles remain merged.

Six controls fail: accepting zero or noncanonical identifiers, omitting
either shutdown guard, returning success from closed reload admission, and
forwarding the queued tunable during shutdown. Patches apply after
source.patch; controls are restored and never enter coverage.

All **4,302 complete coverage mappings are identical** to the preceding
host-worker package. The report reaches **8,421/8,671 lines (97.12%)** and
**1,670/1,850 branches (90.27%)**: 250 lines and 180 branches remain.
No production exclusion, profile mismatch or saturated region is present.

The required matrix passes all thirteen profiles on frozen production
commit 584062d.
It does not execute these later declarations. No production, dependency,
public API or specification changes. Complete clause/history/resource
proof and the 100% coverage gate remain open.
