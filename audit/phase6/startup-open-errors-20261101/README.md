# Public startup socket errors preserve adopted inputs

The existing isolated startup fixture now refuses socket creation through
Runtime::new and the async Service::new, in addition to the blocking
constructor. All three return the original EPERM as Error::Io. Both adopted
names, their exact descriptor numbers and working Unix-stream data paths
are preserved, including the malformed inherited name.

`revision` identifies signed 29bdb59; `source.patch` adds two cases to the
existing test and extends its errno selection. No production or API change.
The fixture now covers eight startup faults. Ten full native startup runs,
three musl runs, ten serial instrumented library repetitions and common
checks pass. External startup still has three passing test declarations;
the instrumented copies stay in the isolated serial profile.

Four controls fail: discarded inputs, a changed errno, a Runtime panic and
a Service unwrap. Patches apply after source.patch; mutations are isolated,
restored and never contribute profiles.

All 4,304 complete mappings remain identical. Constructor counters show
both success and the new error arm in different compiled library instances.
The aggregate report remains 8,423/8,671 lines (97.14%) and 1,672/1,850
branches (90.38%): 248 lines and 178 branches remain. No numerical coverage
gain is claimed. No production exclusions, profile mismatches or saturated
regions are present.

These child syscall-refusal cases run on Ubuntu 6.8.0-147 with GNU and musl;
they create no network configuration. The completed matrix frozen at
production 584062d retains its own scope and excludes these later case
additions. Complete clause/history/resource proof and 100% coverage remain
open.
