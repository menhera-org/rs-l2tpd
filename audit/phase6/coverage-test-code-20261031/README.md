# Coverage scope: test-only failure paths

The pre-decision P4 report measured 92.26% lines and 78.16% branches of
`src/`, including inline `#[cfg(test)]` modules. That exposed a scope
decision before the 100% gate could be completed honestly.

At qualified source `0f5292e`, `src/service.rs:602` is the `panic!("expected withdrawal")`
arm inside the passing test
`panic_completion_during_shutdown_is_reported_after_cleanup`. The test
executes once; its failure arm has a zero coverage counter. Executing that
arm as written fails the test. It is test-fixture failure handling, not an
untested daemon failure path. The same measurement includes other inline
test bodies and their defensive failure paths.

At that point the phase permitted exclusions only for documented unreachable
Linux-kernel branches and did not authorize excluding test code. No new
exclusion was applied before the decision. The separate uncovered production
paths remain required work regardless of this decision.

The maintainer approved production-code coverage on 2026-10-31. The
contract remains 100% line and branch coverage of production
`src/` code, with `#[cfg(test)]` bodies/helpers excluded from instrumentation.
All those tests still execute and must pass; their execution and rule
citations remain checked separately. Production error handling retains
the existing strict obligation, and the Linux-only exclusion rule remains
unchanged for production code. `proposed.patch` makes that distinction
explicit in the plan, testing page and phase instructions; the approved
patch is applied. Nightly-only `coverage(off)` attributes identify test-only
modules/helpers, and all their tests still execute. No production path is
excluded by this change. The coverage CI step uses pinned nightly
2026-10-28 and cargo-llvm-cov 0.9.1 with branch instrumentation; its new
workflow run remains pending. Stable checks and the shipped musl build
continue to use stable Rust.

The earlier 92.26%/78.16% report retains its original scope, including inline
test code. A fresh production-scope profile collection is required; changing
the denominator alone cannot close the 100% gate.
