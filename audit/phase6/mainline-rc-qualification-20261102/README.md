# Required-kernel qualification resumed on 2026-11-02

Phase 6 resumed from signed `455eef7`. The tree was clean and both pending
CI runs completed successfully:
[code](https://github.com/menhera-org/rs-l2tpd/actions/runs/41361624431) and
[handoff](https://github.com/menhera-org/rs-l2tpd/actions/runs/41361814138).
The preceding turn committed the handoff and verified cleanup; it was
progress followed by the requested pause.

The fresh publication check still selects **6.8.0-147.147, 6.8.12,
7.0.0-42.42, 7.0.14 and 7.4-rc1**. Its upstream documents and Ubuntu package
metadata are in `publication/`. The resolved list matches the pre-pause
selection exactly. An initial local resolution wrapper sourced the
runner's directory setup from the wrong location and failed to write its
output; the corrected invocation explicitly restored the checkout before
resolving. That failed wrapper produced no kernel result.

Both RC kernel variants built successfully in disposable networkless
containers. `build-ipv6.log` and `build-no-ipv6.log` retain their configuration
and image digests. A fresh `tests/docker/run.sh matrix required` run is in
progress. Its Ubuntu 6.8 normal and clock profiles passed; no pending RC
guest result is counted as passed. P3 remains open until the complete
required set passes and the final publication check agrees.

The [source review](source-review.md) identifies the selected source
contracts, complete file differences and exact identities. It preserves
the distinction between source evidence and live execution. All 43 selected
files in each compared tree match fresh extractions from the archives.

The common CI script now runs the existing publication-parser self-test
before Cargo. It accepts final and RC tags, rejects malformed tags and
checks guest release-name formatting. POSIX syntax, ShellCheck and the
self-test pass; `ci-parser-enforcement.patch` records the one-line hook.

`common.log` records a passing `./test-ci-gates.sh` run before further
changes: formatting, ShellCheck, Clippy, native/musl builds and tests,
strict rule/source maps and warning-denied documentation. Its build-time
durations are omitted. No production Rust source was changed.

P4 remains **98.01% lines / 92.01% branches**, leaving 173 lines and
148 branches. Complete clause/history/resource/event-cost proof remains
open. This in-progress record does not close Phase 6.
