# Closed host-request receiver

A blocking-service embedder enables host integration, then drops the
receiver before convergence. The new public-API regression checks both
requests whose delivery fails: a bindv6only write and withdrawal of a
malformed inherited descriptor.

The descriptor stays open before its withdrawal deadline. Advancing the fake
clock by five seconds wakes the tunable fallback and closes the expired
local descriptor. Readiness succeeds with an AF_INET socket; bindv6only
remains true, and the configured session exists. Dropping the receiver does
not acknowledge the store withdrawal. Shutdown therefore returns the exact
`kernel or descriptor-store cleanup incomplete` error after its deadline,
while releasing local sockets and sessions.

The test uses the existing shared fake host, configuration, clock and wake
helpers. Synchronization observes accepted configuration snapshots before
advancing time; it adds no sleeps. No host network or system unit changes.
`revision` plus `source.patch` reconstructs the source. Only test code changes.

## Checks and coverage

The complete 30-case service suite passes ten GNU repetitions and three
musl repetitions. Native coverage and mandatory common checks pass. All
preceding production function/region/branch mappings remain unchanged; five
new generic instantiations come from this test's callback type and introduce
no branch mappings (`mapping-check.json`). The merged broader live profiles
therefore remain compatible. Production coverage reaches **95.05% lines**
(8,101/8,523) and **85.03% branches** (1,539/1,810), leaving **422 lines and
271 branches**. No production exclusions or saturated inferred regions.
Logs omit Cargo build durations.

This test establishes behavior when host delivery fails. It does not prove
that a real manager processed a withdrawal; the expected cleanup error
explicitly preserves that distinction. Final qualification, H11/G23 decisions,
the upstream nix release, full clause/resource/event-cost proof and 100%
production coverage remain open.

```sh
# Ten repetitions:
cargo test --locked --all-features --test service
# Three repetitions:
cargo test --locked --all-features --target x86_64-unknown-linux-musl --test service
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-alias-state-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
