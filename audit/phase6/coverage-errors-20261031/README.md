# Error replies, worker creation and configuration coverage

This batch changes tests only. The production prefix of `service.rs` is
byte-identical to `902e3ba`; configuration changes stay in its existing
excluded test module. [Source checks](source-checks.log), `revision` and
`source.patch` identify the tested tree.

- A failed resolver dispatcher creation returns `EAGAIN` without retaining
  a watch. After a dispatcher has started, thread-synchronized seccomp
  refuses lookup-thread creation. Sixteen jobs complete with empty results,
  proving failed spawns release the eight-slot admission budget. The six
  existing startup faults still preserve inherited descriptors. These
  subprocess filters affect no other test or host process.
- Every explicit document field replaces its previous value. Identity
  getters and all discovery methods/DHCPv6 identity choices round-trip
  through configuration serialization. A hard resolver error on reload
  retains its accepted configuration; diagnostic rendering keeps entry,
  source, effect and refusal context.
- Abandoned service reply channels return `service stopped`. Shutdown
  releases a convergence waiter successfully; repeated `run` reports
  completion, and repeated shutdown is harmless.

[Focused startup](startup-focused.log), [configuration](config-focused.log)
and [service](service-focused.log) checks pass. Startup also passes
[without default features](startup-no-default.log), using `nix::libc`
rather than the optional binary dependency. Two draft configuration
fixtures omitted a peerless tunnel's family or explicitly supplied an
inapplicable RA client identity; their failed logs are retained. The
corrected fixture supplies a literal peer and leaves the RA identity unset.

[Common gates](ci-gates.log) and all ten seeded repetitions pass: 109
ordinary library cases, 68 fake cases, 78 rules, 27 service cases and two
startup cases (six inherited-descriptor faults plus two resolver-spawn
faults) per seed. Musl process/startup, strict maps, formatting, Clippy
and warning-denied documentation also pass.

The [merged report](merged.log) is **93.32% of production lines**
(7,868/8,431) and **80.95% of branches** (1,436/1,774), leaving
**563 lines and 338 branches**. No production exclusion was added. The
same 47 test-only modules and one helper stay excluded from instrumentation
while all tests execute.

This is an incremental collection over the fresh
[resolver-cost profiles](../resolver-cost-20261031/README.md), with
unchanged production bodies and positions. The new native run executes
every ordinary all-feature suite; earlier live, process, scenario,
real-manager and Incus profiles remain applicable. No profile-mismatch
warning occurred. Features are `all`, target is GNU, compiler is pinned
nightly-2026-10-28 and cargo-llvm-cov is 0.9.1. Cargo build durations are
omitted. The common/native host kernel is `6.8.0-147-generic`.

The preceding resolver commit's CI run
[41226718700](https://github.com/menhera-org/rs-l2tpd/actions/runs/41226718700)
passes build/coverage but fails the new shared-discovery case in the
live guest. Its log reveals an upstream DHCPv6 cache keyed only by interface
name, allowing reuse across network namespaces. A focused upstream regression
reproduces that defect. The upstream-boundary work is recorded separately
under `audit/phase6/upstream-netns-20261031/`; this batch neither fixes nor
bypasses it. The 100% coverage gate, upstream integration, remaining
clauses/event cost and final matrix remain open.

```sh
./test-ci-gates.sh
cargo test --locked --no-default-features --features fake-kernel --test startup -- --nocapture
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat with seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-resolver-cost-final-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
