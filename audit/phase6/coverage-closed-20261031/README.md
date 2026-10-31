# Closed handles and lifetime proof failures

Dropping a runtime with a full event queue releases a blocked reload waiter.
Retained control handles then reject reloads, restarts and both synchronous
and asynchronous host completions. A completed Tokio service rejects a second
`run` and capacity changes, while convergence after shutdown observes completed
cleanup. These tests exercise public API behavior; implementation is unchanged.

Lifetime-state tests reject foreign senders and mismatched reply sequences,
distinguish ENODEV from failed lookup replies, and invalidate a generation on
malformed kernel framing. Missing sockets, duplicate captures, expired deadlines
and disarmed captures cannot establish ownership. Packet inputs are constructed
by the tests; sockets opened for capture/recovery are real netlink sockets.
These are parser/state tests, separate from the live kernel's reply contract.

The fake conformance runner now executes all 17 shared cases under all four
combinations of CAP_NET_RAW availability and immediate/asynchronous session
deletion. Each case logs the fixture's actual settings. Live peer/zone logging
also records which input the binding checks use. The refreshed live Ubuntu
`6.8.0-147-generic` wrapper passes all 17 cases in an isolated, networkless
container. The other 18 live kernel cases and full scenarios were not repeated.

[Final common checks](final-ci-gates.log) and ten seeded repetitions pass.
Each final seed runs 97 ordinary library cases, 68 cases in one fake wrapper,
78 rules, 27 service cases and the six-fault startup case.
[Count checks](seed-counts.log) verify the results. Initial common/seed/coverage
logs precede the two lifetime-state tests; their separate source patch is
retained. Final logs include the complete package.

Merged production coverage is **92.72% of lines** (7,767/8,377) and
**80.03% of branches** (1,407/1,758), leaving **610 lines and 351 branches**.
There are no production exclusions. This adds 41 covered lines and 11 branches
to the [process record](../coverage-process-20261031/README.md).
The 100% gate remains open.

[Source checks](production-source.log) confirm unchanged production code.
The runtime tests belong to its existing excluded module; lifetime additions
are inside its existing excluded module. The baseline's live/manager/Incus
profiles remain applicable with the same compiler, target and features.
`revision`, `source.patch` and `final-source.patch` identify both stages.
[Final native collection](final-native-coverage.log), [live execution](final-live.log),
[merged report](final-merged.log) and [counts](counts.log) retain the evidence.
No profile-mismatch warning occurred. Cargo build durations are omitted.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat with seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-production-final-20261031"
cargo +nightly llvm-cov --color never --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report --lib --test service --test kernel-fake --test kernel-linux
# Run kernel-linux as in the preceding record's commands.log, using
# closed-%p-%m.profraw for the profile name; merge the exported profiles.
cargo +nightly llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```

Earlier CI remains green: both jobs passed on their first attempts for
[startup run 41217025839](https://github.com/menhera-org/rs-l2tpd/actions/runs/41217025839)
at `3f9d32a` and
[adoption run 41217588917](https://github.com/menhera-org/rs-l2tpd/actions/runs/41217588917)
at `f7db02e`. Retained [startup](ci/startup-jobs.json) and
[adoption](ci/adoption-jobs.json) metadata identify every job and step.
This package still needs its own CI run after commit.
