# File, handover and notification failures

The added checks exercise production error handling without changing its
implementation:

- Check mode writes to `/dev/full`, exits 1 with an output diagnostic, and
  preserves an existing PID-file sentinel.
- Eleven malformed re-exec states cover missing/invalid metadata, encoding,
  path bytes, hex and inode fields. Each returns the precise diagnostic and
  consumes both internal environment keys in an isolated child.
- Invalid PID paths, non-directory parents and missing files leave an unrelated
  inode untouched. Cleanup remains successful when the target is absent.
- Descriptor-store barriers reject a data byte and a manager that retains the
  transferred descriptor past the deadline. An abstract Unix-domain store
  exchanges a notification, rejects malformed names before transmission, and
  reports a transport error after write shutdown.
- The netlink feed reports malformed framing and NLMSG_OVERRUN as loss. An
  injected reopen refusal remains observable after its retry timer; its initial
  socket is a real netlink socket. This test checks retry behavior, not an actual
  kernel EMFILE refusal.

The final [common checks](ci-gates.log) and all ten seeded repetitions pass.
Each seed executes 94 ordinary library cases, 43 ordinary binary cases, one
fake-conformance wrapper, 78 rules, 26 service cases and the six-fault startup
case. [Count checks](seed-counts.log) verify those results. The common checks
also run musl binary/process/startup cases and both strict maps. Privileged
profiles are explicitly ignored in these native runs and were not repeated.

The first common run failed the abstract-store test's transport-error assertion.
It assumed dropping its listener closed every reference immediately; another
binary test's fork can briefly retain that descriptor until exec. Explicitly
shutting down the connected store's write side creates the intended transport
failure independently of such references. The failure remains in
[before-shutdown-ci-gates.log](before-shutdown-ci-gates.log); ten subsequent
complete binary repetitions pass with the corrected fixture.

Merged production coverage is **92.23% of lines** (7,726/8,377) and
**79.41% of branches** (1,396/1,758), leaving **651 lines and 362 branches**.
There are no production exclusions. This adds 33 covered lines and 15 branches
to the [adoption record](../coverage-boundary-20261031/README.md).
The 100% gate remains open.

All Rust source additions are inside existing excluded test modules or the
process integration test. [Prefix comparisons](production-source.log) confirm
unchanged production code. The collection retains the baseline's live, user
manager and Incus profiles with the same compiler, target and features.
[Compiler identity](compiler.log), `revision`, `source.patch` and
`final-source.patch` identify the execution. The final patch uses write shutdown;
the initial patch preserves the earlier fixture. No profile-mismatch warning
occurred. Cargo build durations are omitted.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat the preceding command with seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-production-final-20261031"
cargo +nightly llvm-cov --color never --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report --lib --bin rs-l2tpd --test process
cargo +nightly llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```

[Final native execution](final-native-coverage.log), [merged report](final-merged.log)
and [counts](counts.log) retain the result. The earlier native report passed
with the initial fixture; its counts match the final collection. These
test additions still need their own CI run after commit.
