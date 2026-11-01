# Uncertain session creation and event-scan recovery

The new unit case pauses at the staging/verification boundary after a
creation timeout. It covers eight combinations: direct or configured-MAC
publication, creation absent or completed before verification, and inline or
queued deletion. An EIO scan must retain the uncertain record and creation
name without deleting anything. A later complete scan permits exactly the
verified name deletion when creation completed, then releases the reservation
after absence is confirmed. Re-creation preserves the parent socket and
publication rules. The completed outcome is modeled in the fake; this is
not a live netlink reply-loss experiment.

The public reconciler case checks that a timed-out missing creation does not
publish an interface or block its sibling, and retries without deleting the
sibling or parent. The event tests now include a failed L2TP session query,
with identity/readiness preserved until resync completes. A new VRF-inventory
failure keeps monitor recovery pending and ultimately selects its member's
source on the original socket.

## The test rejects discarded uncertainty

An isolated checkout applies the test and `negative-control.patch`, which
replaces fresh verification with immediate forgetting of an uncertain record.
It fails at `assert!(r.sessions.contains_key(&100))`. The final implementation
passes. This control confirms that the unit case requires retained uncertainty;
its eventual successful re-creation alone would not prove that behavior.
The control mutation is not applied to the working tree.

## Verification and coverage

`revision` plus `source.patch` reconstructs the final tests. Shipping code,
Linux adapters, dependencies, specification and coverage scope are unchanged.
The unit body lives in an existing test-only module excluded from instrumentation;
it still executes in GNU/musl suites.

Ten seeded ordinary runs pass: 128 library, 51 binary, 68 shared fake plus
five fake-only, 83 rules and 30 service cases, with startup faults. Three
musl library/rules repetitions pass (128 ordinary library and 83 rules;
fourteen privileged library cases stay ignored in those native invocations).
Mandatory common checks pass. The focused and negative-control logs are retained.

A native coverage run executes the new cases. Production function, region
and branch mappings match the preceding fresh lifetime collection exactly,
so its live/process/normal/manager/Incus profiles remain compatible. The
merged report reaches **95.20% lines** (8,111/8,520) and **85.56% branches**
(1,547/1,808), leaving **409 lines and 261 branches**. This adds thirteen
covered lines and nine branch outcomes. No production exclusions, mapping
mismatches or saturated inferred regions. Cargo build durations are omitted.

The preceding closed-host-receiver source passes both jobs in
[CI run 41255725188](https://github.com/menhera-org/rs-l2tpd/actions/runs/41255725188).
Current implementation/fixture CI and final five-target qualification remain
separate. H11/G23 decisions, the upstream nix release, complete clause/
resource/event-cost proof and 100% coverage stay open.

```sh
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --test rules
# Repeat three times.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-lifetime-state-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
# Negative control, only in an isolated copy with the final unit test:
git --no-pager apply negative-control.patch
cargo test --locked --all-features --lib timed_out_creation_keeps_uncertainty_until_a_complete_fresh_scan -- --nocapture
# Expected: one failed retention assertion.
```
