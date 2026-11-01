# Discovery retry identity and dependency checks

The existing rule-suite resolver adapter can now report partial discovery.
A five-outcome case checks the reconciler's thirty-second retry:

- Discovery completes before the deadline: retain the lookup identity.
- Discovery stays partial: restart the lookup at the deadline.
- The resolver device disappears: stop the obsolete lookup, retry after
  thirty seconds and recover when the device returns.
- A new device takes the same name: restart even though the resolver
  specification is unchanged, because its device index differs.
- Resolver startup is refused: stop the failed incarnation, preserve the
  accepted peer, then recover on the next thirty-second retry.

Every outcome preserves the tunnel socket and selected peer/source.
Completed discovery remains stable through another thirty seconds.
The model's discovery state is controlled explicitly; the separate released
iphost live tests establish real shared-job recovery.

## Controls and verification

The first isolated control disables reuse of a completed lookup. The case
fails because its identity changes. The second omits the dependency-index
comparison; the replacement-device case fails because its identity stays
unchanged. Both patches remain unapplied to shipping code.

The first fixture expected no remaining deadline after completed discovery.
It failed because active resolvers still need the existing one-second answer
poll. The final assertion checks stable lookup identity across another
thirty seconds instead; `first-fixture.log` retains that diagnostic.
The first common check also rejects two cloned slice assertions; the final
spelling uses `std::slice::from_ref`. The seeded, musl, native and control
runs are repeated on that final test source.

`revision` plus `source.patch` reconstructs the final test and adapter.
Production code, Linux adapters, dependencies, specifications, coverage scope
and guest fixtures are unchanged. The collection host reports
`6.8.0-147-generic`.

Ten seeded suites pass: 132 ordinary library, 51 binary, 68 shared fake plus
six fake-only, 88 rules, 30 service cases and startup faults. Three musl
88-rule repetitions and mandatory common strict checks, feature builds,
Clippy and rustdoc pass. Cargo build durations are omitted from retained logs.

All retained production function, region and branch mappings match.
The sole removed mapping is the rule adapter's instantiation of the default
`Resolve::retry_discovery` body, which it now overrides. Other implementations
still cover that unchanged default. No production mapping is added or
changed. The broader streamed-inventory profiles remain compatible.

The merged report is **95.59% lines** (8,200/8,578) and **86.72% branches**
(1,587/1,830): 378 lines and 243 branches remain. Seven additional lines and
seven branch outcomes are covered. No production exclusions, profile
mismatches or saturated inferred regions.

The frozen five-target matrix on `012764f`, compatible nix release,
complete clause/resource/event-cost proof and 100% coverage remain open.
This model test does not replace live discovery qualification.

```sh
cargo test --locked --all-features --test rules discovery_retries_preserve_completed_jobs_and_revalidate_device_incarnations -- --nocapture
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --test rules
# Repeat three times.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-streamed-inventories-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --json --output-path /tmp/phase6-discovery-coverage.json
# Each control separately, only in an isolated copy with the final test:
git --no-pager apply negative-control.patch
cargo test --locked --all-features --test rules discovery_retries_preserve_completed_jobs_and_revalidate_device_incarnations -- --nocapture
# Expected: completed-lookup identity failure.
# Restore production source, then:
git --no-pager apply dependency-control.patch
cargo test --locked --all-features --test rules discovery_retries_preserve_completed_jobs_and_revalidate_device_incarnations -- --nocapture
# Expected: replacement-device identity failure.
```
