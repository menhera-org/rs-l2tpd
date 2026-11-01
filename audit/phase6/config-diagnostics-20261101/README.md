# Configuration port and diagnostic cases

The resolver-address table now rejects empty, overflowing and very long
ports in IPv4 and bracketed IPv6 inputs. A new diagnostic case checks empty,
hyphen, underscore, dotted and newline-containing unknown keys: bare keys
stay bare; the others are quoted and escaped. It also checks the exact
explanation when an irrelevant DHCPv6 identity is corrected to its default.

`revision` plus `source.patch` reconstructs the tests. Production source,
dependencies, specifications, kernel adapters and guest fixtures are
unchanged. The new body is in the existing test-only instrumentation
exclusion; it still executes. The collection host reports
`6.8.0-147-generic`.

All 45 focused configuration tests pass. Ten seeded ordinary suites pass:
133 library, 51 binary, 68 shared fake plus six fake-only, 88 rules,
30 service cases and startup faults. Three musl library repetitions and
mandatory common strict checks, feature builds, Clippy and rustdoc pass.

Production function, region and branch mappings match the preceding
collection exactly. Compatible native profiles add two covered lines and
two branch outcomes. The configuration text parser reaches 100% lines,
regions and branches. Overall coverage is **95.62% lines** (8,202/8,578)
and **86.83% branches** (1,589/1,830), leaving 376 lines and 241 branches.
There are no production exclusions, profile mismatches or saturated inferred
regions. Cargo build durations are omitted from retained logs.

The frozen required-kernel matrix, compatible nix release, complete
clause/resource/event-cost proof and 100% report remain open.

```sh
cargo test --locked --all-features --lib config::tests::
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib
# Repeat three times.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-streamed-inventories-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --json --output-path /tmp/phase6-config-diagnostics-coverage.json
```
