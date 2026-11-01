# Resolver identity bytes and static binding

The new live adapter case checks anonymous, link-layer, random and exact raw
DHCPv6 client identifiers. Each configuration sends two Information-Requests
with the same transaction and identity. Anonymous requests have no client
identifier; random DUID-LL addresses have the locally administered/unicast
bits. The resolved configuration identity stays unchanged. A matching Reply
is accepted and installs the advertised DNS server.

The same case checks the static adapter's configured bind device and actual
DNS answers of both families through the controlled server. It reuses the
existing namespace, veth, DHCP and DNS fixtures. Option verification checks
header/body bounds and rejects duplicate client identifiers. 

`revision` identifies `e6fb2f7`; `source.patch` adds one ignored library
test. Shipping logic and public APIs are unchanged. The three controls
replace random/raw identities with anonymity or omit static binding.
Each fails the live case in a disposable container. Controls are restored
before qualification and never enter the profile collector.

The initial command used the wrong module name and selected zero tests.
That result is retained but does not count. Every accepted live command
checks for exactly one passing test.

Ten seeded ordinary suites, ten instrumented library repetitions, three
musl library suites and final common checks pass. The ordinary library has
237 passing cases and 18 ignored; the instrumented library has 21 ignored,
including the three coverage-only startup cases.

Three GNU live cases pass in 4.64, 4.58 and 4.90 s; three musl live cases pass
in 4.57, 4.72 and 4.69 s. Their profiles and logs have no LLVM write error.
Live workloads are serialized and all networks exist only inside disposable
containers. This adds Ubuntu 6.8.0-147 evidence; it does not establish this
new wire case on the other four required kernels.

All 4,295 production function mappings are identical to the preceding
collection. Merged coverage is **97.01% lines** (8,404/8,663) and
**89.89% branches** (1,663/1,850), leaving **259 lines and 187 branches**.
There are no production exclusions, profile mismatches or saturated regions.

The frozen 11bef84 required matrix is running. This positive exchange case
does not prove rejection of every malformed or mismatched Reply.
Complete clause/history/resource proof and 100% coverage remain open.

```sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib
# Repeat three times.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-e27-queued-deletion-20261101"
TEST_SEED=1 cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --lib --branch --no-report
# Repeat seeds 2 through 10.
# UNIT is the exact library executable printed by the corresponding GNU/musl build.
# GNU uses the recorded coverage image and a writable profile directory.
docker run --rm --privileged --network none --mount "type=bind,source=$UNIT,target=/adapter-test,readonly" --entrypoint /adapter-test "$IMAGE" --ignored --exact reconciler::resolvers::tests::released_adapter_preserves_client_identifiers_and_static_device_binding --nocapture
# Repeat three GNU and three musl live cases, serialized.
./test-ci-gates.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
