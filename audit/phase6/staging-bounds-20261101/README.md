# Staging-name bounds and creation refusals

The new staging case occupies the deterministic fake's first seven or eight
temporary names with foreign links. A free eighth name must succeed; eight
collisions must return the bounded refusal without a session or reservation.
A ninth-call error fence verifies exactly eight random-source calls. A fresh
attempt then publishes the session without replacing its tunnel or modifying
the foreign links or their MAC addresses. The configured MAC must be applied
before the rename publishes the interface.

A second case injects EEXIST, ENFILE and EPERM without a name collision.
Each original errno must return without drawing a random name, leaving no
partial session/reservation. The next reconcile must recover on the same
tunnel.

`revision` identifies the base; `source.patch` changes tests only.
Seven-draw and nine-draw controls both fail the boundary case. The errno
replacement control fails the refusal case. All production controls are
restored exactly and their patches still apply cleanly.

Ten seeded library/rule/fake/service suites, ten instrumented session-module
repetitions, three musl library runs and final common checks pass.
The ordinary library now passes 228 cases, with 17 in the separately qualified
serial profile. Common checks include strict maps, warning checks, feature
builds and rustdoc.

```sh
PROPTEST_RNG_SEED=N cargo test --locked --all-features \
  --lib --test rules --test kernel-fake --test service
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib
CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-vrf-inventory-state-20261101" \
cargo +nightly-2026-10-28 llvm-cov --locked --all-features \
  --target x86_64-unknown-linux-gnu --branch --no-report --lib \
  -- reconciler::sessions::wanted_tests --nocapture
./test-ci-gates.sh
```

Compatible profiles cover **8,357/8,660 lines (96.50%)** and
**1,643/1,848 branches (88.91%)**, leaving **303 lines and 205 branches**.
All 3,947 production function mappings match the preceding collection.
There are no profile mismatches, saturated regions or production exclusions;
test-only bodies remain excluded while tests execute.

Shipping code and live fixtures are unchanged. This model package adds no
new live-kernel, Incus or root-systemd result. Complete clause/history proof
and the 100% coverage gate remain open.
