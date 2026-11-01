# Session creation and late ownership races

These service tests change real fake-kernel state at controlled boundaries:

- A foreign link takes the requested name after the availability check. The
  daemon must stage its session without changing the foreign link or MAC,
  then publish the same session when the name becomes free.
- Ownership evidence disappears between MAC application and publication.
  Both lifetime loss and removal followed by foreign index reuse must prevent
  publication of that index. Bounded retries must recover on a fresh index;
  the reused foreign link and MAC must survive recovery and shutdown.
- A published session loses its proof before a requested rename. Neither that
  rename nor a later configured MAC change may alter the unmanageable device.

The proof hook delegates to the real fake's proof implementation after a
one-shot state change; it does not invent a proof result. The name race uses
the existing creation barrier and explicitly advances the fake retry clock.
Its convergence and recovery waits are bounded.

`revision` identifies the base; `source.patch` changes only the service test.
The first name-race attempt omitted the fake-clock advance and timed out;
`initial-unadvanced-clock.log` retains that failure. The first lost-proof
control exposed a fixture assertion poisoning the kernel mutex, followed by
a cleanup panic. Its excerpt is retained. The fixture now releases the
mutex before resuming an assertion's unwind. Both lost-proof tests then
fail normally under the broken control, without aborting cleanup.

All three controls fail: ignoring late proof loss, ignoring late removal,
and refusing a creation-name collision instead of staging. Their production
patches are restored exactly. Ten seeded library/rule/fake/service suites,
ten instrumented service runs, three musl service runs and final common
checks pass. Every service run executes all 35 cases.

```sh
PROPTEST_RNG_SEED=N cargo test --locked --all-features \
  --lib --test rules --test kernel-fake --test service
cargo test --locked --all-features --target x86_64-unknown-linux-musl --test service
CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-vrf-inventory-state-20261101" \
cargo +nightly-2026-10-28 llvm-cov --locked --all-features \
  --target x86_64-unknown-linux-gnu --branch --no-report --test service -- --nocapture
./test-ci-gates.sh
```

Compatible profiles cover **8,362/8,660 lines (96.56%)** and
**1,645/1,848 branches (89.02%)**, leaving **298 lines and 203 branches**.
All 3,947 preceding production mappings are unchanged; five callback
instantiations are added. There are no mismatches, saturated regions or
production exclusions.

Shipping code and live fixtures are unchanged. This package adds no live
kernel, Incus or root-systemd result. Complete clause/history proof and the
100% coverage gate remain open.
