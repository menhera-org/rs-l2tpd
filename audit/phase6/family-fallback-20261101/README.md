# IPv4 fallback and peer-family changes

A tunnel whose initial AF_INET6 socket is refused must retain its AF_INET
fallback socket and published session. An IPv6 peer stays disconnected
without an impossible connect attempt; moving to IPv4 connects that same
socket. Returning to IPv6 must disconnect it while a sibling with a fresh
dual-stack socket connects normally. Three fake-clock retries issue no
kernel changes. The original session's index, UP state and MAC survive.
A final IPv4 move reconnects, and removal releases both tunnels and sessions.

Both EAFNOSUPPORT and EPROTONOSUPPORT are exercised. Disabling the
family-compatibility guard fails the no-connect assertion; its production
patch is restored exactly and still applies cleanly.

Ten ordinary repetitions run the case through both library and external
rule harnesses. Ten instrumented library repetitions, three full musl
library/rule suites and final common checks pass. The ordinary library
has 229 passing cases and 17 separately qualified serial cases; both
rule declaration lists compare exactly at 89 entries.

`revision` identifies the base; `source.patch` adds only the shared rule test.

```sh
PROPTEST_RNG_SEED=N cargo test --locked --all-features --lib --test rules \
  -- an_ipv4_fallback_socket --nocapture
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --test rules
CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-vrf-inventory-state-20261101" \
cargo +nightly-2026-10-28 llvm-cov --locked --all-features \
  --target x86_64-unknown-linux-gnu --branch --no-report --lib \
  -- an_ipv4_fallback_socket --nocapture
./test-ci-gates.sh
```

Compatible profiles cover **8,375/8,660 lines (96.71%)** and
**1,651/1,848 branches (89.34%)**, leaving **285 lines and 197 branches**.
All 3,952 production mappings are identical. There are no profile mismatches,
saturated regions or production exclusions.

Shipping code and live fixtures are unchanged. This model case adds no
live-kernel, QEMU, Incus or root-systemd result. Complete clause/history
proof and the 100% gate remain open.
