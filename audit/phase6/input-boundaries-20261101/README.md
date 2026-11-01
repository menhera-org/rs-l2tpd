# Tunable and empty-path boundaries

The tunable test refuses an unsupported sysctl name, an unsupported value,
and an expired deadline. The configuration test treats an empty pathname as
absent, returns no lookup/configuration problem and yields the default
configuration. Tests are placed after production functions to preserve
their source locations.

`revision` identifies `45c1b43`; `source.patch` adds only these two tests.
Shipping logic and public APIs are unchanged. Ordinary binary counts rise
from 59 to 61 passing cases; the same four privileged cases remain ignored.

Each `*-control-from-base.patch` applies independently to `revision` and
reconstructs its named test with one fault. The name, value and deadline
controls each fail the tunable test. They run only inside disposable,
networkless containers, with bindv6only confirmed zero before the test;
bypassing a guard therefore reaches the real writer without host sysctl
access. The false-presence control fails the empty-path assertion. All
controls are restored before qualification and never enter the collector.

Ten ordinary and ten instrumented full binary suites pass, alongside three
full musl binary runs and final common checks. Common checks cover strict
maps, feature builds, GNU/musl ordinary tests, Clippy and rustdoc.
The frozen production matrix remains at 11bef84; the new tests do not alter
its shipping source or live fixtures.

Merged coverage is **96.93% lines** (8,397/8,663) and **89.84% branches**
(1,662/1,850), leaving **266 lines and 188 branches**. There are no
production exclusions, profile mismatches or saturated regions. All 4,286
function names retain identical source regions and filenames. The binary
test instance of tunable::write now exposes three branch records;
4,285 full mappings are identical. Denominators are unchanged.

This case checks input rejection and empty-path handling. It does not add
a privileged sysctl-write result; earlier live handshakes retain that scope.
Complete clause/history/resource proof and 100% coverage remain open.

```sh
TEST_SEED=1 cargo test --locked --all-features --bin rs-l2tpd
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd
# Repeat three times.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-e27-queued-deletion-20261101"
TEST_SEED=1 cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --bin rs-l2tpd --branch --no-report
# Repeat seeds 2 through 10.
./test-ci-gates.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines

# Each tunable control: build, then run only its named test in a container.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd --no-run
# BINARY is the exact executable printed by that command; IMAGE is recorded in image.log.
docker run --rm --network none --mount "type=bind,source=$BINARY,target=/boundary-test,readonly" --entrypoint /bin/sh "$IMAGE" -ec 'test "$(cat /proc/sys/net/ipv6/bindv6only)" = 0; exec /boundary-test --exact tunable::tests::unsupported_or_expired_writes_are_refused --nocapture'
```
