# Fake-kernel control boundaries

Three cases validate the model used by the policy tests:

- An address on a VRF itself is usable inside that domain and excluded from
  the default domain. A deliberately stale address control with no link is
  ignored; it becomes usable when that index appears.
- An unregistered socket keeps its identifier reserved while an external
  descriptor remains. Closing the last external descriptor permits reuse,
  and a later tick must preserve the replacement.
- Ordinary links can change MAC while up. An up L2TP session accepts its
  existing MAC, refuses a change with EBUSY, and accepts the change when
  down. Cleanup must preserve the unrelated ordinary link.

The stale-address case exercises intentionally incomplete model input;
it makes no claim that a live kernel installs an address without a device.
All cases use existing public fixture controls. No model implementation or
shipping code changes.

Four controls fail: excluding the VRF's own address, dereferencing the stale
index, retaining a dead unregistered socket's reservation, and applying the
L2TP MAC restriction to ordinary links. Their production patches are restored
exactly and still apply cleanly.

Ten ordinary and ten instrumented repetitions pass all three cases.
Three full musl fake suites pass all ten cases, and final common checks pass.

`revision` identifies the base; `source.patch` adds only these fixture tests.

```sh
cargo test --locked --all-features --test kernel-fake -- model_ --nocapture
cargo test --locked --all-features --target x86_64-unknown-linux-musl --test kernel-fake
CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-vrf-inventory-state-20261101" \
cargo +nightly-2026-10-28 llvm-cov --locked --all-features \
  --target x86_64-unknown-linux-gnu --branch --no-report \
  --test kernel-fake -- model_ --nocapture
./test-ci-gates.sh
```

Compatible profiles cover **8,375/8,660 lines (96.71%)** and
**1,655/1,848 branches (89.56%)**, leaving **285 lines and 193 branches**.
All 3,952 production mappings are identical. There are no profile mismatches,
saturated regions or production exclusions.

These model cases add no live-kernel, QEMU, Incus or root-systemd result.
Complete clause/history proof and the 100% gate remain open.
