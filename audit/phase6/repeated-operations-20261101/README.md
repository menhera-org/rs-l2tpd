# Repeated scoped connects and renames

Two existing shared conformance cases now check repeated operations. After
a scoped IPv6 link-local connect replaces a VRF binding with its member
(K27), connecting to the same scoped peer again must succeed with the same
source. After renaming an active session device, applying its current name
again must succeed and preserve its index/name lookup (K31).

Only `tests/kernel/conformance.rs` changes. The fake and Linux implementations
run the same assertions. `revision` plus `source.patch` reconstructs the
source. No daemon, adapter, dependency or specification changes.

## Verification

All seventeen shared cases pass three times per ABI (GNU and musl) with
CAP_NET_RAW present and three times with it absent, on Ubuntu
6.8.0-147-generic. Each invocation uses a fresh disposable Docker container
with `--network none`; capability markers verify the effective setting.
The initial twelve-invocation driver reached its 120-second timeout after
eleven successful cases. Its last invocation produced no output, and no
container remained. Only that incomplete invocation was repeated, with a
60-second command limit, and passed. These driver limits are separate from
the tests' own deadlines.

Ten seeded library/binary/fake/rules/service/startup runs pass, including all
four fake capability/deletion combinations. The shared fake case uses its
fixed seed of seven; the seeded planner suites consume TEST_SEED. Common
checks and standalone documentation links pass.

A native coverage run and three instrumented live shared-suite runs pass.
Production function, region and branch mappings match the preceding alias
collection exactly, allowing its broader live/process/normal/manager/Incus
profiles to remain in the merge. No earlier production implementation is
merged. Coverage is **95.03% lines** (8,099/8,523) and **85.03% branches**
(1,539/1,810), leaving **424 lines and 271 branches**. The fake retains 100%
lines and reaches 94.93% branches. There are no production exclusions or
saturated inferred regions. Cargo build durations are omitted from logs.

Both jobs pass for the preceding daemon implementation in
[CI run 41253873439](https://github.com/menhera-org/rs-l2tpd/actions/runs/41253873439),
about sixteen minutes overall. The current shared assertions still require
final five-target qualification. H11/G23 decisions, the upstream nix release,
full clause/resource/event-cost proof and 100% production coverage remain open.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --test kernel-linux --no-run
cargo test --locked --all-features --target x86_64-unknown-linux-musl --test kernel-linux --no-run
# Each printed Linux executable runs in a fresh networkless container:
# --ignored --exact conformance_on_the_linux_kernel --nocapture
# Privileged control: --privileged
# Without CAP_NET_RAW: --cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-drop NET_RAW
#                     --security-opt seccomp=unconfined --security-opt apparmor=unconfined
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-alias-state-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
