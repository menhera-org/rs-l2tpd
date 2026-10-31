# Remove redundant resolver correction

Literal-address processing already removes and reports `resolver_name`.
`TunnelConfig::check` reports that field only for a literal peer, so the
later tolerant-correction arm cannot encounter it. The correction closure
now only applies the remaining peerless fallback. No panic or coverage
exclusion replaces the removed arm.

The existing regression now checks both correction fields and their order,
rather than only counting two problems. Host-name correction still retains
the configured resolver; literal family mismatch still reports the unused
resolver and applies the peerless family correction.

## Verification

`revision` plus `source.patch` identifies the tested source. Common checks,
Clippy and ten seeds pass: 127 ordinary library, 51 ordinary binary,
68 shared fake plus four fake-only, 81 rules and 29 service cases, plus
eleven startup/resolver/descriptor fault paths. The binary suite also runs
the six barrier fault paths.

This shipping-source change gets a fresh coverage target, without profiles
from the previous production implementation. GNU live profiles pass fourteen
library, twenty Linux, five review and three privileged binary cases.
All 28 process cases and 26 normal scenarios pass; scenarios take 159.59
seconds. The real user-manager case passes. Instrumented unprivileged Incus
passes in 19.70 seconds and exports seven daemon profiles.

The unmodified musl root-systemd guest passes in 29.15 seconds, without
unit drop-ins (`root-systemd/`). This verifies the supplied sandbox and
cleanup on Ubuntu 6.8.0-147-generic, not other distribution userspaces.

Fresh nightly-2026-10-28 / cargo-llvm-cov 0.9.1 coverage is **95.01% lines**
(8,099/8,524) and **84.92% branches** (1,537/1,810), leaving **425 lines and
273 branches**. There are no production exclusions, profile mismatches or
saturated inferred regions.

The preceding required matrix uses the I/O source, so this collection does
not establish final consistent-source five-target qualification. An individual
Incus pass does not resolve the staged-MAC H11 decision. The upstream nix
signal-error fix also awaits release. Complete clause/resource/event-cost
proof and 100% coverage remain open; retained current-host address/member
state still needs its G23 bound resolved.

CI for the preceding barrier source passes both jobs in
[run 41249951213](https://github.com/menhera-org/rs-l2tpd/actions/runs/41249951213),
about seventeen minutes overall. Logs omit Cargo build durations and
user-manager resource accounting.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-config-correction-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/config-correction-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/process-errors-20261031/run-live.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
