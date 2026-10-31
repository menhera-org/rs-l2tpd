# Adopted aliases share socket state

The old fake copied a socket's binding, peer and source into an adopted
handle. Linux shares those fields across descriptors of the same socket.
The strengthened shared case passes on Linux and fails on the old fake:
after one handle connects to a mapped peer, its alias incorrectly accepts
a native IPv6 peer instead of EAFNOSUPPORT.

The fake now shares those three fields through the existing Arc/Mutex
pattern. Descriptors and their close state remain separately owned. A
connect through one alias affects the other's refusal; a disconnect clears
both aliases' peer/source/binding state. The binding case also checks that
an alias sees an existing binding and its CAP_NET_RAW replacement restriction,
then permits a fresh bind after disconnect through the other handle.

Linux fixture capability detection now reads the current thread's effective
capabilities instead of assuming CAP_NET_RAW. The complete shared suite also
runs in containers with that capability removed. A separate fake assertion
checks that removing an already absent device produces no duplicate notice.
No dependency or daemon/Linux-adapter behavior changes.

## Verification and profile scope

`revision` plus `source.patch` reconstructs the final source.
`fake-baseline.log` and `fake-baseline-final-case.log` record the old model's
actual assertion failures; `linux-control.log` passes that strengthened case
against Linux before the model fix. Scratch binding checks precede the final
fixture changes.

All ten final seeds pass: 127 ordinary library, 51 ordinary binary,
68 shared fake plus four fake-only, 81 rules and 29 service cases, plus
eleven startup/resolver/descriptor fault paths. Clippy, common checks and
all-target musl builds for ARM64, RISC-V64 and PowerPC64LE pass. Those three
architectures have compile checks, not live runs.

| Ubuntu 6.8.0-147-generic, all features | Result |
|---|---|
| Fresh GNU full live profile | 14 library, 20 Linux, five review and three privileged binary cases pass |
| Full process suite | 28 pass |
| Normal scenarios | 26 pass in 158.92 seconds |
| Final GNU and musl shared conformance | Three repetitions per ABI with CAP_NET_RAW present and three absent pass |
| Final instrumented shared conformance | Three privileged GNU repetitions pass |
| Real user manager | FD-store barrier and address-family checks pass |
| Instrumented unprivileged Incus | Full case passes in 20.88 seconds; seven daemon profiles exported |

Each focused conformance execution is one test declaration containing all
seventeen shared cases. Capability markers explicitly show true or false.
The final alias-binding and capability-detection additions change test code
only; fresh native and focused runs execute them. The full live/normal/manager
collection precedes those final additions. Production function, region and
branch mappings match exactly across that interval (`mapping-check.log`).
No profiles from the preceding production model are merged.

Merged production coverage is **95.03% lines** (8,099/8,523) and **84.97%
branches** (1,538/1,810), leaving **424 lines and 272 branches**. The fake
backend reaches 100% lines and 94.20% branches. There are no production
exclusions, profile mismatches or saturated inferred regions.

The preceding unmodified [P6 run](../config-correction-20261031/README.md)
remains applicable to unchanged daemon/Linux paths. The individual Incus pass
does not resolve the staged-MAC decision. Final five-target fixture
qualification, the H11/G23 decisions, the upstream nix release, complete
clause/resource/event-cost proof and 100% coverage remain open.

Both jobs pass for the preceding configuration source in
[CI run 41251581433](https://github.com/menhera-org/rs-l2tpd/actions/runs/41251581433),
about fifteen minutes overall. Logs omit Cargo build durations and
user-manager resource accounting. Final executions use `native-final.log`,
`seed-final-*.log`, `*-final-allowed-*.log`, `*-final-refused-*.log` and
`instrumented-final-*.log`; earlier records retain their narrower scope.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-alias-state-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/alias-state-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/process-errors-20261031/run-live.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
