# Closed socket handles and fake-kernel observations

A closed local socket handle must return EBADF even while another descriptor
keeps its tunnel alive. The fake retained socket metadata for that lifetime,
but `only_v6` and the first `connect` lookup did not check local ownership.
The baseline returned ENOPROTOOPT (92) and EAFNOSUPPORT (97), respectively,
instead of EBADF (9). Both failing runs are retained. Two ownership filters
correct the shared fake implementation; no Linux-backend or daemon policy
changes are needed.

The existing shared adoption case now checks all five socket operations
against the closed handle before adopting the external descriptor. It still
requires the tunnel/session identity to survive adoption and disappear after
the last close. The unchanged Linux backend passes the new assertions in
`baseline-linux.log` on Ubuntu `6.8.0-147-generic`. Other required targets
still need the final consistent-source matrix.

Four additional fake-only cases check external-reference frame delivery,
invalid requests and metadata mismatch refusal, link-local scope and cached
source release, and proof isolation when one of two tunnels is replaced.
Fixture metadata checks are deliberately stricter than kernel registration;
their EINVAL assertions are not presented as Linux behavior.

## Verification

All features are enabled. `revision` plus `source.patch` reconstruct the source.
Common checks and all ten seeds pass: 122 ordinary library cases, the 68 shared
conformance invocations plus four fake-only cases, 80 rules, 28 service cases
and eight startup/resolver fault paths per seed. Binary checks pass 45 ordinary
cases; four privileged/manager cases execute separately. Formatting, Clippy,
ShellCheck, feature builds, strict maps, musl process/startup checks and
warning-denied documentation pass.

Fresh GNU coverage uses nightly-2026-10-28, cargo-llvm-cov 0.9.1 and ordinary
per-process profiles with the existing single-threaded `_exit` flush.

| Profile on Ubuntu 6.8.0-147-generic | Result |
|---|---|
| GNU native/live | Ordinary suites, 12 live library, 19 kernel, five review and three privileged binary probes pass |
| Full process suite | 27 pass |
| Normal scenarios | 26 pass in 157.31 seconds |
| Real user manager | FD-store processing barrier and address-family checks pass |
| Instrumented unprivileged Incus | Full case passes in 14.60 seconds; seven daemon profiles exported |

Incus observes concurrent udev EBUSY and twice-stable ordered persistent
assignment. This individual pass does not close the
[staged-MAC issue](../staged-mac-override-20261031/README.md). The unmodified
P5 case is not rerun pending that decision. P6's unmodified root-systemd
[Store profile](../store-cost-20261031/README.md) remains applicable: this
batch changes only the fake backend and tests. The shipping Linux backend,
service and binary sources are unchanged.

Fresh coverage is **93.81% lines** (8,000/8,528) and **82.37% branches**
(1,486/1,804), leaving **528 lines and 318 branches**. The fake backend's
missing executable lines fall from 32 to four. Fifty-one test-only modules
and one helper exclude instrumentation while tests execute; no production
path is excluded. The report has no mismatch warning or saturated inferred
region. Earlier-source profiles are not merged.

H11/P5, full clause/resource/event-cost proof, 100% coverage and the final
consistent-source five-target matrix remain open. Logs omit Cargo build
durations and user-manager resource accounting.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-fake-handles-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/fake-handles-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/coverage-simplify-20261031/run-live-normal.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
