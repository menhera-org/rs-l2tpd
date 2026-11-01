# VRF address-family and member-removal events

A new rule case keeps IPv4 and IPv6 tunnels bound to one VRF, an unrelated
unbound tunnel, and two existing sessions. Removing a member's IPv4 or IPv6
address reconnects exactly that family's tunnel and selects the other
member's source. Removing the last address also exercises empty address-cache
cleanup. The unrelated tunnel and both session identities survive.

Re-adding an IPv4 address must cause a reconnect; E6 does not require the new
address to become preferred. The initial draft assumed that ordering and
failed; its log is retained. The corrected assertion checks the reconnect
and an available connection. Removing the member carrying the old source
then forces the remaining IPv4 source, leaves IPv6 disconnected, and
reconnects both bound tunnels without replacing them. A new member/source
restores IPv6 within the one-second retry bound. No unrelated socket or
session is recreated or deleted.

## Verification

`revision` plus `source.patch` reconstructs the fixture. Only an existing
rule-test file changes; shipping code, Linux adapters and specifications are
unchanged. Ten seeded ordinary suites pass (128 library, 51 binary, 68 shared
fake plus five fake-only, 84 rules and 30 service cases, with startup faults).
Three musl 84-case rule suites pass. Common checks and the native coverage
run pass.

Production function, region and branch mappings match the preceding
uncertain-session collection exactly. Its compatible broader live profiles
remain merged. Coverage is **95.27% lines** (8,117/8,520) and **86.01% branches**
(1,555/1,808), leaving **403 lines and 253 branches**. The event module reaches
96.30% lines and 91.33% branches. There are no production exclusions,
profile mismatches or saturated inferred regions. Logs omit Cargo build
durations.

Both jobs pass for the current shipping implementation in
[CI run 41256606416](https://github.com/menhera-org/rs-l2tpd/actions/runs/41256606416).
The new fake-only rule assertion is separate from that run. The required
matrix is running in a frozen bdf81b5 checkout; this later rule case is absent
from that snapshot, and no matrix success is claimed here. H11/G23 decisions,
the upstream nix release, final qualification, complete clause/resource/
event-cost proof and 100% coverage remain open.

```sh
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --test rules
# Repeat three times.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-lifetime-state-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
