# Refused inheritance and incomplete kernel records

A live case hands the Linux backend a Unix socket, a regular descriptor,
IPv4/IPv6 UDP sockets and IPv4/IPv6 TCP sockets. It requires the precise
family, non-socket, encapsulation or socket-type refusal. Unix peer EOF
proves that refusal consumes the handed descriptor; independent Internet
socket observers remain usable. All networking stays in the test's disposable
namespace.

Parser assertions now reject each missing session-identity field, cookies
longer than the kernel's eight-byte maximum, and truncated generic-netlink
deletion messages. Missing fields return EPROTO; malformed notifications
report loss. Oversized-cookie objects are defensive parser inputs, not a
claim that a supported kernel emits them.

## Verification

`revision` plus `source.patch` reconstructs the source. The focused live case
passes three ordinary GNU, three musl and three instrumented GNU repetitions
on Ubuntu 6.8.0-147-generic. Native parser tests, ten seeds, Clippy and common
checks pass. ARM64, RISC-V64 and PowerPC64LE musl all-target builds pass;
live architecture testing is limited to x86_64.

The native run has 127 ordinary library cases and fourteen ignored cases.
The expanded Linux suite has twenty cases; only its new case is rerun here.
The earlier full live, process, scenario, user-manager and Incus profiles are
retained from the [process/service collection](../process-errors-20261031/README.md).
Only excluded test bodies change, and the production function, region and
branch mappings match exactly before and after (`mapping-check.log`).
No profiles with a different production mapping are merged.

Merged production coverage is **94.90% lines** (8,093/8,528) and **84.48%
branches** (1,529/1,810), leaving **435 lines and 281 branches**. There are
no production exclusions, mismatches or saturated inferred regions.
The initial `build.log` names a nonexistent Cargo target; the corrected
`build-final.log` builds `kernel-linux` and supplies the executed binary.

The five-target matrix completed separately with the preceding I/O source
and fixture set. This new twenty-case Linux fixture set has not run on all
five targets. H11/P5, final consistent-source qualification, complete clause
and resource proof, and 100% coverage remain open.

```sh
cargo test --locked --all-features --lib kernel::linux::l2tp::tests -- --nocapture
cargo test --locked --all-features --test kernel-linux --no-run
# Run the printed executable inside a disposable --network none container:
# --ignored --exact unrelated_inherited_descriptors_are_refused_and_consumed --nocapture
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-process-errors-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
# Run the focused instrumented case with a unique LLVM_PROFILE_FILE prefix.
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
