# Shared rule harness and isolated child launches

The library test harness now includes the existing public rule files.
Private cases and public rule cases therefore exercise the same library
instantiations. The external rules target still runs independently, preserving
the public API check. No rule files are copied: a test-only self alias and
module include reuse them, and the property helper imports from its parent.

This matters because LLVM's current upstream
[generic-group summary](https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/tools/llvm-cov/CoverageSummaryInfo.cpp)
merges [coverage maxima](https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/tools/llvm-cov/CoverageSummaryInfo.h),
rather than covered-path unions across instantiations. The local records
retain the actual pinned-toolchain totals; no report or exclusion rule changes.

## Isolation and failures

The first combined run finds the no-log-sink case observing the rule logger's
Debug level. That case now checks the absent sink in a fresh subprocess.
The next parallel run fails three fake lifetime assertions; the same combined
suite passes serially. Child launches can temporarily retain fake socket
references, as the existing isolated-runner policy documents.

The no-sink, adapter-drop and strict-socket-option cases now join that serial
profile. Their child filters include `--ignored`, so the cases actually
execute. Three GNU and three musl runs pass all **17 serial cases**.
They remain required in the live guest runner; they are not retired.

Clippy also catches an external non-exhaustive match whose wildcard becomes
unreachable inside the defining crate. Its test now selects the two notice
streams with the same explicit Monitor/L2tp inputs, without that wildcard.
The initial logger, parallel-lifetime and Clippy failures are retained.

## Qualification

Ten seeded GNU repetitions pass the combined library, external rules, fake
conformance and service suites. Ten instrumented combined-library repetitions
pass. Three musl combined-library/external-rule runs pass. The ordinary library
now passes **226 cases**, with 17 deferred to the serial profile; the external
rules target passes all 88. Each serial run uses a disposable Docker container
with `--privileged --network none`, the appropriate GNU or musl image and
`--ignored --nocapture --test-threads=1`.

Declaration lists from both targets compare exactly after removing the library
module prefix: all **88** public rule declarations appear once in each.
Final common checks pass Clippy, feature builds, GNU/musl ordinary tests, strict
maps and rustdoc. `revision` identifies the base; `source.patch` reconstructs
the test-only changes.

```sh
PROPTEST_RNG_SEED=N cargo test --locked --all-features \
  --lib --test rules --test kernel-fake --test service
cargo test --locked --all-features --target x86_64-unknown-linux-musl \
  --lib --test rules
CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-vrf-inventory-state-20261101" \
cargo +nightly-2026-10-28 llvm-cov --locked --all-features \
  --target x86_64-unknown-linux-gnu --branch --no-report --lib \
  -- --test-threads=1
./test-ci-gates.sh
```

## Coverage and remaining scope

The merged report reaches **8,354/8,660 production lines (96.47%)** and
**1,642/1,848 branches (88.85%)**, leaving **306 lines and 206 branches**.
Both denominators are unchanged. No production exclusions, profile mismatches
or saturated regions appear; test-only bodies remain excluded while tests run.

All mappings common by name remain unchanged. Three placeholder instantiations
are replaced by concrete FakeKernel instantiations with identical mapping
shapes, checked pair by pair; one default resolver-trait instantiation is added.
The catalog changes from 3,946 to 3,947 entries. The comparison JSON retains
these changes instead of claiming an identical catalog.

Shipping code and kernel behavior are unchanged. The separately completed
frozen matrix predates this harness and its 17-case profile. Full clause/history
proof, final qualification and the 100% coverage gate remain open.
