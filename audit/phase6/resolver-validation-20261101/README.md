# Resolver validation and identity checks

Three new model cases exercise the reconciler's resolver boundary using
valid configurations and controlled kernel replies:

- Missing and VRF bind links, failed dependency/spec lookups, recovery,
  non-UTF-8 interface names and an obsolete tunnel identifier.
- Link-local scope from the bind link, explicit zone or both; duplicate
  dependency elimination; replacement under the same name; refused, missing
  and VRF zones; refusal when the zone is another link.
- Default, anonymous, random and explicit DHCPv6 identities for DHCPv6 and
  unified discovery. A missing MAC or EIO refuses default DHCPv6, permits
  unified RA fallback and recovers after the MAC is available. RA leaves
  the injected MAC-query failure unconsumed.

The assertions check exact scope indexes, ports, bindings and client settings,
alongside specific refusals. They do not claim new DHCPv6 wire-level proof
for those identities. Production code, dependencies and kernel fixtures are
unchanged.

## Controls and qualification

`revision` identifies the base; `source.patch` reconstructs the three tests.
`scope-control.patch` disables the zone/bind comparison; its test fails by
accepting the other link. `identity-control.patch` replaces the random identity
with anonymous; its test fails on the resulting resolver settings. Both apply
to `revision`, and neither is shipping.

An initial assertion expected libc's wording for EIO. The report deliberately
uses nix's errno description, `EIO: I/O error`; the corrected assertion checks
the errno prefix. `initial-diagnostic-assumption.log` retains the failure.

Ten seeded library/fake/rule/service repetitions and ten instrumented
repetitions of the new cases pass. Three musl library runs pass. Common checks
pass warning checks, feature builds, GNU/musl ordinary tests, strict maps and
rustdoc. The ordinary library suite now has 140 passing cases and 14 live
cases skipped by that command.

```sh
PROPTEST_RNG_SEED=N cargo test --locked --all-features \
  --lib --test kernel-fake --test rules --test service
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib
CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-vrf-inventory-state-20261101" \
cargo +nightly-2026-10-28 llvm-cov --locked --all-features \
  --target x86_64-unknown-linux-gnu --branch --no-report --lib \
  -- reconciler::resolvers::tests::validation --nocapture
./test-ci-gates.sh
```

Fresh coverage is **8,335/8,660 lines (96.25%)** and **1,630/1,848 branches
(88.20%)**, leaving **325 lines and 218 branches**. All 3,937 production
function mappings match the preceding collection, with no profile mismatches,
saturated regions or production exclusions. Test-only bodies remain excluded
while their tests execute.

The required matrix continues in its frozen production checkout. This
test-only package adds no new live-kernel or Incus result and does not pass
the remaining complete-clause and 100% coverage gates.
