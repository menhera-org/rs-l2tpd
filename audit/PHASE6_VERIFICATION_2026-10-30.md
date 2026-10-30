# Phase 6 verification — 2026-10-30

Status: **in progress; Phase 6 is not complete**. No strict CI flag has
been enabled. The entry commit was `886eae9`.

## Gate status

| Gate/package | Executed evidence | Status |
|---|---|---|
| Source link, P1 | `SRCLINK_STRICT=1 cargo test --locked --all-features --test srclink -- --nocapture`: 4 passed, 0 failed; 41 active facts, 36 production-cited, 5 classified facts, no uncited production function | Local check passes; CI/determinism gate remains open |
| Rule map, P1 | Strict entry run: 340 rules, 330 active, 101 without citations | Open |
| Scenarios, P2 | Scenario construction underway; partial runs are not the whole gate | Open |
| Required kernel matrix, P3 | Not run in Phase 6 | Open |
| Coverage, P4 | Native baseline recorded separately below; live profiles not merged | Open |
| Incus, P5 | Access available; scenario not yet run | Open |
| Root system-unit sandbox, P6 | Not yet run | Open |

All executed checks in this record used host kernel
`6.8.0-147-generic`. This is execution evidence, not a claim that the
moving required kernel set has been re-resolved or verified.

## P1 source-link classification

On 2026-10-30 the maintainer selected explicit evidence-map classification
for K13, K14, K33, K38 and K40. No production citation was fabricated.
The source-link check now reads the scope column of
`docs/kernel-evidence.md`: linux facts require production citations;
delegated/source-only facts require nonempty evidence and a test
declaration citation. Missing/invalid scopes and duplicate evidence rows
fail. Both traceability tools use the same test-declaration scanner;
ordinary comments and helper-function comments do not count.

The new live K33 test lowers an IPv6-addressed device, observes address
removal through the production address dump, then repeats with
`keep_addr_on_down=1` and observes preservation. The existing released
unified-resolver test gains K13/K38 citations for its actual DHCPv6 bind
and Reply exchange. K14/K40 retain the released RA adapter's existing
citations; its raw-source run with `accept_ra=0` does not claim to execute
capability-denied netlink fallback.

Live build command (all features, musl):

```sh
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --test kernel-linux --no-run
```

The resulting executables were run in
`docker run --rm --privileged --network none`, with the checkout mounted
read-only at its absolute path and image `rs-l2tpd-audit-vm:local`.
Exact test filters, each with `--ignored --exact <filter> --nocapture`:

- `lowering_a_device_discards_ipv6_addresses_unless_preserved`: 1 passed,
  0 failed, 14 filtered out, 0.03 s.
- `reconciler::resolvers::tests::released_ra_adapter_preserves_omitted_addresses_and_bounds_its_repository`:
  1 passed, 0 failed, 83 filtered out, 0.05 s.
- `reconciler::resolvers::tests::released_unified_adapter_enables_per_family_failure_fallback`:
  1 passed, 0 failed, 83 filtered out, 0.05 s.

Logs:

- [Strict entry rule map](phase6/entry/rulemap.log).
- [Strict entry source link, before correction](phase6/entry/srclink.log).
- [Strict source link with classifications](phase6/entry/srclink-classified.log).
- [Live build](phase6/entry/build-evidence-live.log).
- [Classified-fact live execution](phase6/entry/classified-facts-live.log).
- [Both traceability tools, report mode](phase6/entry/traceability.log).
- [Clippy, all targets/features, warnings denied](phase6/entry/clippy.log).

## Coverage baseline

`cargo-llvm-cov` 0.9.1 was installed for this work, with nightly's LLVM
tools. The nightly manifest date is 2026-10-28
(`rustc 1.101.0-nightly (41089d07a 2026-10-27)`).
The native run used all features, target
`x86_64-unknown-linux-gnu`, and branch instrumentation:

```sh
cargo +nightly llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly llvm-cov report --target x86_64-unknown-linux-gnu --branch
```

Baseline only: 7,586/9,937 lines (76.34%) and 1,184/1,772 branches
(66.82%). The report is not a combined native/live result and no
coverage exclusion has been introduced. Ignored live tests remain
unexecuted by this native command, as the log records.

- [Native tests with coverage](phase6/entry/coverage-native.log).
- [Native coverage report](phase6/entry/coverage-native-report.log).
- [Coverage tool installation](phase6/entry/install-coverage.log).
- [LLVM tools installation](phase6/entry/install-llvm-tools.log).

## Remaining work and exclusions

P1's remaining behavioral-rule cases, the full scenario suite, repeated
determinism runs, the required matrix, merged 100% coverage, Incus,
the root system unit, and final documentation/CI integration remain open.
No scenario has been counted as skipped-and-passed. No coverage exclusions
have been approved or used.
