# Deferred MAC changes after device removal

The existing logging test now creates a managed session, defers a MAC change
while its device is up, then removes the device while retaining the session.
Three reconciliations must finish without writing a MAC address or replacing
the session. Exactly one warning identifies the session, the departed device
and the skipped hardware-address change. An unconsumed injected write failure
proves that reconciliation never attempted the write.

This is fake-kernel policy evidence for S12, S19, S20 and G4. It does not add
a live namespace-move or per-distribution manager result. Production code is
unchanged from `revision`; the before/after source patches agree.

Ten native and instrumented model/rule/service/startup repetitions, three
musl model runs, the full native suite, common gates, Rust 1.89 and additional
ARM64/RISC-V64/PowerPC64LE musl compile checks pass. Two independent controls
misreport either the removal reason or the skipped operation; each fails the
intended assertion. Restoring production source makes the focused case pass.

Coverage reaches **8,484/8,687 lines (97.66%) and 1,697/1,852 branches
(91.63%)**, leaving 203 lines and 155 branches. All 4,327 production mappings
are identical to the preceding error-boundary report. There are no production
exclusions, profile mismatches or saturated regions. Earlier production
implementations remain excluded from the collector.

`commands.sh` records the positive commands; control patches and logs retain
the deliberately broken runs. The required-kernel matrix has its own frozen
source and execution scope. Phase 6's complete clause proof and 100% coverage
gate remain open.
