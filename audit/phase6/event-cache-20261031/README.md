# Incremental link/address cache maintenance

This package addresses relevant-event cache scans and two cache-retention
defects. It does not close the entire event-cost, resource or Phase 6 gate.
No dependency, public API, kernel operation or timer interval is added.

## Changes and regression evidence

The former `retain_devices` scanned every cached master, VRF and address
after a relevant event or tunnel convergence. It now drains changed device
keys, keeps a reverse member index, and stores addresses per device. Only
actual binding changes prune a master's dependent children; a member move
does not scan unrelated bound siblings. Removed bindings release addresses
and membership records while keeping dependencies of remaining bindings.
Full reconciliation and monitor-loss recovery still inspect global state.
Seeding a newly watched device still requires an address dump.

Two demonstrated defects are corrected:

- Monitor resync cleared the seeded-device set but retained addresses that
  were absent from its complete snapshot. [Before](resync-before.log)
  fails the stale-address assertion; the final case passes.
- When only a VRF member was bound, notifications for unbound siblings
  accumulated mappings because their parent was known as a VRF. After
  10,000 notices there were 10,001 records. [Before](siblings-before.log)
  fails; the final case retains exactly the bound member, with no kernel
  requests and no pending cache work.

[Five final focused cases](cache-relations-final.log) also check binding
removal, moves between VRFs, release of obsolete caches, unchanged foreign
links, and failed address seeding followed by successful monitor recovery.
The latter injects two dump errors because both initial indexing and the
first convergence can seed addresses; [the one-error fixture](cache-failure-fixture.log)
was insufficient and is retained as a fixture failure.

## Diagnostic cost observations

The common workload is 500 identical bound-link notifications after a
fully converged configuration, with no kernel operations permitted:

| Independent bindings | Before, milliseconds | After, milliseconds |
|---|---|---|
| 1 | 2.02 | 1.36 |
| 100 | 40.69 | 1.43 |
| 300 | 126.24 | 1.46 |

[Before](cost-before.log) and [after](cache-relations-final.log) are native
debug-profile observations, not elapsed-time pass conditions or a new SLA.
The original benchmark attempted 2,000 fake tunnels and failed during
fixture convergence before reaching that measurement; [that run](cost-fixture-incomplete.log)
is not counted as a product result. The final workload uses up to 300.

The final case also moves one bound member between two VRFs 500 times,
with the other bindings sharing a parent. Exactly 500 connect operations
occur and the final reverse index contains all current members. Recorded
whole-fake-backend times are 11.07/30.14/60.68 milliseconds at 1/100/300
bindings. These include fake source selection and other convergence work;
they do not establish constant cost for the entire reconnect path. The
broader M16/G12 CPU-cost and G23 history bounds remain separate obligations.

## Rules-suite descriptor coupling

[Repeated runs](rules-reproduction-before.log) reproduce an intermittent
missing replacement socket in the existing DNS-watch re-creation test.
Its first 15 repetitions pass; the sixteenth fails. An earlier attempt
failed at seed 9 after seeds 1–8 passed. No failed run is called a
determinism pass.

The rules suite's logging test launched a subprocess while other tests
owned real Unix descriptors used by the fake lifetime model. The
single-threaded [controlled probe](fork-lifetime-probe.rs) forks with such
a fake tunnel open and holds the inherited descriptor until explicitly
released. [Its result](fork-lifetime-probe.log) shows the tunnel remains
after two virtual seconds and disappears after child exit. The process
spawn creates a real-time dependency outside the fake clock.

The exact scheduling of the original failure was not captured. A
[60-run diagnostic](rules-diagnostic.log) and a
[deliberately delayed pre-exec experiment](fork-window-diagnostic.log)
do not reproduce it. The temporary pre-exec delay is shown in
[its patch](fork-window-diagnostic.patch) and is absent from the final code.
These runs are inconclusive diagnostics, not proof of the root schedule.

The logger now filters by the test's thread ID instead of launching a
child. Another thread emits a matching error and must not affect its
counts. All original episode/severity assertions remain. The suite has
no subprocess launcher after this change; the inherited-reference
mechanism is removed without sleeping or changing the fake lifetime model.
[Ten final runs](rules-final.log), `TEST_SEED=1..10`, each pass all 74
tests. Their 32-seed planner ranges overlap; this is scoped repetition,
not full-suite determinism or CI enablement.

Probe reproduction after an all-feature library build:

```sh
cargo build --locked --all-features --lib
rustc --edition 2024 audit/phase6/event-cache-20261031/fork-lifetime-probe.rs \
  -L dependency=target/debug/deps \
  --extern rs_l2tpd=target/debug/librs_l2tpd.rlib \
  -o /tmp/phase6-fork-lifetime-probe
/tmp/phase6-fork-lifetime-probe
```

## Verification and scope

Commands use `--locked --all-features` unless the shared gate explicitly
checks another feature combination:

```sh
cargo test --locked --all-features --lib cache_cost -- --nocapture
cargo test --locked --all-features --test rules -- --nocapture
./test-ci-gates.sh
SRCLINK_STRICT=1 cargo test --locked --all-features --test srclink -- --nocapture
RULEMAP_STRICT=1 cargo test --locked --all-features --test rulemap -- --nocapture
tests/docker/run.sh scenarios
```

[The final shared CI script](ci-gates-final.log) passes, including native
and musl ordinary tests, feature builds, formatting, ShellCheck,
warning-denied Clippy and documentation. [Strict source links](srclink.log)
pass four cases. [Strict rule map](rulemap.log) still fails, exit 101:
343 total / 333 active / 275 cited / 58 missing. Earlier ordinary,
intermediate focused and shared-gate logs retain their original scope.

[The complete host run](../scenarios-20261031T110055Z-3731951/run.log)
passes all 23 scenarios on `6.8.0-147-generic` in 156.25 seconds, including
VRF changes, address churn, fragmentation and 300-tunnel shrink cycles.
[The final controller summary](scenarios-controller.log) records
`SCENARIO_RESULT=0`. The runner builds all-feature musl artifacts and
uses a disposable privileged container with `--network none`. The scoped
clock and Incus cases are excluded by that runner, not counted as passed.
The source snapshot postdates the host run only by the test-only logger
change; production source and host scenario code are unchanged.

[revision](revision) and [source.patch](source.patch) identify the final
tested source. `source-identity.log` checks that the earlier baseline
production files match the committed pre-change source, and that final
source still matches the snapshot. `docs-checks.log` records local Markdown
file-target and diff-whitespace checks; external URLs/anchors are excluded.
Cargo build durations are omitted from archived logs.

No new required-kernel matrix, Incus/root-systemd profile or merged
coverage collection is claimed here. Complete event-cost/history bounds,
58 rule citations, remaining clauses, final latest-target reruns and
strict CI remain open. [The kernel behavior page](../../../docs/kernel-behavior.md)
now distinguishes each required target's behavior and executed profiles.
