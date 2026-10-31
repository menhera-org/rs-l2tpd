# Burst recovery and unavailable VRF support

This package supplies the last two missing host-requirement declarations,
R35 and R45. It changes no daemon behavior or dependency. Full proof of every
clause and the global Phase 6 gates remain separate from citation coverage.

## R35: bounded link/address bursts

`a_link_address_burst_coalesces_loss_and_recovers_the_final_source` in
[events.rs](../../../tests/rules/events.rs) configures a bound tunnel and
session, drains its initial events, then limits the fake monitor queue to four
notices. One thousand foreign link/address/create/delete cycles overflow it;
the relevant source removal and replacement happen after the queue is full.

The receive yields one loss indication plus at most four queued notices. After
forwarding them, readiness remains true, the same session and socket survive,
the source is the final configured host address, and the exact mutation trace
is one disconnect, one rebind and one connect. No timer or queued monitor work
remains. This is a coalesced-overflow assertion, not a CPU benchmark or a live
route-flood result; existing K7/H8 and monitor-filter tests have their own scope.

[The first fixture](burst-fixture.log) expected no bind operation after
disconnect. That expectation was wrong: disconnect clears the binding (K22),
so recovery must rebind. [The corrected test](burst.log) requires all three
operations. No product fix was needed.

## R45: an ordinary device when the VRF driver is unavailable

`unavailable_vrf_driver_keeps_ordinary_device_binding_and_frames` in
[boot.rs](../../../tests/scenarios/boot.rs) runs only in the new `no-vrf`
stock-kernel guest profile. It requires the `vrf` module to be absent and
module autoload disabled, and positively verifies that an attempted VRF device
creation fails. The profile loads the other required L2TP/Ethernet drivers.
It never unloads or changes modules on the host.

The two namespaces have ordinary veth devices named `vrf0`. Both IPv4 and IPv6
tunnels bind to them, reach readiness and carry bidirectional frames. Renaming
the bind device away disconnects both tunnels; restoring its name reconnects
both. Frames work again and session indexes are unchanged. The VRF driver
remains absent throughout. A VRF-looking name does not supply a VRF domain.

The profile is separate from the normal suite and requires a modular stock
kernel; it does not claim a full normal-matrix pass or simulate CONFIG_NET_VRF=n
by changing a running host. Its records retain the real release, kernel config,
artifact hashes, QEMU command and result markers.

## Executions

All Cargo commands use `--locked --all-features` except other feature sets
explicitly checked by the shared CI gate. The ordinary rule suite is native;
the guest artifacts use `x86_64-unknown-linux-musl`. QEMU uses TCG, a private
initramfs and no network device. The supplied Ubuntu 26.04 configuration's
default KHO reservation is disabled by the existing cold-boot helper.

```sh
cargo test --locked --all-features --test rules a_link_address_burst -- --nocapture
# Each TEST_SEED=1..10:
cargo test --locked --all-features --test rules -- --nocapture
./test-ci-gates.sh
RULEMAP_STRICT=1 cargo test --locked --all-features --test rulemap -- --nocapture
tests/kernel/run-guest.sh IMAGE MODULES CONFIG no-vrf RECORD
```

[rules-ten.log](rules-ten.log) passes all 75 rule cases for each of ten seeds.
The planner's 32-seed ranges overlap; this is scoped determinism evidence.
[rulemap.log](rulemap.log) remains red, exit 101: 343 total / 333 active /
314 cited / 19 missing. All active R rules now have declaration citations;
that does not establish complete assertion coverage of their clauses.

[noble/run.log](noble/run.log) passes the one scoped case on
`6.8.0-147-generic` in 2.42 seconds; [resolute/run.log](resolute/run.log)
passes it on `7.0.0-42-generic` in 2.54 seconds. Both require
`CONFORMANCE_RESULT=0`, `SCENARIO_RESULT=0` and `MATRIX_GUEST_RESULT=0`.
[ci-gates.log](ci-gates.log) passes the shared formatting, ShellCheck,
warning-denied Clippy/docs, feature builds, native/musl ordinary suites and
four strict source-link cases. Guest controller summaries are retained too.
`revision` and `source.patch` identify the tested source; source-identity.log
checks it. docs-checks.log checks local Markdown file targets and whitespace,
excluding web URLs and anchors. Cargo build durations are omitted.

The no-VRF profile covers the two modular Ubuntu targets; it is not a result
on a vanilla kernel built without VRF. The full current-code normal matrix,
Incus/root-manager refreshes, coverage, complete event-cost/history proof,
remaining 19 citations and strict CI remain open.
