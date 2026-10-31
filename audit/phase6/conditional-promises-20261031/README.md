# Conditional promises and complete local rule traceability

The final three uncited rules, G15, G16 and G20, now have executable
declaration citations. The strict rule map links all 333 active rules.
This is traceability, not completion of every clause, kernel target, resource
proof or the coverage gate. Strict CI enforcement remains pending.

## Live promise scenario

`readiness_existence_fidelity_stability_and_ordered_shutdown` in
[promises.rs](../../../tests/scenarios/promises.rs) configures three tunnels
and sessions before underlay addresses or routes exist: an IPv4 peer, a
DNS-dependent peer with an absent bind device, and an IPv6 peer.

- Readiness follows the last session creation within one second in this
  healthy fixture, with zero connected peers. All three tunnels and sessions
  exist despite absent routes, DNS and the configured missing binding.
- Configuring the underlay connects the two literal peers within the measured
  one-second bound. The DNS/absent-binding entry stays disconnected. Real
  bidirectional frames prove the IPv4 path works.
- Identical reloads do not reconnect. A configured session rename and a peer
  change preserve all three session indexes, tunnel/session counts and creation
  counts. The renamed device still carries frames. The kernel's tunnel dump
  reports the configured new peer and the actual local source.
- SIGTERM must produce every session-removal event before the first tunnel
  removal event, then a completed shutdown and exit status 0. Three-tunnel
  cleanup must finish within six seconds in this fixture. Actual kernel dumps
  must contain no tunnel or session afterwards, on both sides.

This exercises G15–G20 together. Session identity is checked after each in-place
transition and creation/removal reports must remain unchanged before shutdown;
it is not a packet-by-packet uptime proof across every possible host event.
The existing property, timing and host scenarios supply separate cases.

[The focused run](../scenarios-20261031T125234Z-3896029/run.log) passes in
1.47 seconds before only the additional timing-output statements. There is no
production behavior or dependency change.

## Parent/PID and bounded conflict assertions

`daemon_readiness_pid_inode_and_reexec` in
[process.rs](../../../tests/process.rs) now cites G15/G20 for actual parent
readiness exit, PID publication and removal, kernel cleanup and successful
termination. The overlapping-instance case now requires conflict-budget
readiness within ten seconds of starting the second instance and prints that
elapsed monotonic time. This checks the bound, not merely a generous harness
timeout. The existing runtime cleanup-window test also cites G20 for its
separate withdrawal and per-tunnel deletion deadlines.

## Commands and evidence

```sh
tests/docker/run.sh scenarios promises::readiness_existence
# Three consecutive full host runs:
tests/docker/run.sh scenarios
# Each TEST_SEED=1..10:
cargo test --locked --all-features --lib --test kernel-fake --test rules --test service -- --nocapture
RULEMAP_STRICT=1 SRCLINK_STRICT=1 cargo test --locked --all-features --test rulemap --test srclink -- --nocapture
./test-ci-gates.sh
cargo test --locked --all-features --target x86_64-unknown-linux-musl --test process --no-run
# Disposable privileged Docker, --network none, read-only checkout:
process --include-ignored --test-threads=1 --nocapture
```

Ordinary suites use the native target. Live artifacts use
`x86_64-unknown-linux-musl` on `6.8.0-147-generic`. All Cargo invocations use
`--locked --all-features` except feature-specific checks in the common gate.
Host networking, kernel modules, sysctls and process limits are unchanged.
The verification record lists the completed final counts and logs.

| Final record | Result |
|---|---|
| [strict-maps.log](strict-maps.log) | Explicit `RULEMAP_STRICT=1 SRCLINK_STRICT=1`: three rule-map and four source-link cases pass; all 333 active rules cited, all Linux functions cited, 37 production and six classified K facts |
| [fake-ten.log](fake-ten.log) | Each of ten seeds passes 92 ordinary library cases (11 live ignored), one fake-conformance case, 75 rule cases and 25 service cases; planner seed ranges overlap |
| [ci-gates.log](ci-gates.log) | Common formatting, ShellCheck, warning-denied Clippy/docs, feature builds and native/musl ordinary suites pass; its map invocations remain lenient |
| [live.log](live.log) | All 27 process cases pass; conflict-budget readiness takes 9.017 seconds, within ten seconds |
| [First full host run](../scenarios-20261031T125657Z-3898324/run.log) | 26 pass in 164.21 seconds |
| [Second full host run](../scenarios-20261031T125950Z-3903596/run.log) | 26 pass in 163.32 seconds |
| [Third full host run](../scenarios-20261031T130249Z-3909199/run.log) | 26 pass in 161.90 seconds |

The three full runs are consecutive on final Rust source, with no intervening
source edits and zero observed flakes. Each requires `SCENARIO_RESULT=0` in
its retained controller summary. They are local host-profile qualification,
not the plan's remaining ten-run CI requirement.

`revision` and `source.patch` identify the tested source. source-identity.log
checks the final snapshot and hashes artifacts. docs-checks.log checks local
Markdown file targets and whitespace, excluding web URLs and anchors. Cargo
build durations are omitted.

## Strict-mode reporting correction and CI qualification

The shared `test-ci-gates.sh` currently runs map checks without setting strict
flags. Earlier host-requirement, observability and architecture records called
its four source-link tests strict; that wording is corrected. Their zero
missing counts were reported, not enforced by those invocations. Separate
older explicit strict logs retain their original scope. The explicit command
above now sets both flags for the current tree.

The Phase 6 page calls for ten fake runs and three container runs before
enabling a strict gate. The plan additionally requires ten repetitions in CI
for each suite, so local repetitions alone do not close that requirement.
CI enforcement remains off until that stronger requirement is fulfilled.
Current rule/source maps do not establish complete clause coverage. The final
required-kernel matrix, Incus/root-manager profiles, complete event/resource/
history proof, merged coverage and remaining CI work are still open.
