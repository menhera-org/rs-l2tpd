# Scoped inventories and VRF events

This test-only batch starts from signed `7e095c1`. All **5,889 exported
function mappings** match the preceding event/lifetime snapshot, so the
collector reuses those profiles. It covers **8,645/8,705 lines (99.31%)**
and **1,792/1,840 outcomes (97.39%)**: three more lines and five more
outcomes. **60 lines and 48 outcomes remain uncovered.** There are no
production exclusions. Phase 6 remains open.

The model cases check that removing a VRF member retries only a previously
connected tunnel; member-address changes affect only the matching family
and VRF domain; and a literal link-local zone works without a configured
bind device. The readiness-parent fixture now rejects an unexpected byte
after a valid daemon PID.

The live inventory case creates two tunnels, checks namespace-wide refusal
of a colliding IP session ID, and checks unfiltered, per-tunnel and absent
tunnel inventories. It also records a wrong-tunnel single-session query
and requires the adapter to return absence after validating the reply's IDs.
The creation-timeout case refuses sends with ETIMEDOUT in an isolated child,
requires the unchanged five-second capture deadline, preserves the errno,
and verifies that the capture name can be armed again afterward.

## Results

- Ten instrumented ordinary suites pass with seeds 11 through 20. They
  exercise the final model/readiness assertions; the two live declarations
  remain ignored there and have separate qualification.
- Three GNU and three musl container repetitions each pass 308 ordinary
  library cases, 80 ordinary binary cases and both new live cases.
  Three further instrumented GNU live repetitions pass and export profiles.
- All five focused required-kernel profiles pass both live cases, the three
  new event/zone cases, both shared tracer calibrations, ordinary binary
  cases, selected filesystem cases and signal task-limit checks. This is
  a focused profile, not a replacement thirteen-profile matrix.
- Seven restored controls are rejected: accept a wrong readiness byte,
  remove the session-dump filter, reverse the connected-member guard,
  ignore address family, treat an ordinary master as a VRF, omit the
  unbound zone, or return immediately on a timed-out creation.
- The common CI gates pass, including strict maps for 333 active rules and
  43 kernel facts. Documentation links and standalone-document checks pass.
- The preceding signed `7e095c1` passes
  [both CI jobs](https://github.com/menhera-org/rs-l2tpd/actions/runs/41546063321)
  and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41546063324).

## Required-kernel observations

| Target | Wrong-tunnel raw session query | Adapter result |
|---|---|---|
| Ubuntu 6.8.0-147.147 | ENODEV; no record | absent |
| Vanilla 6.8.12 | ENODEV; no record | absent |
| Ubuntu 7.0.0-42.42 | the existing session from the other tunnel | absent |
| Vanilla 7.0.14 | the existing session from the other tunnel | absent |
| Mainline 7.4-rc1 | the existing session from the other tunnel | absent |

The old path uses `l2tp_nl_session_get` and
`l2tp_tunnel_get_session`. The newer path selects
`l2tp_session_get` → `l2tp_v3_session_get`, whose namespace ID lookup
can return that other session. The existing adapter's pair check is
necessary. The GNU coverage host has the older behavior; this batch does
not claim an instrumented newer-kernel execution of that guard. The five
stable guest witnesses establish its live behavioral scope.

`source.patch` records the root test changes. The private guest checkout
uses the same production bodies and changes its binary-profile dispatch.
One test closure has a formatting-only difference: rustfmt output compares
equal, and `guest-final-formatting.patch` retains the exact difference;

`guest-base-revision`, `guest-source.patch` and `focused-matrix-init.txt`
record that scope. The shipping runner is unchanged. Control patches use
their separately recorded checkout base. Every mutation is restored.

## Rejected fixtures and limits

The first member-removal oracle wrongly expected a connection to remain
after its last addressed member disappeared. The corrected case requires
disconnection and checks the reconnect attempt. A first inventory fixture
tried duplicate session IDs, contradicting K19; the corrected case asserts
EEXIST and then creates a distinct ID.

The first timeout fixture tried to query through another thread after
installing a TSYNC filter. That thread was filtered too. Its container,
instrumented and five guest failures are retained. The corrected fixture
runs in its own child, removes that observer, and directly checks deadline
and capture release. Rejected profiles were moved outside the collector;
only passing live exports are imported.

The final timeout fixture, including its minimum-deadline assertion and
child isolation, passes the repeated GNU/musl and focused guest profiles.
No production function, timeout or specification rule changes. The
preceding record retains full normal/boot and serial clock scope, together
with its failed parallel clocks and rejected QEMU experiments. Complete
clause/history/resource/event-cost proof and raw 100% coverage remain open.
