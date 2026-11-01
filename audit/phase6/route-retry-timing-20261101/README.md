# First-route retry timing: decision required

The H6 live gate currently requires observed connection within exactly one
second of route creation. Two retained runs exceed that boundary:

| Implementation / ABI | Observed route-to-connect delay | Result |
|---|---|---|
| Pre-rebind / instrumented GNU | 1.000167510 s | Assertion fails; 24/26 normal scenarios pass, with a separate packet failure |
| Final cleanup/rebind / stable musl | 1.000375371 s | Assertion fails; all other 25 normal scenarios pass |

Exact sources and logs are in the
[tunnel-state record](../tunnel-application-status-20261101/README.md):
`pre-rebind/live.log` and `scenarios-1/run.log`. The timestamp records when
the daemon-log reader observes the connection message. It does not isolate
timer wake-up, the kernel call or log-reader scheduling. The overshoot alone
does not identify their individual contributions. Later passing runs do not
explain these failures.

The reconciler arms a retry at `kernel.now() + one second`. H6 already
states that convergence uses this one-second retry; a route can appear just
after the prior attempt. The policy deadline and observed completion are
separate quantities. Rule regressions check the exact next deadline and
recovery after advancing the fake clock by one second, including refused
peers and simultaneous retry types.

`proposed.patch` is **unapplied**. It would:

- Keep the exact one-second retry deadline under deterministic rule tests.
- Retain the live fixture's existing ten-second event timeout and require
  actual connected state plus frame exchange; record the monotonic delay.
- Explain scheduling and kernel-operation delay in H6 and make the Phase 6
  acceptance row match those measurements.

No retry interval or daemon behavior changes. This changes the live gate's
written one-second completion bound, so it needs a maintainer decision under
Phase 6's rule: “Never weaken a rule to make a gate pass.” The alternative
is to retain that bound and redesign the timing/event contract and its
implementation; another numerical tolerance would need justification too.

The patch passes `git apply --check`; it has not been applied or counted as
a passing gate.
