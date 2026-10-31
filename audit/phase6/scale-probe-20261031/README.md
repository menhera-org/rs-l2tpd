# Exploratory 300-object reload/shrink probe

Command from the repository root:

```sh
docker run --rm --privileged --network none --mount type=bind,source="$PWD",target="$PWD",readonly --entrypoint sh rs-l2tpd-audit-vm:local "$PWD/audit/phase6/scale-probe-20261031/probe.sh" "$PWD/target/x86_64-unknown-linux-musl/debug/rs-l2tpd"
```

The script creates 300 socket-owned tunnels and sessions, waits for
readiness, then alternates one and 300 entries for three shrink cycles.
It checks every kernel object count and requires at most one descriptor
per tunnel plus 20. Actual descriptor counts return from 314 to 15;
RSS snapshots are recorded without imposing a hardware-specific bound.
Final shutdown removes every tunnel and session and exits zero.

The first probe incorrectly sent SIGHUP when objects existed, before
readiness, so P9 correctly allowed the signal to be ignored. That fixture
error is retained in before-readiness-fixture-error.log. The corrected
probe explicitly waits for readiness; run.log ends SCALE_PROBE_RESULT=0.

This is not the H17/G23 gate: it does not yet assert per-event request
cost, linear reconcile cost, resolver/history memory bounds, or frame
exchange through every session. No Rust test citation or full scenario
pass is claimed for it. The disposable container has been removed.
