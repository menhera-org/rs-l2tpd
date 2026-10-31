# H16: guest wall-clock steps and monitored pause/resume

This package adds the scoped `clock` mode to the QEMU helper and to the
required matrix. It tests the real daemon against a separately booted
kernel; it never changes the host's clock or networking. The test requires
both the clock-profile environment flag and the kernel command-line marker
`rs_l2tpd_clock_guest=1` before executing any `date -s`. Ordinary container
and native profiles leave this case ignored.

## Experiment and independent observations

The guest has two namespaces, two real daemons, a controlled DNS responder,
a working named-peer tunnel and a second tunnel with no route to its peer.
The pending tunnel retries; the DNS-backed tunnel has a thirty-second
lookup refresh and must keep carrying frames without reconnecting when
the same answer returns. Test-only DNS request timestamps record actual
wire queries, separately from daemon log observation.

1. Start and prove frames in both directions on the working pseudowire.
2. Set the guest wall clock one year forward, then one year backward,
   using `date -u -s @SECONDS`, checking each requested change took effect.
   Observe the real one-second pending-peer messages throughout and require
   their monotonic intervals to stay between 0.75 and 1.5 seconds. The
   initial DNS refresh must occur 29.9–32 seconds after its previous query,
   including the small query/completion/scheduling difference; a wall-clock
   jump cannot trigger an early refresh or delay it indefinitely.
3. Restore guest wall time from its original value plus monotonic elapsed
   time. The guest prints a pause request and blocks for the controller's
   acknowledgement; the daemon processes remain live until QEMU stops.
4. The host controller sends QMP `stop`, checks `query-status` reports
   paused/non-running, holds a measured three-second pause, checks the VM
   is still paused, sends `cont` and verifies running status. Only then does
   it send the guest acknowledgement through the serial input.
5. The guest's monotonic elapsed time across that handshake must stay below
   two seconds, while the host records at least three seconds of actual
   paused state. Retries must retain their one-second monotonic cadence and
   the next real DNS refresh its thirty-second interval. An unchanged DNS
   answer or clock stimulus must not reconnect the established tunnel;
   frames still cross both ways.
6. Add only a route for the pending tunnel, without a subscribed link or
   address event. Readiness was already achieved; a real retry must now
   establish this tunnel within one second, and frames must cross its
   session both ways. This positive control prevents a periodic log line
   alone from being treated as proof of actual connection attempts.
7. Add an address after resume, then temporarily rename the configured bind
   device away and back. Observe reconnection on the address event, actual
   transmit drops while the bind name is absent, and frames after the name
   returns. Both original session indexes survive. Orderly stops leave no
   tunnels or sessions.

The interval windows are live scheduling tolerances, not changed timer
constants. Exact scheduling policy has separate fake-clock tests. QMP
pause is the Phase 6 suspend stand-in; it does not inject a physical S3
resume or an overflowing subscription while the entire guest is stopped.
Existing live overflow/resync tests remain separate evidence.

## Controller and fixture calibration

`tests/kernel/clock-control.rs` is a small standard-library-only Rust host
helper. It owns and cleans up its QEMU child, bounds protocol lines and
QMP deadlines, matches transaction IDs, rejects command/error/state
mismatches, and ignores interleaved asynchronous events. Three unit tests
cover valid/reordered messages, events, wrong states/IDs, command errors,
EOF and malformed/oversized lines. They run before each clock guest.

The controller intentionally recognizes only the fixed argument-free QMP
commands used here; the source records that limitation and the point at
which a full JSON parser is needed. No dependency was introduced.
The protocol and run-state checks follow the
[QMP specification](https://www.qemu.org/docs/master/interop/qmp-spec.html)
and [QMP command reference](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html).
The greeting is checked without archiving the host's installed QEMU
version. Source/executable identities, commands and scoped result markers
are recorded instead.

The initial complete experiment passed in
[../qemu-clock-first-20261031](../qemu-clock-first-20261031/run.log).
Three final repetitions add explicit per-retry measurements and controller
artifact identity. They use the same all-feature musl executables and the
same mainline 7.3.0 image/config. The same case then passed on Ubuntu
6.8.0-147-generic, vanilla 6.8.12, Ubuntu 7.0.0-42-generic and vanilla
7.0.14. The required matrix now calls this scoped clock boot for every
target, in addition to normal profiles and the separate IPv6-absent and
missing-driver boots. A whole required-matrix rerun remains necessary at
phase exit.

## DHCPv6 low-port-range clause

The same package closes the remaining positive R46/K13 clause. The scenario
now runs three variants: denied pure DHCPv6 and unified RA fallback with
`ip_unprivileged_port_start=1024`, then pure DHCPv6 with the range starting
at 0. In every case the daemon really lacks CAP_NET_BIND_SERVICE, verified
through its effective mask, and reports that fact once. The low-range case
observes an actual Information-Request from UDP source port 546, returns
a matching DHCPv6 Reply, observes DNS resolution and exchanges frames in
both directions without EACCES. Namespace-local tunables and servers stay
inside the disposable fixture.

The focused run is
[scenarios-20261031T082938Z-3588507](../scenarios-20261031T082938Z-3588507/run.log):
one test function, three variants, pass. The later full host regression
profile also includes this strengthened case.

## Results and remaining work

All seven final runs passed one scoped guest case and three controller
self-checks each. Exact timing measurements and links follow. Every run
records the expected kernel release and zero conformance, scenario, guest
and controller markers; those markers apply only to this scoped case.
All seven selected userspace artifact lists, controller source hashes and
controller executable hashes match byte for byte.

| Target/run | Retry intervals, seconds (count) | DNS refresh before/after, seconds | Host pause / guest monotonic interval, seconds |
|---|---|---|---|
| 6.8.0-147-generic (noble) | 1.002625–1.008031 (59) | 30.025149 / 30.008233 | 3.001285 / 0.008747 |
| 6.8.12 (vanilla6812) | 1.003246–1.007058 (59) | 30.023012 / 30.006788 | 3.000934 / 0.008737 |
| 7.0.0-42-generic (resolute) | 1.003066–1.007434 (59) | 30.022095 / 30.007007 | 3.000817 / 0.007066 |
| 7.0.14 (vanilla7014) | 1.002955–1.007650 (59) | 30.022830 / 30.007465 | 3.000667 / 0.009360 |
| 7.3.0 (final-1) | 1.003103–1.006355 (59) | 30.021816 / 30.006162 | 3.000734 / 0.007543 |
| 7.3.0 (final-2) | 1.003008–1.006435 (59) | 30.030336 / 30.006054 | 3.000925 / 0.007009 |
| 7.3.0 (final-3) | 1.003140–1.009498 (59) | 30.028061 / 30.008056 | 3.000947 / 0.007853 |

Runs: [Ubuntu 6.8](../qemu-clock-noble-20261031/run.log),
[vanilla 6.8.12](../qemu-clock-vanilla6812-20261031/run.log),
[Ubuntu 7.0](../qemu-clock-resolute-20261031/run.log),
[vanilla 7.0.14](../qemu-clock-vanilla7014-20261031/run.log),
[mainline repetition 1](../qemu-clock-final-1-20261031/run.log),
[2](../qemu-clock-final-2-20261031/run.log),
[3](../qemu-clock-final-3-20261031/run.log).

The [full host regression](../scenarios-20261031T085431Z-3596603/run.log)
passes all 22 scenarios, including the strengthened DHCPv6 case.
[Ordinary all-feature tests](ordinary.log), [warning-denied Clippy](clippy.log)
and [four strict source-link checks](srclink.log) pass. The
[strict rule map](rulemap.log) honestly fails: 343 total, 333 active,
273 cited, 60 missing. H16/R8 add two citations; this does not close
the global rule or coverage gate.

The starting revision is in [revision](revision).
[source.patch](source.patch) and [extra-source-hashes.log](extra-source-hashes.log)
record the executed changes and the two new Rust sources. After the
mainline repetitions, only matrix.sh was broadened from one mainline
clock boot to one per target; the four additional runs invoke run-guest.sh
directly. [full-target-source.patch](full-target-source.patch) records that
driver-only adjustment. [final-source.patch](final-source.patch) and
[final-extra-source-hashes.log](final-extra-source-hashes.log) match
that state; no executed guest/controller input changed between the seven
runs. Each run records its image, config, executable identities and command.
Identical kernel config bytes are referenced by relative path and digest
in each run's kernel-config.log.

[Final formatting, shell syntax/ShellCheck and matrix parser checks](final-checks.log)
pass. Local Markdown file targets were also checked.

H17 resource/event-cost bounds, the remaining promise and rule clauses,
current merged 100% coverage, final kernel/Incus/root-unit refreshes and
strict CI are still open. No skipped profile is counted as a pass.
