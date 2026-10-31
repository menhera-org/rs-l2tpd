# H17: 300 tunnels, request observation and released storage

This package adds the live scale scenario and fixes two allocations that
followed the largest past configuration rather than current ownership.
It does not claim the whole Phase 6 resource or event-cost gate is closed.

## Request observer calibration

The old nlmon reader counted only NETLINK_ROUTE (protocol 0). That was
sufficient for H8's route-query assertion but would have missed generic
netlink requests in an H17 zero-request assertion. It now counts requests
on every captured netlink protocol, separately records generic requests,
and recognizes RTM_GETROUTE only on NETLINK_ROUTE. A generic family whose
number happens to be 26 must not be classified as a route query.

The parser test checks that distinction as well as compound messages,
notifications/replies and malformed lengths. The live positive control
performs two actual route lookups and an L2TP dump: it sees six requests,
including two generic requests and exactly two route queries, with no
packet loss. H8 also passes with identical counts on empty and 100,000-route
IPv4/IPv6 tables: 36 total requests, 15 generic, and two deliberate fixture
route queries in each case.

Commands:

```sh
cargo test --locked --all-features --test scenarios netlink_requests_are_counted
tests/docker/run.sh scenarios netlink::
```

[Live calibration and H8](../scenarios-20261031T091506Z-3608656/run.log);
[controller output](observer-controller.log).

## Live scale case

The final case starts two daemons with 300 tunnels and sessions each,
requires readiness and exact live object counts, records elapsed monotonic
time, then shuts down and proves cleanup. It separately starts with one
entry and expands to 300 and back to one for three cycles. Descriptor
counts must equal one per additional owned tunnel, plus the same fixed
baseline; every shrink must return to the original descriptor count.

All 300 session devices are configured with distinct inner IPv4 /30s;
every session carries an actual ping in each direction. An identical
300-entry reload has its requests counted and bounded by a linear
envelope. The envelope is a regression guard, not a replacement normative
timing constant.

For the unrelated-event measurement, fixture commands run in namespace B.
A veth peer is moved into A and then removed by deleting its other end in
B. That produces actual link notifications in A without fixture requests
there. One hundred repetitions produce at least 200 captured notification
packets. Across them and a 2.2-second negative observation window, the
daemon must issue zero requests, reconnect nothing and log nothing.
PACKET_STATISTICS must report no loss and the reader must drain every
packet. A subsequent relevant address event must reconnect all 300 bound
tunnels, so a dead monitor cannot satisfy the negative assertion.

RSS is recorded in KiB and checked against a generous per-entry envelope
and a bounded difference between repeated shrink states. RSS includes
allocator retention; it cannot prove that every allocation was released.
The direct allocation regressions below cover the discovered retained
maps. The first exploratory Rust run passed before the storage fix:
[run](../scenarios-20261031T091729Z-3610359/run.log).
It started with one entry; the final case additionally tests fresh
300-entry readiness. Neither the earlier shell probe nor this finite
measurement proves all discovery/store history bounds by itself.

## Retained allocations: failure and correction

Two direct regressions failed before the fix:

- [Socket storage](socket-before.log): 300 real L2TP/IP sockets were
  created in an isolated namespace, then 299 closed. The map retained
  420 slots for one surviving tunnel.
- [Lifetime registrations](registration-before.log): retiring 299 of
  300 tracked registrations retained 396 slots for one survivor.

The kernel socket and registration maps now shrink geometrically when
capacity exceeds four times their current size, with a fixed allowance
of sixteen slots. This avoids reallocating on every close while bounding
capacity by current ownership plus a constant. An ended lifetime
generation releases its entire registration allocation. Socket closing,
identity, deletion confirmation and proof semantics are unchanged.

The final tests check the capacity bound after every retirement, preserve
the surviving socket descriptor, reject the closed handle, and verify
that generation loss releases all registration capacity. This measures
allocated storage independently of process RSS. Before/after logs are
retained; no failed result was rewritten as a pass.

Commands for the native regression and the musl live library executable:

```sh
cargo test --locked --all-features --lib retired_registrations_release_their_storage
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --no-run
# Run that emitted library executable in a disposable privileged container:
docker run --rm --privileged --network none \
  --mount type=bind,source="$PWD",target="$PWD",readonly \
  --entrypoint sh rs-l2tpd-audit-vm:local -ec 'uname -r; exec "$@"' run \
  LIBRARY_TEST_EXECUTABLE --ignored --exact \
  kernel::linux::resources_tests::socket_storage_follows_survivors_after_a_large_configuration \
  --nocapture
```

[Native after](registration-after.log); [live after](socket-after.log).
These focused after logs precede the final stronger per-removal assertions;
the final ordinary/QEMU profiles execute those strengthened tests.

## Final checks and limits

The [full host suite](../scenarios-20261031T092135Z-3614334/run.log)
passes 23 scenarios in 153.31 seconds. Two further scale-only repetitions
pass in 67.91 and 64.73 seconds. [Measured host results](measurements.md)
record 3.25–3.52 seconds for fresh readiness of both 300-entry daemons,
600 unchanged-reload requests and zero unrelated-event requests in all
three runs. Descriptor counts return from 314 to 15.

[Ordinary tests](ordinary.log), [Clippy with warnings denied](clippy.log)
and [four strict source-link checks](srclink.log) pass. The
[strict rule map](rulemap.log) still fails honestly: 343 total, 333 active,
275 cited, 58 missing. H17/G12 add two citations, not global gate closure.

The ordinary suite first exposed a process-fixture race:
[original failure](ordinary-before-process-fixture-fix.log). File-error
reporting precedes signal installation, so sending SIGTERM immediately
after that report could invoke its default action. The fixture now waits
for the actual kernel-open failure in the startup retry loop before
sending SIGTERM. No daemon signal behavior changed.
[Twenty corrected repetitions](process-repetitions.log) pass; the first
incorrect Cargo argument invocation is retained separately in
process-repetitions-invocation-error.log and executed no test.

The first mainline guest passed 11 live library cases, 16 kernel cases,
five review cases, 38 ordinary binary cases plus three explicit privileged
binary cases, 26 process cases and 22 scenarios. Its new scale case failed
the fixture's inherited ten-second readiness observation deadline while
session 213 of 300 was being created.
[Original failed guest](../qemu-h17-mainline-20261031/run.log) is retained.
G15 bounds uncontested readiness by kernel creation, with ten seconds
specifically for held identifiers; it does not impose ten seconds on
creating an arbitrary number of uncontested objects.

The scale case now uses explicit sixty-second waits for the 300-entry
readiness, reload and shutdown observations. Other scenarios retain their
existing deadlines. Actual operation times, kernel counts, descriptor/RSS
bounds, frame checks and zero-request assertions remain measured.
The [final host scale run](../scenarios-20261031T093915Z-3634859/run.log)
passes in 65.83 seconds with the explicit waits. The
[complete mainline rerun](../qemu-h17-mainline-final-20261031/run.log)
passes all 23 scenarios in 471.32 seconds, as well as all conformance and
process profiles listed above. Fresh 300-entry readiness takes 38.43
seconds for both daemons in that TCG profile. It records 600 unchanged-
reload requests, zero unrelated requests across 400 captured packets,
bidirectional frames on all 300 sessions, three completed shrink cycles,
and descriptors returning from 314 to 15. All final guest result markers
are zero. The kernel remains 7.3.0.

Both final runs select identical daemon and scenario executables:
[host artifact identities](host-artifacts.log) match the corresponding
[guest identities](../qemu-h17-mainline-final-20261031/artifacts.log).
[Formatting and diff checks](final-checks.log) pass, and local Markdown
file targets were checked. Identical kernel configurations are referenced
by digest and relative path in each guest's kernel-config.log.

The baseline is in [revision](revision). [source.patch](source.patch) and
[extra-source-hashes.log](extra-source-hashes.log) capture the original
executed changes. [pre-scale-timeout-source.patch](pre-scale-timeout-source.patch)
adds only the process-fixture correction; that difference was checked
byte for byte. [scale-timeout-source.patch](scale-timeout-source.patch)
and [scale-timeout-extra-source-hashes.log](scale-timeout-extra-source-hashes.log)
capture the explicit scale wait correction used by the final reruns.
[final-source.patch](final-source.patch) and
[final-extra-source-hashes.log](final-extra-source-hashes.log) match that
state byte for byte. No production source changed
between these stages.

A review follow-up remains in the lifetime subscriber: RTM_DELLINK currently
scans tracked registrations for its index. The live zero-request assertion
does not prove constant lookup cost there. M16/G12's complete CPU-cost proof
must address that scan before the global gate is called green. Discovery
repository/libc-worker/store retirement bounds retain their separate tests
and remaining proof obligations. Current-source 100% coverage, the full
latest-target matrix, final manager refreshes, rule completeness and strict
CI remain open.
