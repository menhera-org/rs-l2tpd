# Shared-kernel neighbour pressure

Overlapping instrumented GNU and stable musl host scenario runs intermittently
failed H17's single-packet assertion near session 200. The latest retained
failure is in `../streamed-inventories-20261101/parallel-host-failure/`.
The packet assertion now retains its command output. Earlier transcripts
did not capture neighbour-overflow counter deltas.

Linux v6.8.12 uses one exported
[ARP table](https://github.com/gregkh/linux/blob/v6.8.12/net/ipv4/arp.c#L152-L184).
Its [allocator](https://github.com/gregkh/linux/blob/v6.8.12/net/core/neighbour.c#L469-L490)
charges the table's shared garbage-collected entries, refuses allocation
when collection cannot recover capacity at the hard threshold, and increments
`table_fulls`. The table is shared across network namespaces. Device-specific
parameters are filtered by namespace in the
[table dump](https://github.com/gregkh/linux/blob/v6.8.12/net/core/neighbour.c#L2501-L2559),
while the table/counters are reported globally. `kernel-sources.log` records
source identities; the v6.8.12 blobs match the fetched stable-source metadata.

## Controlled guest result

The focused experiment boots vanilla 6.8.12 in an isolated four-vCPU QEMU
guest. It changes no neighbour thresholds. Two processes each create a
300-session pair of namespaces and run the **unchanged** `wire` helper:
one actual ping per session and direction, with the original two-second
packet timeout and assertion. A diagnostic-only wrapper permits 180 seconds
for startup/cleanup; it does not qualify H17's timing gate.

| Execution | Packet result | ARP `table_fulls` delta |
|---|---|---|
| Two concurrent processes | Both fail: sessions 272 and 238, side 0; each reports 100% packet loss | +2 across the concurrent run |
| The same diagnostic alone afterward | All 300 sessions exchange frames both ways; case passes in 58.38 s | 0 |

`attempt-2/run.log` retains the failures, counters and successful serial
control. `PRESSURE_CONTROL_RESULT=0` means that this expected-failure
experiment behaved as asserted; it is **not a normal conformance result**.
The ordinary host suites then pass all 26 cases three times serially,
with the original H17 startup and packet assertions intact.

This reproduces shared-budget contention as a cause of this failure shape.
It supports serializing these host-kernel workloads. Historical host
failures remain retained; their missing counter snapshots prevent direct
retrospective attribution of every dropped packet.

## Reproduction and scope

Apply the streamed-inventory record's `source.patch` to its `revision`, then
apply `focused-driver.patch` in an isolated checkout. The latter adds only
the diagnostic wrapper and disposable guest mode; it is not applied to the
shipping runners. Kernel, executable, image and command identities are in
`attempt-2/`. The experiment's pressure stays inside the QEMU guest; no host
networking or sysctl is changed.

The first attempt, retained in this directory's root files and reconstructed
with `first-driver.patch`, ran two full H17 cases with the normal startup
allowance in a two-vCPU guest. Both timed out before packet traffic;
`PARALLEL_TABLE_FULLS_DELTA=0`. That attempt is inconclusive for neighbour
pressure and does not count as its reproduction. The focused experiment
isolates the traffic assertion instead.

Host-kernel scale runs, including coverage and musl variants, must run
serially with sufficient shared neighbour capacity. Separate QEMU guests
have independent kernels and can run concurrently. The code, packet
assertion and daemon's resource contract are unchanged by that scheduling
requirement.
