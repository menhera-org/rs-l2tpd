# H8 request-count measurement boundary

The [full matrix](../matrix-20261031T133318Z-3943822/README.md) failed its
vanilla 7.0.14 H8 scenario because total netlink requests differed by one.
Temporary diagnostics reproduced the failure with 36 versus 48 requests.
Both startup/reload phases issued 23 requests. The additional requests
were generic-netlink command 4, `L2TP_CMD_TUNNEL_GET`, after shutdown began.

[source-evidence.log](source-evidence.log) identifies that command from the
tested kernel's UAPI and records the daemon's `shutdown_deletions` loop.
Each shutdown step queries tunnels still awaiting kernel deletion. Queued
kernel cleanup and notification scheduling determine how many such steps
are needed. Exact lifetime request-count equality therefore compares
scheduler-dependent cleanup work along with startup/reload work.

The corrected fixture issues its two deliberate route-query controls after
reload, waits until the observer has read them, and snapshots startup/reload
requests at that boundary. It then stops the daemon and drains the same
capture. Equality still applies to startup/reload work; exactly two route
queries, zero lost packets and complete capture accounting remain required
through shutdown. The rule is unchanged: the daemon does not query routes.
Complete CPU-cost proof remains a separate open requirement.

Three consecutive corrected H8 repetitions pass on vanilla 7.0.14 in 73.85,
72.72 and 72.75 seconds. Each small/large pair has 27 startup/reload requests
including the fixed fixture controls, nine generic-netlink requests and
exactly two route queries. Full-lifetime totals vary between 36 and 37.
`fixed/run.log` retains the counts and results; `fixed-checks.log` checks all
six observations and three passing results.

These are focused diagnostic boots, not normal conformance profiles.
`diagnostic-init.sh` replaces only the copied guest init, requests three H8
repetitions and stops at the first failure. The diagnostic boot stops after
its first failed case; the corrected boot completes all three. Its
`CONFORMANCE_RESULT=0` is the existing runner protocol marker; no library,
kernel, process or other scenario suite ran in these boots. The scope line
and this record define the evidence. Both boots use the retained vanilla
7.0.14 image/config and networkless review userspace image. The temporary
runner copy points at this init; all other runner behavior is unchanged.
`diagnostic.patch` records the temporary logging, which is absent from the
final test. Executable and kernel identities are retained for both boots.

The matrix driver also compares initial/final sources against its captured
starting revision. Previously, using a fresh `HEAD` at both times could
miss source changes that were committed during a run. Its publication-parser
self-test and the full common CI checks pass. A complete matrix rerun with
the corrected H8 fixture is still required; the failed matrix remains failed.
