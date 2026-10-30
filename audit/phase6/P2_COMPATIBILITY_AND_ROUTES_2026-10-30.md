# Phase 6 P2 compatibility, process and route scenarios — 2026-10-30

This extends the partial host suite; the complete P2 gate remains open.

G11/G22 runs the archived v0.1.5 binary with its own Cargo.lock, against
the new daemon using a configuration both understand (including V4/V6
spellings, without the new host table). Both outer families deliver
frames in both directions before and after reload. The runner records
the baseline tag's resolved commit, build features and binary git-blob
hash. Historical dependencies never enter the new daemon's dependency
graph. Both daemonizing processes have bounded cleanup guards.

H19/P22 uses a POSIX shell as init: waits for the original parent's
zero exit and PID publication, sends reload and re-exec signals to that
PID, checks the changed peer and unchanged PID/interface index, verifies
frames, then checks shutdown's PID removal and kernel cleanup.

H8 creates exactly 100,000 blackhole routes per family, without defaults.
An nlmon AF_PACKET socket observes the namespace's rtnetlink traffic,
including unicast requests an ordinary second rtnetlink socket cannot
receive. Each trace contains two deliberate route-query controls,
requires zero packet loss and all packets read, and then requires exactly
those two RTM_GETROUTE requests. Daemon startup/reload/shutdown produce
the same request count with and without the large tables (21 total,
including fixture operations). Timings are recorded as diagnostics;
equal wall-clock samples are not asserted. The passing run measured
6.0/6.5 ms readiness and 1.3/1.2 ms reload before/after large tables.
The assertion is unchanged work and no table access, not a statistical
performance claim. Route population finishes before tracing begins.

The capture parser has an ordinary self-check; a separate live positive
control sees both deliberately generated queries and verifies loss
accounting. It requires nlmon already present and never loads a host
module. Every privileged command runs inside a disposable container with
network none; the checkout is read-only and the namespace guards clean
up processes and links on failure.

Initial evidence:

- [0.1.5 case](entry/interoperability-015.log).
- [14-case process/compatibility subset](entry/scenarios-with-compat-init-1.log).
- [Capture positive control](entry/nlmon-control.log).
- [Large route tables](entry/large-tables.log).

Final three subset runs, all features / x86_64-unknown-linux-musl,
kernel 6.8.0-147-generic, are linked in the transcripts below. Each run
records its exact Docker command, image ID, baseline identity, build,
kernel and libtest counts. The Incus case and ordinary parser self-check
are filtered from these ignored-only container runs; neither is counted
as passed there.

- [Run 1](entry/scenarios-compat-init-routes-1.log).
- [Run 2](entry/scenarios-compat-init-routes-2.log).
- [Run 3](entry/scenarios-compat-init-routes-3.log).

Boot/clock scenarios, the complete manager-version combinations, missing
support/capability scenarios, 300-entry scale/resource proof, H20
fragmentation, the full conditional-promise list, kernel matrix, merged
100% coverage and root system-unit sandbox remain open. No strict CI
flag has been enabled.
