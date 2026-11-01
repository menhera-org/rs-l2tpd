# Generic-netlink family cache recovery

Three cases exercise the existing family-cache contract. A cached family
without its multicast group returns ENOENT on repeated subscription attempts.
An expired request returns ETIMEDOUT while retaining the resolved family.
A live kernel's ENOENT clears a stale family, after which family resolution,
an absent-tunnel query and a multicast subscription succeed.

`revision` identifies signed b22ed23; `source.patch` adds only tests at the
end of l2tp.rs. Production code, public APIs and dependencies are unchanged.
The stale-cache fixture seeds the absent family ID 65535. It exercises the
actual kernel refusal and recovery path; unloading a kernel module is
outside this fixture's scope. The missing-group fixture seeds the private
cache and uses a real userspace netlink socket; it establishes adapter
refusal behavior, not a claim that a required kernel omits the L2TP group.

Ten native and ten instrumented library runs with distinct TEST_SEED values
pass, as do three musl library runs and final common checks. The ordinary
library has 249 passing declarations and 20 ignored. Instrumentation adds
the existing shared live/startup cases, leaving 47 in the serial profile.
The new live recovery case passes three GNU and three musl repetitions on
Ubuntu 6.8.0-147-generic in disposable networkless containers.

Three isolated, uninstrumented controls fail their intended assertions:
using group zero when absent, discarding the family after a transport
failure, and retaining the stale family after ENOENT. Their patches apply
after source.patch. The control source is restored; no control profiles
enter the coverage collector. Source evidence for vanilla 6.8.12, 7.0.14
and 7.3 records genl_rcv_msg returning ENOENT for an absent family.

All 4,320 complete mappings remain identical. Coverage reaches
8,431/8,671 lines (97.23%) and 1,677/1,850 branches (90.65%), leaving
240 lines and 173 branches. There are no production exclusions, profile
mismatches or saturated regions.

The frozen production matrix at 584062d retains its own scope and excludes
these later declarations. Required-target qualification of the new case,
complete clause/history/resource/event-cost proof and 100% coverage remain
open.
