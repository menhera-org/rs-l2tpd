# User-manager, task-limit and root-sandbox qualification

Signed code `419c9b1a1294122222765f4891929f13aeb03eef` passes three GNU
user-manager runs and three genuine container task-limit repetitions.
Each manager run checks the template's address-family restrictions, stores
one descriptor, waits for processing, withdraws it and observes zero stored
descriptors. Each task-limit repetition refuses both signal-thread creation
positions with EAGAIN before kernel startup; no panic or readiness is reported.
All transient manager units and test containers are gone.

The unmodified supplied root system unit also passes its sandbox scenario
in **26.72 s** under QEMU. The guest uses Ubuntu 24.04 userspace and the stock
Ubuntu 6.8.0-147-generic image/modules. The fixture checks mount protections,
capabilities, ordering, descriptor storage and cleanup; `ROOT_SYSTEMD_RESULT=0`
is present. This is one root-unit scenario, not a full required-kernel matrix
or a result for other distribution userspaces.

The source patches are empty and agree. GNU profiles from manager/task-limit
runs are merged; the root guest uses stable musl binaries. Coverage remains
**8,503/8,687 lines (97.88%) and 1,702/1,852 branches (91.90%)**, with no profile
mismatch or saturated region. There are no production changes or exclusions;
P4 still lacks 184 lines and 150 branches.

`commands.sh` records the commands and `native.log` identifies the instrumented
executables. An initial wrapper had an awk quoting error before any test ran.
The corrected wrapper passes syntax/ShellCheck and all recorded runs.
Cleanup verification matches unit names, allowing a zero-unit listing footer.
No Phase 6 completion is claimed.
