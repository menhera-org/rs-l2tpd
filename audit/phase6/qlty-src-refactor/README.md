# Source-smell refactor checkpoint

Source: signed `2ce54d281e0edbf2fb32d811f5cd027abbc9d954`, synced before
fresh qualification. Behavior, public APIs, test assertions, smell thresholds
and coverage exclusions are unchanged. Source patches are empty throughout.

| Function | Cognitive complexity before | After |
|---|---|---|
| pidfile::directory | 28 | 14 |
| lifetime::receive | 25 | 12 |
| lifetime::capture | 28 | 8 |
| events::link_new | 27 | 13 |
| events::addr_changed | 29 | 14 |
| events::monitor_resync | 29 | 16 |
| events::retain_devices | 26 | 9 |
| sessions::converge_session | 26 | 6 |
| store::retire_socket | 25 | 16 |
| runtime::wait_event | 26 | 11 |

The [cosmetic Dockerfile patch](dockerfile-cosmetics.patch) reflows/sorts the
builder package list and documents a local DL3018 exception for the existing
signed-index, networkless review-image package resolution. Package selection
is unchanged. The [Dockerfile linters](dockerfile-check.log) pass. These
changes are applied after the required matrix passes and the optional run is
stopped at the user's request.

The new helpers score at most 20; the highest remaining analyzed production function
scores 24. Explicit test matrices remain intact. See the exact
[before](qlty-src-before.log), [after](qlty-src-after.log),
[function metrics](target-function-metrics.log) and [commands](qlty-commands.log).

| Execution | Result and record |
|---|---|
| `./test-ci-gates.sh` | Pass; common-gates.log |
| `tests/docker/run.sh matrix required` | All 13 profiles pass; sibling matrix record |
| `sh tests/kernel/run-optional.sh RECORD` | Deferred by the user to step 6; [scope](optional/deferred.log); partial output is not a pass |
| Three serial `tests/docker/run.sh scenarios` / `incus` pairs | All pass; [summary](container-results.log), sibling runner records |
| `tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD` | ROOT_SYSTEMD_RESULT=0; [guest](systemd/run.log) |
| Maintained coverage calibration, ten GNU seeds, instrumented Ubuntu 7.0 guest, thread/fork failure profiles and merged checker | Pass; [merged report](coverage/merged-source-coverage.log) |
| Dispatch source-work and GNU/musl allocations | Pass in [build CI excerpt](build-ci.log) |
| Local maintenance and Markdown links | Pass; maintenance-checks.log |

Merged source coverage is 8,602/8,602 lines and 1,838/1,838 condition outcomes,
locally and in [CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41783315134).
Raw LLVM totals remain separate: 99.47% lines and 98.26% outcomes. Production
exclusions: none. The full [compressed export](coverage/llvm-export.json.xz),
[source/mapping inventory](coverage/source-and-mapping-inventory.json),
[raw summary](coverage/raw-coverage.log) and calibration controls are retained.
Checkout prefixes in logs, inventory and compressed JSON are normalized to
`CHECKOUT`; restore the absolute checkout prefix in both JSON files before
replaying the checker. Build/download timing is omitted; contract measurements
and suite results are retained.

Every completed normal required guest passes all 28 scenarios and 37 process
cases, plus 31 private live cases, 24 Linux cases and five review cases. Each completed
clock profile requires controller-confirmed pause/resume. All six optional
profiles must run on the final source at step 6. Exact releases,
configuration, package digests, executable identities and result markers
remain in the runner records. Kernel-only optional guests do not qualify
distribution userspace, SELinux or packaging. Ubuntu 24.04 userspace and
Ubuntu 6.8 are qualified separately by Incus and the unmodified system unit.
The earlier nlmon fixture fix and diagnostic controls remain in commit
`9817a0d19ac89d5cc0844180022ec8b0dfa07ce5`; the new matrix includes its regression.
No kernel.org HTML is retained. Current gating scripts live outside `audit/`.
