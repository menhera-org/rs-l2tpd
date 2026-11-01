# Released iphost 0.4.4 integration: qualification in progress

The manifest and lockfile use the downloaded crates.io release. The signed
upstream correction, package verification, three failing 0.4.3 witnesses
and three passing released-0.4.4 witnesses are recorded in
[anonymous Reply validation](../anonymous-reply-20261101/README.md).

`revision` identifies 0ea073d; `source.patch` records the complete source
under qualification, including the standard-library boundary changes.
The specification, public API and resolver policy are unchanged.

The initial ten native repetitions, three musl model runs and GNU live
profile pass. The common gate then rejects deprecated fetch_update on
current stable. Rust 1.89 rejects its replacement try_update, so a narrow
method annotation retains MSRV compatibility. Logs from that first source
are separated under `initial-api-attempt/`; their passing results do not
qualify the final source. A fresh collector and final common/model runs
pass after the annotation. No initial profiles enter the final collector.

A subsequent common run exposes a test budget error: the invalid-data
barrier case times out before the helper writes its byte. Its 200 ms
budget now applies only to the held-descriptor timeout case; the data
case gets the fixture's three-second budget. The required invalid-response
diagnostic remains exact. This changes only a test body. The failed run
is retained as `initial-api-attempt/short-barrier-budget-failure.log`.

## Final-source results

Common checks pass, including Clippy, feature builds, all tests, strict maps
and warning-denied docs. Ten native seeds and ten instrumented library
seeds pass using TEST_SEED=1 through 10. Three musl model/binary runs, Rust
1.89 and all-target checks for ARM64, RISC-V64 and PowerPC64LE musl pass.

GNU live passes 22 serial library, 24 Linux, five review, three privileged
binary, 29 process and 27 normal scenario cases (164.94 s for scenarios).
GNU Incus passes in 17.79 s, with seven daemon profiles and container
cleanup. The actual user-manager case and three task-limit profiles pass.
The unmodified root-systemd sandbox passes in 30.97 s on Ubuntu 24.04
with 6.8.0-147-generic.

The corrected barrier case passes ten native and three musl repetitions;
accepting invalid data makes its control fail. Its test-only budget edit
preserves all 4,302 production coverage mappings. Four separate boundary
controls also fail. Failed-control profiles never enter coverage.

The fresh merged report is **8,416/8,671 lines (97.06%)** and
**1,666/1,850 branches (90.05%)**: 255 lines and 184 branches remain.
There are no production exclusions, mismatched profiles or saturated
regions. The preceding 97.01% / 89.89% report remains historical.

The first repetition commands used unused seed variables; their logs are
retained under initial-api-attempt/default-seed-repetitions and do not
count as distinct seeds. One musl invocation named the nonexistent fake
target; its failure is retained separately. Corrected commands use
kernel-fake and TEST_SEED.

Three musl scenario/Incus repetitions are running. The required-kernel
matrix remains open for this source. Complete clause/history/resource
proof and 100% coverage remain open.
