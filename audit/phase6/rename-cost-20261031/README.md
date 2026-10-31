# Rename planning and targeted session recreation

The rename planner now indexes current holders and waiting targets and drains
an ordered ready set. It releases acyclic dependencies before staging cycles.
Indexes hold sets of identifiers, so duplicate cached names do not disappear
when only one holder moves. All bookkeeping follows confirmed mutations;
failed renames retain their prior state. The maps live only for this reconcile.

The same six-case workload runs against `00e9d2d` and the proposal. It checks
1, 100 and 300 sessions in reverse dependency chains and cycles, requires every
device index to survive and all target names to match, and forbids creation,
deletion or socket closure. Acyclic chains must use no temporary name.

| Sessions | Baseline chain | Indexed chain | Baseline cycle | Indexed cycle |
|---|---:|---:|---:|---:|
| 1 | 0.19 ms | 0.08 ms | 0.04 ms | 0.05 ms |
| 100 | 20.44 ms | 3.21 ms | 4.06 ms | 3.39 ms |
| 300 | 397.45 ms | 12.64 ms | 23.29 ms | 18.01 ms |

`baseline.log` and `final-focused.log` retain nanoseconds and operation counts.
There is no timing threshold. Fake-kernel mutation cost remains part of these
measurements. The earlier before-identity-index logs use `87f7470` and are
supplementary; they are not the baseline for this table.

A separate baseline regression demonstrates unrelated work on an event path.
An initial creation failure leaves one session pending. Deleting another
session and forwarding its deletion notice used to retry both entries.
`recreate-baseline.log` fails because the unrelated session is created before
its own retry. `recreate-fixed.log` passes: the deleted session returns at once;
the unrelated one waits for the scheduled retry and does not disturb it.

Event recreation now uses the desired identifier index and releases only the
confirmed session's matching creation-name reservation. A unit case preserves
reservations with another tunnel or session identifier. Other new cases cover
a removed middle of a rename chain, a failed rename, overlapping retained
targets and duplicate cached names. The first removal fixture omitted fake
kernel work/notice delivery; its failure is retained separately. Final fixtures
advance the virtual kernel and forward its notices.

Common checks and ten seeded repetitions pass: 116 ordinary library cases,
68 fake conformance cases, 80 rules, 27 service cases and eight startup/resolver
faults per seed. Native runs explicitly ignore 12 live library cases; the live
profile executes all 12. Formatting, ShellCheck, Clippy, feature builds,
native/musl process/startup, strict maps and warning-denied docs pass.

| Fresh profile | Result |
|---|---|
| GNU native and live | All ordinary cases, 12 live library, 19 kernel, five review and three privileged binary probes pass |
| Full process suite | 27 pass in 18.09 seconds |
| Normal scenarios | 26 pass in 158.56 seconds |
| Real user manager | FD-store barrier and address-family assertions pass |
| Instrumented unprivileged Incus | Full case passes in 9.20 seconds; seven daemon profiles exported |
| Unmodified musl Incus | Full case passes in 26.43 seconds; container deleted |
| Unmodified musl root systemd | Supplied unit passes in 27.10 seconds with no drop-ins |

The kernel is Ubuntu `6.8.0-147-generic`, with all features. Coverage uses GNU,
pinned nightly-2026-10-28 and cargo-llvm-cov 0.9.1; unmodified P5/P6 use stable
musl binaries. Both Incus profiles retain the kernel address after concurrent
udev EBUSY and require the same persistent address on both ordered creations.
The root guest's concurrent creation gets the persistent address. Approved
H11 limits are unchanged. The unmodified Incus record is
`../incus-20261031T195738Z-289841/`; root evidence is in `root-systemd/`.

Fresh merged coverage is **93.29% of production lines** (7,906/8,475) and
**80.91% of branches** (1,445/1,786), leaving **569 lines and 341 branches**.
No production exclusions or profile-mismatch warnings occur. Forty-eight
test-only modules and one helper exclude instrumentation while tests execute.
This batch closes two measured cost defects, not the full event-cost/resource
proof. Complete clauses, 100% coverage and the final five-target matrix remain
open. Store-retirement scans and topology-cache bounds still need review.

The preceding identifier-index source passes both jobs on the first attempt in
[CI run 41236261835](https://github.com/menhera-org/rs-l2tpd/actions/runs/41236261835),
including normal guest conformance. `ci/wanted-jobs.json` retains metadata.
The standalone documentation commit also passes CI run `41235519537`.

`revision` plus `source.patch` reconstruct the final source. For either baseline,
archive the named revision and append `regression.rs` to
`tests/rules/sessions.rs` and `recreate-regression.rs` to `tests/rules/events.rs`.
No production code changes in those baseline fixtures. Logs omit Cargo build
durations and user-manager CPU/memory accounting.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-renames-final-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/rename-cost-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/coverage-current-20261031/run-live.sh
sh audit/phase6/coverage-current-20261031/run-incus.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
tests/docker/run.sh incus
sh tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD
```

The manager command follows the preceding lookup record, with unit
`phase6-renames-manager-20261031` and this collection's instrumented binary.
