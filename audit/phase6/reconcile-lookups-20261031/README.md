# Indexed desired identities

Tunnel/session record matching, inherited tunnel/session matching and resolver
reload previously searched the accepted configuration for each record. Desired
identifier indexes now locate the configuration name directly. Complete kernel
identity checks still decide whether a record matches; an identifier alone
never proves ownership. Configurations already require unique identifiers.

The indexes are rebuilt on accepted configuration changes and cleared on
shutdown. They contain only current configuration names. The existing eight
reload epochs now check 31 collections, including both new indexes, against
the one-entry baseline. Removed conflict entries also check index cleanup on
empty reload and shutdown. Operator-name changes preserve the tunnel socket
and session device while replacing both index values.

`wanted_tests.rs` measures 500 paired tunnel/session lookups against the old
scans and the actual indexed methods. Synthetic records avoid opening one
socket per configuration entry. Both return identical results; separate cases
reject mismatched tunnel/session identifiers, peer identifiers and cookies.
The workload makes zero kernel requests. Measurements have no timing threshold.

| Entries | Old scans | Indexed methods |
|---|---:|---:|
| 1 | 0.35 ms | 0.39 ms |
| 100 | 48.58 ms | 1.56 ms |
| 300 | 159.09 ms | 1.69 ms |
| 1,000 | 764.97 ms | 2.18 ms |

The initial focused run is in `wanted.log`; each final seeded run repeats
these assertions and retains its own measurements. Lookup uses ordered maps;
this removes repeated full scans, not every cost in reconciliation. The rename
planner and event-triggered session recreation still need review.

`common.log` passes formatting, ShellCheck, warning-denied Clippy/docs, feature
builds, native/musl tests and both strict maps. All ten seeds pass: 112 ordinary
library cases, 68 fake cases, 78 rules, 27 service cases and eight startup/
resolver faults per seed. Twelve live library cases remain explicitly ignored
in native runs and execute in the separate live profile.

| Fresh profile | Result |
|---|---|
| GNU native coverage | Pass; all features, pinned nightly-2026-10-28 |
| GNU live probes | 12 library, 19 kernel, five review and three privileged binary cases pass |
| Full process suite | 27 pass in 17.77 seconds |
| Normal scenarios | 26 pass in 160.77 seconds |
| Real user manager | FD-store barrier and address-family checks pass |
| Instrumented unprivileged Incus | Full case passes in 8.95 seconds; seven daemon profiles exported |
| Unmodified musl Incus | Full case passes in 16.32 seconds; container deleted |
| Unmodified musl root systemd | Supplied unit passes in 26.73 seconds with no drop-ins |

The live kernel is Ubuntu `6.8.0-147-generic`. Both Incus profiles and the root
guest observe the concurrent udev MAC write refused with EBUSY, preserving the
kernel address. Ordered creations receive the same persistent address. The
approved H11 limitations apply. `root-systemd/` records the actual sandbox,
manager barriers, restart and cleanup; its separate README identifies scope.
The unmodified Incus record is `../incus-20261031T194638Z-253808/`.

Merged fresh coverage is **93.32% of production lines** (7,871/8,434) and
**80.95% of branches** (1,436/1,774), leaving **563 lines and 338 branches**.
No production exclusions or profile-mismatch warnings occur. Forty-eight
test-only modules and one helper exclude instrumentation while tests still
execute. No previous-source profiles are merged. The final consistent-source
matrix, complete clause/resource/event-cost proof and 100% coverage remain open.

The preceding dependency integration, commit `069b31b`, passes both jobs of
[CI run 41234101648](https://github.com/menhera-org/rs-l2tpd/actions/runs/41234101648)
on the first attempt, including the normal live guest. The workflow completes
in about 13½ minutes overall, within its configured timeout budgets.
`ci/iphost043-jobs.json` retains job metadata.

`revision` plus `source.patch` and `wanted_tests.rs` reconstruct the source;
copy the test file to `src/reconciler/` after applying the patch. Logs omit
Cargo build durations and user-manager CPU/memory accounting.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-wanted-final-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/reconcile-lookups-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/coverage-current-20261031/run-live.sh
sh audit/phase6/coverage-current-20261031/run-incus.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
tests/docker/run.sh incus
sh tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD
```

The real-manager command follows the preceding DHCPv6 queue record, using
unit `phase6-wanted-manager-20261031` and this collection's instrumented binary
from `native.log`. It retains Type=notify, NotifyAccess=all, FDStoreMax=8,
NoNewPrivileges, RuntimeMaxSec=30s and the supplied address-family filter.
