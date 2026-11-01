# Reconciler record guards and parent retirement

Four test-only additions qualify existing session and tunnel guards.
Production code is unchanged from `revision`; `source.patch` and
`final-source.patch` agree.

- A pending name already observed as the configured target becomes applied
  without a rename or other kernel write, preserving registration identity.
- A direct defensive-helper case removes the stored creation name. Verified
  deletion must return without scanning or guessing a name; a queued scan
  failure remains unconsumed and the kernel object stays intact. This is
  a unit boundary check, not a claim that an observed live kernel produced
  this record state.
- Failed child deletion must not retain a local session record after its
  unwanted owned parent closes. Deferred deletion completes and reservations
  are released after the fake kernel advances.
- An unwanted adopted parent clears unmatched-child retry state and its
  existing failure report even when the deletion retry fails again.

All twelve wanted/session unit cases pass three focused GNU and three musl
runs. Ten native and instrumented model/rule/service/startup repetitions,
three musl model runs, common gates, Rust 1.89 and three further musl
architecture compile checks pass. The latter are compile checks only.
Five independent uninstrumented controls each fail the intended new case,
leaving eleven passing unit cases: redundant rename, guessed missing name,
retained orphan record, retained unmatched child, and retained report.

The report reaches **8,474/8,687 lines (97.55%) and 1,695/1,852 branches
(91.52%)**, leaving 213 lines and 157 branches. All 4,319 mappings match
the preceding service-queue report. No production exclusion, profile
mismatch or saturated region is present. The collector continues the
unchanged checked-reply implementation; profiles from earlier production
implementations are not merged.

These are fake-kernel policy and helper cases on local GNU/musl executables.
They add no per-target live, manager or system-container qualification.
The unchanged production implementation retains its frozen 3f503cd required
matrix. The global coverage and complete clause-proof gates remain open.
