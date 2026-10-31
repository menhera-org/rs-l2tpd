# Indexed deadlines and cancellation of obsolete conflicts

Runtime::next_event previously called a selector that scanned all tunnel,
resolver, conflict, deletion and descriptor-retirement deadlines after
each event. This package replaces those scans with ordered deadline indexes
and fixes conflict history that survived configuration removal.

## Implementation and invariants

The private Deadlines helper keeps an owner-to-time map and a sorted
(time, owner) set. Replacing a deadline removes its previous time;
cancellation removes both entries. Each active owner has exactly one entry
in each index, and due iteration visits only due owners. Read-only map
access remains available; mutable map access cannot bypass index updates.
There is no dependency or new configurable interval.

Reconnect and resolver retry times move out of individual records into
these maps. Deletion maps gain time indexes. Left-out conflicts and
descriptor retirements update their indexes when armed, rearmed or
cancelled. The selector compares a fixed set of scalar deadlines and
indexed minima; it no longer scans configured records. Shutdown uses the
same indexed deletion/retirement minima and retains its existing deadline
cutoff semantics.

Tests cover empty queues, equal times, replacement, cancellation and
10,000 repeated updates of one owner. A further 10,000 seeded mutations
compare state, minimum and due owners against an independent map model.
Fake-kernel cases verify fixed retry times through unrelated events,
successful reconnect cancellation, removal cancellation and socket cleanup.

## Existing conflict-history defect

A ten-times-refused entry could remain in the conflict map after its
configuration was removed, retaining a slow retry indefinitely. The
[regression failed](conflict-before.log) before the cleanup fix, after the
deadline indexing itself had been implemented. On a changed configuration,
obsolete conflict identities and their timers are now discarded. Shutdown
also clears conflict counters and retries. The
[passing case](conflict-after.log) covers removal and shutdown and checks
that the foreign tunnel remains untouched.

## Selector workload

The same native debug/all-feature test performs 20,000 next-deadline
queries with 1, 300 or 20,000 pending deletion records. Each result must
equal the known earliest absolute deadline; the records must remain intact.
Only the query loop is timed.

| Pending records | Original scan, milliseconds | Indexed selector, milliseconds |
|---|---|---|
| 1 | 16.214 | 10.016 |
| 300 | 447.922 | 9.652 |
| 20,000 | 29,174.281 | 8.837 |

[Original workload](cost-before.log), [final focused cases](deadlines-final.log).
Timings are diagnostic observations, not a new SLA or a timing-based pass
condition. The assertions concern exact deadlines, contents and bounded
index cardinality.

## Executed checks

- [Ordinary all-feature tests](ordinary.log), [warning-denied Clippy](clippy.log)
  and [four strict source-link checks](srclink.log) pass.
- [Ten seeded rule runs](seeds.log), TEST_SEED=1 through 10, each pass
  all 74 rule/property tests. The planner expands each starting seed to
  32 sequences; these starting ranges overlap. This is scoped local
  determinism evidence, not completion of the full Phase 6 determinism/CI gate.
- [All 23 host scenarios](../scenarios-20261031T101443Z-3684488/run.log)
  pass on Ubuntu 6.8.0-147-generic in 153.40 seconds, including 300-session
  frames and zero kernel requests for unrelated link events.
- [All 26 process cases](process.log), including the ignored privileged
  cases, pass on that kernel in 17.42 seconds. These exercise real sockets,
  handover, shutdown and descriptor retirement; they do not replace P6's
  separate real-root-systemd sandbox check.
- [Mainline 7.3.0 clock guest](../qemu-deadline-clock-20261031/run.log)
  passes the one scoped H16 case and three host-controller checks.
  One-second retries and thirty-second wire DNS refreshes remain correct
  across forward/backward wall-clock steps and a confirmed three-second
  QMP pause. Its zero markers apply only to this clock profile.

The baseline is in [revision](revision). [source.patch](source.patch) and
[extra-source-hashes.log](extra-source-hashes.log) identify the tested
tracked changes and new helper. Final snapshots must match byte for byte.
The original selector workload uses the baseline implementation plus its
new measurement test; the conflict-before failure is a later intermediate
stage, not the pre-index source. Earlier intermediate logs are retained.

All privileged actions ran in disposable containers or the guarded QEMU
clock guest; the host clock, network and units were untouched.

## Remaining Phase 6 work

Indexed lifetime deletion and deadline selection are now implemented.
Complete G12/M16 proof still needs the cost of relevant-event cache
maintenance and the other event paths, not only the unrelated-event
zero-request assertion. Remaining rule clauses, full resource/history
proof, current-source 100% merged coverage, the full latest-target
matrix, final Incus/root-unit refreshes and strict CI remain open.
No strict flag or global gate is enabled by this package.

[Exact commands](commands.log), [strict rule-map output](rulemap.log),
[final source snapshot](final-source.patch) and
[final helper identity](final-extra-source-hashes.log) complete the record.
The strict map remains at 275 cited / 58 missing active rules (exit 101).

The shared pre-commit script was added by concurrent contributions while
this package was running. It was missed before commit 0f8818e; the complete
[shared CI gates](ci-gates.log) subsequently passed on that source, before
this verification follow-up. This adds repository-wide ShellCheck,
no-default/serde library and daemon builds, native/musl tests and
warning-denied documentation to the package's earlier checks. Its map
checks retain the script's lenient defaults; no full Phase 6 gate is
claimed. The intervening contributions changed CI/quality configuration,
documentation and shell helpers; the tested Rust sources were unchanged.
