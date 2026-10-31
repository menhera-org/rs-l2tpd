# Indexed lifetime deletion handling

The H17 review found that every RTM_DELLINK scanned all tracked lifetime
registrations, including for an unrelated interface. This package removes
that scan without adding another index or a dependency.

## Change and correctness checks

Lifetime registrations now use a standard-library BTreeMap keyed by
(interface index, incarnation), with an observed-removal flag. A deletion
looks up the index's key range and visits only its registrations.
Proofs, release and refused-creation disarming use the exact pair.
An older registration can remain removed while a new registration with
the same interface index is still present; releasing the old one cannot
discard the new proof. Generation loss clears the entire registration map.

This replaces the registration HashMap, its duplicate index field and
its geometric capacity-shrink code. The socket-owner HashMap's H17
shrinking remains unchanged. The registration retirement test now checks
surviving records and generation cleanup, rather than a HashMap-specific
capacity. It is not a byte-level heap measurement.

The new unit cases exercise unrelated and forged deletions, multiple
incarnations sharing an index, a later capture after removal, exact
release/disarm, a mismatched index, and completed retirement.
The live overflow and foreign-sender cases still prove generation loss
and ordered kernel proofs. No kernel protocol, timer or normative rule
changes.

## Before/after workload

The same native debug/all-feature case creates 1, 300 or 20,000 tracked
registrations through the actual capture decoder, then supplies 20,000
unrelated kernel-format deletion notifications. The measured loop excludes
fixture creation. Assertions require the records, capture state and
incarnation count to remain correct.

| Current registrations | Before scan, milliseconds | Final indexed lookup, milliseconds |
|---|---|---|
| 1 | 23.274 | 25.180 |
| 300 | 209.188 | 32.028 |
| 20,000 | 12,315.358 | 42.659 |

[Before](cost-before.log), [initial after](native-after.log),
[final native cases](native-final.log). The measurements demonstrate the
removed dependence on scanning all registrations; they are not a fixed
performance SLA or a wall-time assertion. The pass conditions remain
deterministic state assertions. Ordered-map lookup still has its normal
search cost; matching registrations are the only values traversed.

Command:

```sh
cargo test --locked --all-features --lib kernel::linux::lifetime::tests -- --nocapture
```

## Executed verification

- [Ordinary all-feature tests](ordinary.log), [Clippy with warnings denied](clippy.log)
  and [four strict source-link checks](srclink.log) pass.
- [32 live kernel cases](live.log) pass on Ubuntu 6.8.0-147-generic:
  11 library, 16 kernel conformance and five review cases. The log records
  all three executable identities and the actual nonzero test counts.
- [All 23 host scenarios](../scenarios-20261031T094744Z-3644024/run.log)
  pass in 155.60 seconds, including bidirectional traffic through every
  one of the 300 sessions, 600 unchanged-reload requests and zero requests
  across unrelated link events.
- [Strict rule map](rulemap.log) still fails: 343 total, 333 active,
  275 cited, 58 missing. No strict CI flag is enabled.

The host scenario command is `tests/docker/run.sh scenarios`. For the live
library/conformance/review run:

```sh
cargo test --locked --all-features --target x86_64-unknown-linux-musl \
  --lib --test kernel-linux --test review-kernel --no-run
# For each of the three emitted executables:
docker run --rm --privileged --network none \
  --mount type=bind,source="$PWD",target="$PWD",readonly \
  --entrypoint sh rs-l2tpd-audit-vm:local -ec 'uname -r; exec "$@"' run \
  EXECUTABLE --ignored --test-threads=1 --nocapture
```

The first standalone live command omitted the input redirection on its
executable-list loop and ran no executable. Its misleading result marker
is retained in [live-empty-loop.log](live-empty-loop.log) as a harness
error, not a pass. The corrected command requires exactly three input
executables, a successful nonempty test result from each, and exactly
three completed runs before recording success.

The baseline is in [revision](revision). [source.patch](source.patch)
records the first tested source; [final-source.patch](final-source.patch)
additionally includes exact disarm assertions in the existing unit case.
Production source is identical across the passing host/live/final native
profiles. All privileged work was inside disposable containers with
networking disabled; no probe container remains.

## Remaining Phase 6 work

This closes the lifetime subscriber's global deletion scan, not the whole
G12/M16 event-cost proof. Runtime::next_event still recomputes
Reconciler::next_deadline after events; that selector scans all tunnel
timers and other deadline records. Its cost still needs correction and
verification. Resolver/event-history bounds, remaining rule clauses,
current-source 100% merged coverage, the complete latest-target matrix,
final Incus/root-unit refreshes and strict CI also remain open.

[Exact commands](commands.log), [Cargo live-build output](live-build.log),
[container image identity](live-image.log) and [final formatting/diff checks](final-checks.log)
complete the record. Local Markdown file targets were also checked.
