# Phase 6 P2 implemented host subset — 2026-10-30

This is a partial scenario suite, not a completed P2 gate. The Rust
cases cover H1, H2, H3, H5, H6, H7, H9, H10, H12, H13, H14 and H18.
They assert frame delivery/drop counters, kernel objects, interface
indices, event/log outcomes and bounded waits in disposable containers.
H7 covers the VRF join/nomaster and scoped-member path; the complete
multi-clause H7 case list is not claimed by that one case.

The runner builds all features for `x86_64-unknown-linux-musl`, mounts
the checkout read-only at its absolute path, and uses
`docker run --rm --privileged --network none`. Each run records the
image ID, command, target/features, build output and `uname -r`.
The three final executions all used `6.8.0-147-generic`:

| Command | Cases | Duration | Record |
|---|---|---|---|
| `tests/docker/run.sh scenarios` | 12 passed, 0 failed | 57.14 s | [run 1](scenarios-20261030T065128Z-3053777/run.log) |
| same | 12 passed, 0 failed | see log | [run 2](scenarios-20261030T065231Z-3055726/run.log) |
| same | 12 passed, 0 failed | see log | [run 3](scenarios-20261030T065332Z-3057215/run.log) |

Those runs compiled the separately exercised Incus case but filtered it
out; it was not counted as a pass. Incus results are recorded separately.
The entrypoint gains Incus dispatch with the P5 package.

F3's cached-master regression fails before the fix and passes after it.
Convergence now reuses known membership rather than issuing a parent
lookup every time. A changed master still needs classification; a failed
classification is not cached. Both ordinary and VRF parents are covered
by the fake test, and the final live repetitions above exercise VRF
membership changes after the fix.

- [F3 regression before](entry/f3-before.log).
- [F3 regression after](entry/f3-after.log).
- [Runner transcripts](entry/scenarios-repeat-1.log),
  [second](entry/scenarios-repeat-2.log),
  [third](entry/scenarios-repeat-3.log).

Earlier fixture failures remain in the accompanying entry/scenario logs:
initial ARP synchronization, incorrect IPv6 text matching, lost IPv6
addresses on VRF enslavement, and an iproute2 dump that did not honor the
test's assumed identifier filter. These were fixture corrections, not
daemon fixes or successful gate runs.

H4/H16 boot/clock cases, H8/H17 scale, H11 manager-version combinations,
H15 fallbacks, H19 init behavior, G11 interoperability and the complete
conditional-promise case list remain open. The matrix and global merged
coverage are also open. No strict CI flag has been enabled.
