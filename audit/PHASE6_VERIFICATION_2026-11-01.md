# Phase 6 verification, 2026-11-01

Phase 6 is incomplete. This checkpoint summarizes the current evidence;
[the October 31 record](PHASE6_VERIFICATION_2026-10-31.md) retains earlier
runs, failures and corrections. The current implementation is
`694735e56f836d5ae461ec50d05b9bfe60512699`. Its
[fresh lifetime-state record](phase6/tracked-lifetime-20261101/README.md)
identifies exact source, commands, features, kernel, counts and logs.

## Gate status

| Requirement | Executed evidence | Still required |
|---|---|---|
| P1 rule map | Current strict common checks pass. The [CI qualification](phase6/strict-gates-20261031/README.md) retains ten passing seeded fake/live jobs for its identified source | Keep enforcement; declaration citations do not establish clause proof |
| P1 source links | Current strict check passes with no uncited Linux functions; delegated/source-only facts retain evidence-map classification | Maintain source assertions and execution scope as targets change |
| P2 scenarios | Fresh GNU collection passes 26 normal scenarios on Ubuntu 6.8.0-147-generic in 161.25 s, including H20 fragmentation and the 300-tunnel/session case | Complete clause/resource/event-cost proof; resolve the current-host-state G23 bound |
| P3 required kernels | The [October 31 matrix](phase6/matrix-20261031T213935Z-567802/README.md) returns MATRIX_RESULT=0 for five normal and five clock profiles, plus scoped IPv6-absent and missing-driver boots | Re-resolve published targets and qualify the final source/fixture set |
| P4 coverage | Fresh production merge: 95.05% lines, 85.07% branches; zero exclusions and saturated regions | Cover 422 lines and 270 branches; enforce the completed 100% gate in CI |
| P5 Incus/LXD | Fresh unprivileged Incus case passes in 19.78 s; seven daemon profiles exported, receive-buffer fallback checked | Resolve staged-MAC H11 contract and establish required determinism; individual passes do not cancel the retained failure |
| P6 root sandbox | Unmodified musl root-systemd case passes on Ubuntu 6.8.0-147-generic in 28.04 s, ROOT_SYSTEMD_RESULT=0 | Repeat after relevant changes; no other-userspace sandbox claim |
| P7 documentation/CI | README/index/testing status now distinguish the passing matrix snapshot from final qualification. Strict flags remain enabled; CI budgets remain bounded | Final consistent-source record, complete proof and coverage enforcement |

[CI run 41255403378](https://github.com/menhera-org/rs-l2tpd/actions/runs/41255403378)
passes both jobs for `54e99d2`, about sixteen minutes overall. Runs for later
commits remain separate from that result. No timeout was observed in this
completed run. Current implementation CI is
[run 41256606416](https://github.com/menhera-org/rs-l2tpd/actions/runs/41256606416),
still pending at this checkpoint.

## Required-kernel snapshot

These are the versions actually resolved and tested on October 31, not a
claim that the publication indexes remain unchanged on November 1.

| Target | Guest release | Normal / clock |
|---|---|---|
| Ubuntu 24.04, 6.8.0-147.147 | 6.8.0-147-generic | 26 scenarios pass / pass |
| Vanilla equivalent | 6.8.12 | 26 / pass |
| Ubuntu 26.04, 7.0.0-42.42 | 7.0.0-42-generic | 26 / pass |
| Vanilla equivalent | 7.0.14 | 26 / pass |
| Mainline 7.3 | 7.3.0 | 26 / pass |

The source was frozen independently of subsequent work. Each normal guest
also passed its recorded live conformance, binary and process suites.
[Per-target behavior](../docs/kernel-behavior.md) gives errno, notification,
cleanup, boot and manager distinctions. The mainline IPv6-absent boots and
Ubuntu 7.0 missing-driver case are separate scoped profiles. Desired broader
kernel/distribution coverage remains unrun. Final qualification must include
the later monitor, descriptor, process and index-reuse assertions.

## Fresh production coverage

The new collection uses `nightly-2026-10-28` with branch instrumentation for
x86_64 GNU. The shipped musl builds remain on stable. Native tests, full live
library/Linux/review/process cases, normal scenarios, a real user-manager
case and an unprivileged Incus case contribute profiles from one production
implementation. Earlier production implementations are not merged.

The [summary](phase6/tracked-lifetime-20261101/coverage-summary.json) reports
8,098/8,520 production lines and 1,538/1,808 branches covered. The fake has
828/828 lines and 130/136 branches. Test-only bodies/helpers remain excluded
from instrumentation under the maintainer-approved production scope, while
the tests execute. There are no production exclusions or saturated inferred
regions. All-target/all-feature ARM64, RISC-V64 and PowerPC64LE musl checks
pass; those are compile checks, not live architecture results.

The preceding [repeated-operation](phase6/repeated-operations-20261101/README.md)
and [closed-receiver](phase6/closed-host-receiver-20261101/README.md) records
retain their separate source/mapping checks and GNU/musl repetitions. Their
assertions also execute in the new native collection.

## Pending decisions and upstream integration

[Phase 6](../docs/phase6.md#rules-that-hold-for-the-whole-phase) requires:
"Never weaken a rule to make a gate pass." Both proposals below remain
unapplied while independent work continues.

- **H11 staged configured MAC:** the committed daemon can have its configured
  MAC replaced by a later udev persistent assignment. The
  [failure and authority control](phase6/staged-mac-override-20261031/README.md)
  retain a reviewable proposal documenting later manager authority and giving
  the configured-MAC fixture an explicit `.link` policy. The previously
  approved concurrent/ordered persistent-MAC contract stays in force.
- **G23 current dependency state:** with one configured tunnel, witnesses
  retain 100 to 10,000 current addresses or VRF member records. The
  [bound proposal](phase6/resource-cache-bounds-20261031/README.md) would count
  required current dependency state and require streaming temporary inventories.
  Approval would not itself fix the existing full-namespace dump vectors.
- **Nix signal errors:** pinned 0.30.1 can report success after a refused
  signal-mask syscall. [PR #2852](https://github.com/nix-rust/nix/pull/2852)
  remains open, awaiting integration and a compatible release. Its regression
  passes native GNU/musl jobs; their full CI finds an unrelated old overflow
  fixture. Independent [PR #2853](https://github.com/nix-rust/nix/pull/2853)
  fixes that fixture and has a passing CI run. Both PRs remain unmerged.
  [Signal evidence](phase6/upstream-signal-errors-20261031/README.md) and
  [overflow controls](phase6/upstream-overflow-fixture-20261031/README.md)
  retain the fixes. No local dependency override or daemon workaround is applied.

The 100% report, final required-kernel qualification and complete clause/
resource/event-cost proof are unfinished. This checkpoint records progress;
it does not mark any missing requirement passed.
