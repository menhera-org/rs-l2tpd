# Phase 6 verification, 2026-11-01

Phase 6 is incomplete. The current implementation is identified by the
[streamed-inventory record](phase6/streamed-inventories-20261101/README.md),
its `revision` and `source.patch`. It builds on production `eeec257`; the
approved contract and fixture changes are in `c6f10e9`. The
[tunnel-state record](phase6/tunnel-application-status-20261101/README.md)
and [maintainer decisions](phase6/maintainer-decisions-20261101/README.md)
identify exact sources, commands, features, results and retained failures.
[The October 31 checkpoint](PHASE6_VERIFICATION_2026-10-31.md) retains
preceding work and its original scope.

## Gate status

| Requirement | Executed evidence | Still required |
|---|---|---|
| P1 rule/source maps | Current strict common checks pass. The [strict qualification](phase6/strict-gates-20261031/README.md) retains its ten seeded fake/live CI repetitions | Maintain enforcement; declaration citations do not establish complete clause proof |
| P2 scenarios | Approved normal suite passes 26 cases three times in 158.12, 162.29 and 157.99 s, including H20 and H17 | Complete clause/resource/event-cost proof; keep host-kernel scale runs serial under the documented shared budget |
| P3 required kernels | [November 1 matrix](phase6/matrix-20261101T003757Z-933582/README.md): five normal and five clock profiles, two IPv6-absent profiles and missing-driver profile pass; publication checks agree | Qualify the final daemon/fixtures after the later socket fixes and streamed inventories |
| P4 coverage | Fresh production collection: 95.51% lines, 86.17% branches; no production exclusions or saturated regions | Cover 385 lines and 253 branches; enforce the completed 100% gate in CI |
| P5 Incus/LXD | Current full unprivileged Incus case passes in 8.95 s with seven daemon profiles; the approved policy also retains its three earlier fresh-container passes | Repeat after relevant implementation changes; results remain scoped to the recorded userspace/kernel |
| P6 root sandbox | Unmodified supplied unit passes the shared corrected manager case in 26.64 s on Ubuntu 6.8.0-147-generic, ROOT_SYSTEMD_RESULT=0 | Final-source qualification after relevant changes |
| P7 docs/CI | Required-kernel distinctions and approved limits are documented. Strict flags and bounded workflow budgets remain active | Final consistent-source record and complete proof/coverage enforcement |

The preceding socket implementation passes both jobs in
[CI run 41262268588](https://github.com/menhera-org/rs-l2tpd/actions/runs/41262268588),
about fourteen minutes overall, without timeout. Its
[job metadata](phase6/maintainer-decisions-20261101/ci-production-jobs.json)
is separate from the newer contract/fixture commit's pending CI.

## Kernel snapshot and manager scope

The November 1 resolver selected Ubuntu 6.8.0-147.147 and 7.0.0-42.42,
vanilla equivalents 6.8.12 and 7.0.14, and mainline 7.3. Initial and final
selections match. The matrix froze `bdf81b5`: each normal guest passes
14 privileged library, 20 Linux, five review, binary/process and 26 normal
scenario cases. Five separate H16 clock/QMP profiles also pass.

This snapshot includes newer monitor, descriptor, process and index-reuse
assertions absent from the preceding matrix. It predates the current
socket application/cleanup fixes and the approved MAC/timing fixtures;
its success does not qualify those changes. [Per-target behavior](../docs/kernel-behavior.md)
records precise errno, namespace-notification, lifetime, boot and manager
differences. Broader distributions and live non-x86 architectures remain
unrun. The Incus/root-manager results apply to their Ubuntu 24.04 userspace
on Ubuntu 6.8.0-147, independently of the bare-kernel matrix.

## Current socket fixes and coverage

The reconciler now reports required disconnect/bind failures as unapplied,
while a refused peer remains a valid disconnected state. Unspecified-source
cleanup restores the configured binding through the existing shared path;
failed cleanup/restoration retries without claiming success. Simultaneous
full-reconcile and per-tunnel deadlines attempt each tunnel once.

Baseline controls fail on premature application success, duplicate attempts
and the missing post-cleanup binding. The corrected implementation passes
ten seeded ordinary suites, three musl library/fake/rule suites, common
checks, cross-target musl compile checks, full GNU live/process cases,
a real user manager, Incus and the root sandbox.

The [fresh summary](phase6/streamed-inventories-20261101/coverage-summary.json)
reports 8,193/8,578 lines and 1,577/1,830 branches covered. Only this
production implementation's profiles contribute; superseded implementations
remain separate. Test-only bodies/helpers are excluded under the approved
production scope while their tests execute. No production exclusion,
profile mismatch or saturated region is recorded. ARM64, RISC-V64 and
PowerPC64LE results are compile checks only.

## Approved decisions and unfinished work

- **H11 MAC authority:** the maintainer approved the documented later-udev
  limitation and explicit `.link` policy for the staged configured MAC.
  Concurrent and ordered persistent-MAC checks remain intact. The original
  [failure and controls](phase6/staged-mac-override-20261031/README.md)
  remain retained; the corrected fixture now has three fresh Incus passes.
- **G23 dependency state:** the maintainer approved counting current link/
  address state needed by configured dependencies, with streamed temporary
  inventories and release after the final dependency. The
  [witnesses](phase6/resource-cache-bounds-20261031/README.md) remain retained.
  The written contract and streaming implementation are applied. Six
  direct/VRF resource cases check 1–10,000 entries and final-reference
  cleanup. Completion-failure cases reject staged data; their negative
  control fails. Full byte/resource/event-cost proof remains a separate gate.
- **H6 retry timing:** the maintainer approved the
  [deadline/completion distinction](phase6/route-retry-timing-20261101/README.md).
  Exact one-second deadlines remain checked with the fake clock. Live tests
  record observed delay and retain the existing ten-second event timeout
  plus connection/frame checks. Earlier 168/375-microsecond overshoots are
  preserved; three corrected normal suites pass.
- **Nix signal errors:** [PR #2852](https://github.com/nix-rust/nix/pull/2852)
  remains open, awaiting integration and a compatible release. Independent
  [PR #2853](https://github.com/nix-rust/nix/pull/2853) fixes its unrelated
  overflow-fixture CI failure and has a passing full workflow; it is also
  unmerged. [Signal evidence](phase6/upstream-signal-errors-20261031/README.md)
  and [overflow controls](phase6/upstream-overflow-fixture-20261031/README.md)
  retain both fixes. No daemon workaround or local dependency override is
  applied.

The [neighbour-pressure control](phase6/neighbour-pressure-20261101/README.md)
reproduces packet loss with two simultaneous 300-session workloads in one
isolated guest: both fail and the ARP overflow counter rises by two. The
same traffic runs alone without overflow. Host-kernel qualification now
runs serially; three unchanged normal suites pass. Earlier host transcripts
lack counter deltas, so the control establishes the shared-budget mechanism
rather than direct attribution of every historical packet drop.

The final matrix, 100% report and complete clause/resource/event-cost proof
remain unfinished.
