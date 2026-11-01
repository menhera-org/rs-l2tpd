# Phase 6 verification, 2026-11-01

Phase 6 is incomplete. The current implementation is identified by the
[checked libc signal record](phase6/libc-signals-20261101/README.md), its
`revision` and `source.patch`. It builds on the
[streamed inventories](phase6/streamed-inventories-20261101/README.md);
the approved contract and fixture changes are in `c6f10e9`. The
[tunnel-state record](phase6/tunnel-application-status-20261101/README.md)
and [maintainer decisions](phase6/maintainer-decisions-20261101/README.md)
identify exact sources, commands, features, results and retained failures.
[The October 31 checkpoint](PHASE6_VERIFICATION_2026-10-31.md) retains
preceding work and its original scope.

## Gate status

| Requirement | Executed evidence | Still required |
|---|---|---|
| P1 rule/source maps | Current strict common checks pass. The [strict qualification](phase6/strict-gates-20261031/README.md) retains its ten seeded fake/live CI repetitions | Maintain enforcement; declaration citations do not establish complete clause proof |
| P2 scenarios | Current normal suite passes 26 cases three times in 160.88, 160.96 and 161.00 s, including H20 and H17 | Complete clause/resource/event-cost proof; keep host-kernel scale runs serial under the documented shared budget |
| P3 required kernels | [Streamed-inventory matrix](phase6/matrix-20261101T025846Z-1217029/README.md): five normal and five clock profiles, two IPv6-absent profiles and missing-driver profile pass; publication checks agree | Qualify the later checked libc signal calls and test additions |
| P4 coverage | Compatible production collection: 96.00% lines, 87.81% branches; no production exclusions or saturated regions | Cover 344 lines and 223 branches; enforce the completed 100% gate in CI |
| P5 Incus/LXD | Current full unprivileged GNU Incus case passes in 23.63 s with seven daemon profiles; three fresh musl cases also pass | Repeat after relevant implementation changes; results remain scoped to the recorded userspace/kernel |
| P6 root sandbox | Unmodified supplied unit passes the shared corrected manager case in 27.99 s on Ubuntu 6.8.0-147-generic, ROOT_SYSTEMD_RESULT=0 | Final-source qualification after relevant changes |
| P7 docs/CI | Required-kernel distinctions and approved limits are documented. Strict flags and bounded workflow budgets remain active | Final consistent-source record and complete proof/coverage enforcement |

The current production implementation `012764f` passes both jobs in
[CI run 41267147784](https://github.com/menhera-org/rs-l2tpd/actions/runs/41267147784),
about fourteen minutes overall, without timeout. Its
[job metadata](phase6/discovery-retries-20261101/ci-production-jobs.json)
is separate from later test-only additions' CI. The preceding test head
`df29654` also passes both jobs in
[CI run 41270177487](https://github.com/menhera-org/rs-l2tpd/actions/runs/41270177487).
The checked libc signal implementation passes both jobs in
[CI run 41272054292](https://github.com/menhera-org/rs-l2tpd/actions/runs/41272054292).
Its later installer tests pass
[CI run 41272918857](https://github.com/menhera-org/rs-l2tpd/actions/runs/41272918857).
The new resource step still needs its own CI run.

## Kernel snapshot and manager scope

The November 1 resolver selected Ubuntu 6.8.0-147.147 and 7.0.0-42.42,
vanilla equivalents 6.8.12 and 7.0.14, and mainline 7.3. Initial and final
selections match. The latest matrix froze `012764f`: each normal guest passes
14 privileged library, 20 Linux, five review, binary/process and 26 normal
scenario cases. Five separate H16 clock/QMP profiles also pass.

This snapshot includes the socket application/cleanup fixes, streamed
inventories and approved MAC/timing fixtures. It predates the checked libc
signal calls and later test additions; its success does not qualify those
changes. [Per-target behavior](../docs/kernel-behavior.md)
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

The [current summary](phase6/file-reload-conflict-20261101/coverage-summary.json)
reports 8,247/8,591 lines and 1,607/1,830 branches covered. Test-only
[member recovery](phase6/member-inventory-resync-20261101/README.md) and
[discovery retry](phase6/discovery-retries-20261101/README.md) cases add
nine lines and twelve branch outcomes. The
[configuration diagnostic cases](phase6/config-diagnostics-20261101/README.md)
cover empty/overflowing DNS ports and quoted/escaped key paths; the text
parser reaches 100% lines and branches. The
[PID authority cases](phase6/pid-authority-20261101/README.md) add one
line and four branch outcomes while preserving all production mappings.
[PID syscall faults](phase6/pid-faults-20261101/README.md) add another
eight lines and six outcomes, with original errors and cleanup asserted.
The [FIFO case](phase6/pid-fifo-20261101/README.md) adds one line and two
outcomes, requiring non-regular-file refusal before writing. Those earlier
additions preserved production mappings; the rule adapter overrides its
default retry-discovery method. The checked libc signal calls change
production code, so their collection starts fresh. Ten further instrumented
library/service seeds pass and contribute current-source profiles. The
[installer failure cases](phase6/installer-errors-20261101/README.md) add
five lines and three outcomes while preserving production mappings; their
false-success control fails. The
[signal-thread resource check](phase6/signal-thread-limits-20261101/README.md)
adds five cleanup lines with unchanged production mappings. Its omitted-wakeup
control fails; ten GNU and three musl final-driver runs pass. A bounded CI
step now runs both refusals and retains their logs. The
[file reload case](phase6/file-reload-conflict-20261101/README.md) adds four
lines, checking semantic refusal, diagnostics and recovery; its false-success
control fails. Only
this implementation's profiles contribute; superseded implementations
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
- **Nix signal errors:** the maintainer approved direct `libc` calls for
  broken wrappers and clarified that contributing to `nix` is not required.
  The [local exception](phase6/libc-signals-20261101/README.md) replaces
  mask setup and signal wait, checks both libc error conventions before
  reading outputs, and returns conversion errors. GNU/musl delivery and
  refusal tests, daemon error/exit/PID assertions, ten seeded suites,
  three musl suites, common checks and both failure controls pass.
  The [upstream signal](phase6/upstream-signal-errors-20261031/README.md)
  and [overflow](phase6/upstream-overflow-fixture-20261031/README.md)
  proposals remain references; their release is no longer a daemon gate.

The [neighbour-pressure control](phase6/neighbour-pressure-20261101/README.md)
reproduces packet loss with two simultaneous 300-session workloads in one
isolated guest: both fail and the ARP overflow counter rises by two. The
same traffic runs alone without overflow. Host-kernel qualification now
runs serially; three unchanged normal suites pass. Earlier host transcripts
lack counter deltas, so the control establishes the shared-budget mechanism
rather than direct attribution of every historical packet drop.

The frozen `012764f` matrix passes. A fresh required matrix is running in a
clean frozen checkout of the checked libc signal implementation `ce6a70a`.
The 100% report and complete clause/resource/event-cost proof remain
unfinished.
