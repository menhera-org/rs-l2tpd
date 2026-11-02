# Checked boundaries

This batch starts from signed `241bd51`. It changes production boundaries,
so its coverage collector is new; no preceding implementation's profiles
are merged. Coverage is **8,634/8,705 lines (99.18%)** and
**1,780/1,840 branch outcomes (96.74%)**. **71 lines and 60 outcomes
remain uncovered.** There are no production exclusions. The changed
denominators reflect refactoring; this is not an unchanged-mapping comparison.

The binary now checks failure to ignore SIGPIPE during startup and exec.
Private helpers expose the existing PID-file identity validation, diagnostic
redaction, service/host exit precedence and startup-channel conversion to
direct tests. The double-fork parent's wait/readiness loop is separated
without changing its policy. Its tests exercise interrupted and failed waits,
interrupted/failed/empty polls, and shutdown before the readiness PID arrives.
An owned daemon child also recovers after its descriptor limit is restored.

Netlink callers now distinguish data replies from ACK-only operations.
Unexpected data during an ACK-only mutation breaks the exchange, discards
the socket and returns the existing uncertain-outcome error; it must not
be interpreted as a definite mutation failure. Family and link decoders
have shared checked helpers. Three reconciler checks were redundant under
the surrounding snapshot/removal invariants and are removed. Failed
session deletion still makes the first shutdown attempt incomplete.

The syscall fixture blocks catchable signals until its TID and initial
SIGSTOP arm the tracer, then restores its original mask. This fixes an
observed early SIGCHLD delivery stop. Calibration verifies restoration and
the exact refusal when the mask syscall fails. The checked direct pthread
call uses the documented nix exception. The descriptor-limit fixture uses
test-only nix resource wrappers and checked libc prlimit for its owned
child; it adds no production dependency or feature.

## Results

- Shared CI gates pass, including strict maps for 333 active rules and
  43 kernel facts, warning-denied Clippy and documentation.
- Ten fresh instrumented model/CLI/process repetitions and three selected
  musl repetitions pass. Rust 1.89 and three additional musl architecture
  compile checks pass.
- Three stable GNU and three stable musl container repetitions each pass
  82 ordinary binary cases, three selected filesystem cases and all
  35 process cases. These include the new descriptor-limit recovery.
- The fresh GNU live collection passes the serial library, Linux, review,
  process and all 27 non-Incus scenario cases. Four serial startup
  resource cases pass separately. Three fresh GNU buffer-force guests each
  export seven profiles; these recover one additional branch outcome.
- Fresh GNU Incus passes, with seven daemon profiles recovered. Three
  shipped-musl scenario/Incus pairs pass on Ubuntu 6.8.0-147. Three
  manager/task-limit repetitions and the unmodified root systemd unit pass.
- All thirteen required kernel profiles pass: normal and H16 clock/pause
  on Ubuntu 6.8.0-147.147, vanilla 6.8.12, Ubuntu 7.0.0-42.42,
  vanilla 7.0.14 and mainline 7.4-rc1; both mainline IPv6-absent boots;
  and Ubuntu's missing-Ethernet-driver recovery. Each normal profile
  includes all 27 scenarios and 35 process cases. See
  [checked results](results.log) and the per-profile logs under `kernels/`.
- The publication recheck selects the same versions as the preceding sealed
  matrix. Source/build comparisons for those kernels remain in that record.
- Five restored negative controls fail at their intended runtime assertions:
  omit either PID identity field, accept unexpected ACK-only data, accept a
  family reply without an ID, or ignore SIGPIPE-disposition failure.

The ordinary test profiles leave six declarations ignored; selected
filesystem, signal task-limit and manager cases run in their separate
profiles. The full normal guest runner is unchanged. Two source-link
comments were added to test-only helpers after the normal guest batch
started; production bodies and test assertions were unchanged.

`source.patch` records the tracked source changes against `revision`;
`boundary-tests.txt` retains the added test module. Control patches use the
isolated checkout's recorded base revision and include its pending batch
changes. Every mutation is restored before the next control.

## Rejected attempts and limits

An early parent fixture hung; calibration exposed SIGCHLD arriving before
its initial tracer stop. The corrected arming protocol passes the final
repetitions above. Rejected logs remain. A Noble launch used the wrong
module-directory layout and failed before boot; its corrected run passes.

The attempted fork-limit fixture failed to migrate its launcher into a
private child cgroup. One earlier launcher continued after that failure
and a descendant retained captured pipes; its disposable container was
removed. The bounded revision still failed before exercising the daemon.
Its source and failed log are retained as deferred evidence. It is absent
from the shipping test suite and contributes no success or coverage claim.

The prior signed commit passes
[CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41412876985) and
[CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41412876983).
This batch's push results are checked separately after publication.
Phase 6 remains incomplete: the 100% line/branch gate, complete
clause/history/resource/event-cost proof and final CI enforcement remain open.
