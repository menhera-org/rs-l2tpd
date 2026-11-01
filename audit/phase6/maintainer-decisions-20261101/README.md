# Approved MAC authority and current dependency state

On 2026-11-01 the maintainer approved three prepared proposals:

- H11 documents later udev assignments as manager overrides under S12/G4.
  The staged configured-MAC case uses `MACAddressPolicy=none` matching
  `incusl2tp` and `rsl2tp-t*`. Concurrent activation and ordered persistent
  assignment/re-creation remain separate, unchanged checks.
- G23 includes the current link/address state required by configured
  dependencies. It requires streamed temporary inventories, release after
  the final dependency is removed, and no unrelated-state retention.

- H6 keeps the exact one-second retry deadline under fake-clock tests,
  records live monotonic completion time and retains the existing ten-second
  event timeout plus actual connection/frame checks. Scheduling and kernel
  operation delays are documented. The strict observed-time failures remain
  retained.

All three proposals are applied. The G23 streaming implementation and its
resource proof are still required; approving the bound does not pass G23.
`revision` plus `source.patch` identifies the approved specification and
shared-manager fixture changes. The daemon implementation is unchanged
from `eeec2573ccccd3ee9d7ad84ff97165ffa2abe637`.

## Verification

Three fresh unprivileged Ubuntu 24.04 Incus containers, without network
profiles or NICs, pass the full static musl scenario in **14.57, 17.17 and
9.14 seconds**. Each includes tunable fallback, descriptor-store survival,
concurrent networkd/udev activation, twice-ordered persistent assignment
and the explicitly coordinated configured MAC. Receive-buffer fallback
also passes. Containers are deleted after each run; `incus-*/cleanup.log`
retains cleanup results.

The unmodified root-systemd unit passes its full sandbox/store/restart/
cleanup scenario in **31.59 seconds**, `ROOT_SYSTEMD_RESULT=0`. It shares
the corrected manager fixture. These results apply to Ubuntu
6.8.0-147-generic and the recorded Ubuntu userspace; they are not
per-distribution manager proofs for the other required kernels.

Common checks pass, including strict rule/source maps, Clippy, GNU ordinary
and musl process/startup suites, feature builds and rustdoc. Cargo build
durations are omitted. The preceding tunnel-state record retains fresh
95.46% line / 86.11% branch production coverage; this package does not
change production code or claim a new coverage merge.

The corrected normal suite passes all 26 scenarios three times in a row:
**162.34, 161.62 and 162.06 seconds**. Recorded H6 delays are 997,489,600,
993,663,185 and 998,312,497 ns. No earlier failed run is removed.

The manager runs precede the H6 change: `revision` plus `mac-fixture.patch`
identifies their compiled source. The final two normal runs use the final
fixtures; the first differs only by the unused import restored by
`first-normal-unused-import.patch`. Clippy found that leftover import after
the timing assertion changed. It was removed, and the complete common gate
passes afterward; the original diagnostic is retained as `pre-import-common.log`.
The upstream compatible nix release, final matrix, complete clause/resource
proof, unresolved earlier packet loss and 100% coverage also remain open.

```sh
# Three runs, each creates and deletes a fresh unprivileged container:
tests/docker/run.sh incus
./test-ci-gates.sh
# Root guest command and artifact identities:
# root-systemd/command.log and root-systemd/artifacts.log
```

## Later decision: broken nix wrappers

The maintainer approved a documented direct `libc` exception when a `nix`
wrapper is broken and clarified that contributing to `nix` is not required.
The prior release prerequisite above is superseded. Checked signal-mask
and signal-wait calls are now applied; the source, GNU/musl success/error
checks and failure controls are in `audit/phase6/libc-signals-20261101/`.
The original revision/patch here still identifies the three earlier proposals.
