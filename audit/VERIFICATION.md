# Verification checkpoint

Signed source [`2ce54d2`](https://github.com/menhera-org/rs-l2tpd/commit/2ce54d281e0edbf2fb32d811f5cd027abbc9d954)
preserves behavior and public APIs. [Execution records](phase6/qlty-src-refactor/README.md)
retain the commands and full results. Further complexity, inlining and package
work is in progress; full qualification of the final source is deferred to
goal step 6. This checkpoint does not qualify those pending changes.

| Check on `2ce54d2` | Result |
|---|---|
| Common gates and all three CI jobs | [Pass](https://github.com/menhera-org/rs-l2tpd/actions/runs/41783315134) |
| Strict maps | 333 active rules; 43 kernel facts; no uncited Linux functions |
| Merged production coverage | 8,602/8,602 lines; 1,838/1,838 condition outcomes; no production exclusions |
| Required kernel matrix | All 13 profiles pass; stable publications and empty source patches |
| Musl scenarios / Incus | Three consecutive pairs pass; containers deleted |
| Unmodified root-systemd unit | Pass on Ubuntu 6.8 with Ubuntu 24.04 userspace |
| Source-work curves and GNU/musl allocations | Pass in the build job |
| CodeQL | [Pass](https://github.com/menhera-org/rs-l2tpd/actions/runs/41783315117) |

Required kernels are Ubuntu `6.8.0-147-generic`/`7.0.0-42-generic`, vanilla
`6.8.12`/`7.0.14` and mainline `7.4.0-rc1`. Each normal guest passes all
28 scenarios and 37 process cases, plus 31 private live, 24 Linux and five
review cases. Separate clock/pause, IPv6-absent and missing-driver boots pass.
Raw LLVM metrics remain separate: 99.47% lines and 98.26% condition outcomes.

The optional matrix on this checkpoint was stopped at the user's request;
its partial Debian 13 guest is neither a pass nor a regression finding.
All six optional profiles must run on the final source at step 6. The earlier
Debian 13 and Rocky 9/10 passes and the test-only nlmon race investigation
remain in [signed history](https://github.com/menhera-org/rs-l2tpd/blob/9817a0d19ac89d5cc0844180022ec8b0dfa07ce5/audit/nlmon-bind-fix/README.md).
Debian 12 receives best-effort degradation outside the support target.

Ten targeted production functions fall from cognitive scores 25–29 to 6–16;
new helpers score at most 20. Further real complexity work toward an A rating
is pending. Smell thresholds and coverage exclusions are unchanged.
Cosmetic Dockerfile findings are resolved; the review image documents its
local apk-pinning exception for the existing signed-index, networkless
resolution policy. `qlty check .` succeeds with only the packager NOTE.

Current gating code lives in `tests/`, `tools/` and the repository root.
Historical records are retained in Git before removal from the main tree.
Fetched kernel.org HTML is never committed. Kernel-only optional guests do
not qualify distribution userspace, SELinux or packaging; source-only and
delegated assertions keep their [evidence classifications](../docs/kernel-evidence.md).
