# Lifetime input and released-registration boundaries

Two test-only changes qualify existing lifetime handling:

- A multicast datagram with valid outer framing but an unusable link payload,
  or a synthetic unrelated message carrying a valid link payload, must leave
  the generation, pending capture, tracked registration and lookup unchanged.
  A subsequent creation and deletion must still capture the owned device
  and mark only that device removed.
- The ordered-completion table now removes a registration before delivering
  its controlled absence reply. The reply reports removal without restoring
  the released tracking entry.

These are synthetic parser/state cases, not observations of malformed kernel
broadcasts or a claimed natural concurrent release through LinuxKernel.
The existing live lifetime cases and required matrix retain their own scopes.
Production code is unchanged from `revision`; before/after patches agree.

Ten native and instrumented model/rule/service/startup repetitions, three
musl model runs, the full native suite, common gates, Rust 1.89 and additional
ARM64/RISC-V64/PowerPC64LE musl compile checks pass. Three independent controls
end the generation for an unusable payload, end it for an unrelated message,
or recreate the released registration. Each fails exactly one of ten ordinary
lifetime cases; the three privileged cases stay explicitly ignored in those
control runs. Control profiles are not merged.

Coverage reaches **8,487/8,687 lines (97.70%) and 1,699/1,852 branches
(91.74%)**, leaving 200 lines and 153 branches. All 4,327 production mappings
are identical to the preceding removed-device MAC report. No production
exclusion, profile mismatch or saturated region is present. The collector
excludes profiles from earlier production implementations.

`commands.sh` records positive commands. Control patches/logs identify each
deliberate defect. Complete clause proof and the 100% coverage gate remain open.
