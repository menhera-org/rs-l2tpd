# Plan and release status

[Documentation index](README.md)

The v0.2.0 rewrite and Phase 6 proof are complete. Version 0.2.0 has not
been released; packaging and publication remain Phase 7 work. The
[specification](spec/README.md) defines behavior, and the
[verification guide](phase6.md) defines the gates that later changes must keep.

## Implementation milestones

| Phase | Deliverable | Status |
|---|---|---|
| 0 | Remove the obsolete implementation and establish the module/test layout | Complete |
| 1 | Typed configuration, partial merging and strict/lenient validation | Complete |
| 2 | Kernel boundary, fake backend, bounded Linux adapter and live conformance | Complete |
| 3 | Identity-based reconciliation, degraded states, resolver integration and events | Complete |
| 4 | Program-driven runtime, async/blocking services and host handshakes | Complete |
| 5 | Binary, signals, readiness, descriptor store, re-exec and optional systemd installer | Complete |
| 6 | Strict maps, live scenarios, kernel matrix, coverage, Incus and root-systemd qualification | Complete; retain the gates below |
| 7 | v0.2.0 publication and distribution packages | Pending |

Completed development diaries and superseded audits are preserved in Git
history. Current evidence is indexed by repository file `audit/VERIFICATION.md`.
The [architecture](architecture.md), [interface](interface.md) and
[dependencies](dependencies.md) describe the implemented tree.

## Rules for further changes

- Keep the `Kernel` boundary: policy tests use the fake, and kernel behavior
  is checked with live conformance and versioned source citations.
- Preserve kernel object identities across changes unless the specification
  requires replacement. Uncertain mutations retain ownership and reservations
  until local verification resolves them.
- Keep work and memory bounded. A timeout does not cancel a libc lookup or
  prove a failed mutation had no effect.
- Fix required `l2tp`/`iphost` functionality upstream before depending on it.
  The documented checked-`libc` exception for broken `nix` wrappers remains
  available with GNU/musl tests.
- Add a dependency only when its reduction in maintained code justifies it;
  keep its purpose in [dependencies](dependencies.md).
- Treat test citations as traceability. Assertions, executed feature/live
  suites, clause cases and coverage provide separate evidence.
- Use `./commit.sh` and `./sync.sh`; retain exact source identities and failed
  attempts in verification records. Do not record machine-specific facts.

## Phase 6 — proof

The [Phase 6 guide](phase6.md) gives commands and acceptance criteria.
The six gates remain required: strict rule map, kernel source links,
whole-daemon scenarios, the moving required-kernel matrix, 100% merged
production source coverage and an executed unprivileged system-container
profile. The supplied root systemd unit is qualified separately.

The current source passes all 333 active-rule and 43 kernel-fact mappings.
Production coverage is 8,582/8,582 merged lines and 1,844/1,844 condition
outcomes, with unchanged exclusions. The current CI and full kernel/host
results are recorded in [testing](testing.md) and repository file
`audit/VERIFICATION.md`. Optional distribution-kernel profiles extend the
execution record without replacing any required target.

Before claiming a later change preserves Phase 6, execute the affected
gates on the actual source. Refresh published kernel selections and rerun
the matrix when required targets move. Keep raw LLVM metrics separate from
the merged-source result, and source-only/delegated assertions separate
from live tests. Neither a documentation edit nor an ignored test declaration
closes a gate.

## Phase 7 — release

1. Update the changelog and release documentation for the final shipped
   behavior and verified limitations.
2. Implement the planned `musl-deb` builder, control template, maintainer
   scripts and CI check for `amd64` and `arm64`; see
   [packaging](packaging.md#musl-deb-a-minimal-debian-package).
3. Build and verify the static release artifacts and Debian-family packages.
4. Tag v0.2.0, publish with `cargo publish --registry crates-io`, and attach
   packages and tarballs to the release.

These are release tasks, not completed publication claims. The optional
`--setup-systemd` installer already exists and adds no dependency.
