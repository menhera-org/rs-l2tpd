# Contribution Guidelines

## For Humans

- Respect and obey the [Menhera(R) Code of Conduct (CoC)](https://www.menhera.org/code-of-conduct/).

## Implementation

The final state must satisfy the following requirements:

- Code coverage of tests must be 100% of all the code paths.
- Every claim in the specs must be tested.
- All the tests must succeed deterministically.
- All the kernel-facing codes must be source-linked against relevant kernel source files, confirming every behavior in detail.
- All the kernel-relevant code units must be tested against a live kernel.

## Roadmaps

1. [x] Finish the specs (`docs/spec`).
2. [x] Diff the current code's behavior against the specs.
3. [x] Confirm every diff for the correct behavior.
4. [x] Rewrite the specs with knowledge from the diff if really needed (skip if none)
5. [ ] Refactor the whole codebase for minimal testable codebase satisifying every spec item. Don't aim for minimal diff, but refactor everything to minimize the codebase (`ponytail` skill is useful; coding agents are encouraged to ask humans for its installation), to minimize the supply-chain size (i.e. remove unnecessary deps), to minimize the attack surface, and to minimize the ongoing maintenance costs. **NOTE: if we need fixes upstream (notably `l2tp` crate), please stop and fix upstream**.
6. [ ] Make everything satisfy the requirements above. The specs and the kernel sources are authoritative, along with live kernel tests.

## Kernel targets

Currently, the latest two Ubuntu LTS kernels MUST be tested,
in addition to mainline and vanilla equivalents of those Ubuntu
kernels. We SHOULD aim for a broader support covering Ubuntu/Debian-ish stock kernels, vanilla Linux kernels, and RHEL-ish stock kernels.

## Container support

We must support running our daemon codes under unprivileged
system containers under LXD/Incus.
