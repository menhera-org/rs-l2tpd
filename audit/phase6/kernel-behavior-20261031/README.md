# Required-kernel behavior documentation

The maintainer requested behavior documentation for every required kernel.
[docs/kernel-behavior.md](../../../docs/kernel-behavior.md) covers all five
resolved targets and every active K fact, separating executed assertions
from versioned-source, delegated and incomplete evidence. README.md,
the documentation index, testing, plan and kernel evidence pages link it.

source-comparison.log records exact Ubuntu source-tag URLs, SHA256
identities and excerpts for session deletion, dump traversal and
notification scope, plus the corresponding files from all three built
upstream tarballs. config-features.log records each target's config
identity and relevant options. These are source/config observations, not
additional live-test counts. The config and test commands introduce no
new dependency.

docs-checks.log records local Markdown file-target checks (fragments and
external URLs excluded), formatting, POSIX shell syntax, ShellCheck and
diff whitespace validation. The approved contract's ordinary tests,
strict source-link check and warning-denied Clippy are retained in
[../kernel-contract-20261031](../kernel-contract-20261031/README.md).

matrix-checks.log verifies the five normal results/releases/errnos,
identical executable identities, unchanged source/publication manifests,
both scoped H4 boots and the precise KHO override scope. The fresh strict
rule-map check still fails with 70 uncited rules (343 total, 333 active,
263 cited); rulemap.log retains that expected failure and exit 101.

Live results belong to
[../matrix-20261031T071523Z-3533819](../matrix-20261031T071523Z-3533819/command.log),
which uses the approved K26/K34 correction and the documented KHO
cold-boot calibration. All-feature musl executables, source patch,
artifact identities, guest releases and commands are retained there.
The diagnostic KHO boots have their own explicitly limited
[record](../boot-memory-20261031/README.md).

No unexecuted case is promoted to a per-kernel pass. The remaining
H15/H16/full H17, denied-capability/delegated cases, full manager refresh,
coverage and strict CI work remains open in the Phase 6 verification
record. Broader optional kernels and new security-update builds must be
resolved and tested before extending the documented observations.
