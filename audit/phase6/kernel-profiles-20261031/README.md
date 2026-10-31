# Required-kernel profiles and README coverage badge

The maintainer requested a behavior description for every required kernel
and asked to commit their Code Coverage badge with the README change.
The README preserves that badge and links the expanded
[kernel behavior page](../../../docs/kernel-behavior.md).

The page now gives each of the five resolved targets its own profile and
a table separating normal/H20, H15, H16, H17 and H11/Incus results. It uses
the already archived runs and exact-source comparisons linked there;
this documentation change does not add a kernel execution. In particular,
mainline's expanded normal profile also executes the four capability/
netlink cases and the low-port DHCPv6 positive case. Missing per-target
manager, capability and scale results remain explicit.

`./test-ci-gates.sh` passed before this commit: formatting, ShellCheck,
warning-denied Clippy, feature builds, native/musl ordinary tests,
traceability tools and warning-denied documentation. Its complete output
is in [ci-gates.log](ci-gates.log). This is one shared-gate execution,
not a determinism, coverage-completeness or final-matrix result.
The working tree also contained ongoing event-cache work; this commit
contains only the requested badge, documentation and this check record.

[docs-checks.log](docs-checks.log) records 54 checked local Markdown file
targets and a passing diff-whitespace check. External links and fragment
anchors were not checked. No claim is made about the badge's remote
rendering or coverage value. Required versions remain dated observations
from 2026-10-31, not a promise about future security-update packages.
