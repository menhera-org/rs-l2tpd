# File races, inheritance and shutdown

This combined batch extends signed `7dab197`. Production function bodies
remain unchanged. The merged collector now covers **8,563/8,687 lines
(98.57%)** and **1,737/1,852 branch outcomes (93.79%)**. This adds 20 lines
and 12 outcomes to the preceding report. All 4,331 production mappings are
unchanged; no production exclusion was added. **124 lines and 115 outcomes
remain uncovered**, so the 100% gate remains open.

The file-race fixture traces only an explicitly stopped worker in its own
disposable child. It grows a regular file after metadata checks, removes a
configuration file before open and inserts a PID symlink before publication.
It uses a sized, initialized `PTRACE_GET_SYSCALL_INFO` query because the
locked `nix` wrapper passes zero size and then assumes initialization.
The helper's GNU/musl checks include zero-size output preservation,
PEEKDATA's valid all-ones result, invalid requests/pointers, bounded reads
and callback-error cleanup. Negative descriptor arguments are interpreted
as C integers, accepting both zero-extended and sign-extended register
values. No production crate or Cargo feature is added.

The batch also covers metadata failures, local/inherited descriptor
duplication failures, duplicate/unwanted/mismatched handovers, command-mode
errors, startup withdrawal failures, a lost store manager and failed PID
cleanup after re-exec. The descriptor-refusal cases exercise the reconciler
over fake sockets and a real fcntl refusal; they do not substitute for the
Linux backend's conformance suite.

Final common gates, ten instrumented fake repetitions, three musl fake
repetitions, Rust 1.89 and three additional musl architecture compile checks
pass. The first instrumented run executes all ordinary suites; the next
nine repeat the fake targets. Binary suites are separately exercised in
three GNU and three musl containers. Those containers also execute ordinary
process cases and the two selected shutdown cases. Three GNU instrumented
collections add the serial descriptor and DHCP-only fixtures; three musl
serial library runs pass too. The serial fixtures are explicitly invoked
with `--ignored --exact`; their declarations alone count as no execution.

All five final expanded guest profiles pass: Ubuntu 6.8.0-147.147, Ubuntu
7.0.0-42.42, vanilla 6.8.12, vanilla 7.0.14 and mainline 7.4-rc1. Each runs
70 ordinary binary cases, three selected filesystem cases, four selected
library cases, 12 ordinary process cases, four selected ignored process
cases and the K41 listener control. The other 18 process declarations are
not executed by this targeted profile. K41 announces the foreign deletion
on the first four targets; 7.4-rc1 does not. Every target receives its local
deletion control. `guest-source.patch` freezes the exact shipping tests and
temporary audit fixture; `guest-fixture.patch` isolates that fixture.

Three isolated controls fail at their intended runtime assertions: removing
the post-read size check, permitting a symlink inserted during publication
and passing zero size to the syscall-info query. The controls were restored.
The query control demonstrates that a broken tracer cannot pass merely
because it failed to observe the operation under test.

Rejected runs are retained. BusyBox uses F_DUPFD_CLOEXEC while opening its
probe script; the first guest/container runs therefore rejected the older
exec fault selector. The corrected selector matches both that command and
the exec worker's minimum descriptor, leaving the probe available.
An instrumented repetition also exposed an immediate-close assumption in
the existing fake session-deletion test. The corrected case explicitly
holds a duplicate, releases it, observes closure without advancing the
fake clock, then runs the original one-second retry. A later repetition
also exposed a provisional-socket conflict when the new fork-based fixture
ran alongside the fake suite. That fixture now joins the existing serial
live profile, where a child cannot inherit descriptors of concurrent fake
cases. The normal CI guest already executes that profile serially.
The GNU container additionally caught zero-extension of negative integer
arguments in an older libc; the helper calibration now checks their C
integer value. Final repetitions after these corrections pass.

The parent commit's push CI fails at the same BusyBox probe selector;
`preceding-ci-failure.txt` retains the job and diagnostic. Native build/check
and CodeQL pass for that parent. This package corrects the selector; its
own push CI result is recorded after publication.

Negative-path PID tests emit synthetic NUL-containing paths. For readable
audit diffs, affected logs store NUL as `<NUL>`. The marker was absent from
each original, and every transformation was checked by reconstructing the
original bytes. `nul-encoding.log` retains the original Git blob identities,
byte counts and replacement counts. Other bytes are unchanged.

The temporary expanded guest fixture is recorded separately from shipping
sources. Pre-serial-declaration passes and rejected attempts retain their
own source snapshots. The incremental collector retains diagnostic runs of
the same production implementation; rejected attempts are not counted as
determinism passes. Results here do not replace the full required-kernel matrix or
establish new Incus/root-unit scope. Phase 6 remains incomplete.

The publication recheck in `publication/versions` still matches the sealed
matrix: Ubuntu 6.8.0-147.147 and 7.0.0-42.42, vanilla 6.8.12 and 7.0.14,
and mainline 7.4-rc1. `publication.log` retains the fetch results.
