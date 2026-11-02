# Phase 6 verification, 2026-11-02

Phase 6 remains incomplete. The scoped-inventory batch reaches
**99.31% lines / 97.39% branch outcomes**. All 5,889 exported mappings match
the event/lifetime snapshot, allowing its profile reuse. No production
code is excluded. The required normal/boot
profiles and a serial clock replay pass, with failed parallel clocks and
QEMU experiments retained. The
[November 1 record](PHASE6_VERIFICATION_2026-11-01.md) preserves earlier
scope and maintainer decisions.

| Requirement | Executed evidence | Still required |
|---|---|---|
| P1 rule/source maps | Common checks cover 333 active rules and 43 kernel facts; prior ten-run CI qualification is retained | Complete clause proof remains distinct from declaration traceability |
| P2 scenarios | All 27 normal cases pass on each required kernel, including H20 fragmentation and H17 scale | Complete clause/history/resource/event-cost proof |
| P3 required kernels | Five normal profiles, three absence/recovery boots and five serial clock profiles pass; publication selection is unchanged | Resolve or bound the retained parallel clock/emulator failures; recheck published targets |
| P4 coverage | 8,645/8,705 lines (99.31%); 1,792/1,840 outcomes (97.39%); no production exclusions | Cover the remaining 60 lines and 48 outcomes, then enforce 100% in CI |
| P5 Incus/LXD | Fresh GNU unprivileged system-container run passes on Ubuntu 24.04 / 6.8.0-147; preceding shipped-musl scope is retained | Preserve that kernel/userspace scope |
| P6 root sandbox | The unmodified supplied unit and three manager/task-limit runs pass; direct fork-limit cases pass three stable runs per libc | Other distribution userspaces remain untested |
| P7 docs/CI | Kernel selection, behavior and limits are documented; strict maps and workflow timeouts remain active | Final complete proof and 100% coverage enforcement |

The [scoped-inventory record](phase6/scoped-inventory-events-20261102/README.md)
adds three covered lines and five outcomes without changing production
mappings. Ten instrumented suites, three GNU and three musl container
repetitions, three instrumented live repetitions and five focused required
kernel profiles pass. Seven restored controls reject their intended faults.
The timeout case checks the unchanged five-second capture deadline in an
isolated child. A wrong-tunnel session query yields no record on both 6.8
targets and the other tunnel's record on all three newer targets; the
adapter filters that record. These focused profiles do not replace the
preceding thirteen-profile matrix. Complete proof and 100% remain open.

The [event/lifetime record](phase6/event-and-lifetime-ordering-20261102/README.md)
identifies signed base `0bb8100`, the test/helper changes and a fresh collector.
It adds eight covered lines and seven outcomes. Ten instrumented ordinary
suites, repeated GNU/musl models, final focused lifetime runs, GNU live/Incus,
manager/task-limit and root-unit profiles pass. Three fresh buffer-force
guests each export seven profiles. Seven negative controls reject their
intended faults, including panics in either fork-error arm. All mutations
are restored.

The required normal guests ran the first lifetime fixture. Its later
quiet-reader revision removes an incidental elapsed-time assertion and
passes three GNU, three musl and three instrumented focused runs. No shipping
timing assertion changed. All five serial clock replays pass with the
shipping runner unchanged; the initial parallel failures and all rejected
QEMU configurations remain failures. Passing replay does not prove ten-run
determinism or establish the cause of the pre-userspace INT3 panic.

The [checked-boundary record](phase6/checked-boundaries-20261102/README.md)
records changed production code against signed `241bd51`, a separate
collector, ten instrumented repetitions, three selected musl repetitions,
three GNU and three musl process collections, five negative controls,
GNU live/Incus, manager/task-limit and root-unit results. Each full normal
guest includes 82 ordinary binary tests, three selected filesystem tests,
both signal task-limit cases, 35 process cases and 27 normal scenarios.
The attempted fork-limit fixture failed during cgroup setup and is deferred;
it contributes no daemon success or coverage claim.

The [earlier sealed matrix](phase6/matrix-20261102T011736Z-3377142/README.md)
retains frozen signed source `455eef7`, matching publication selections and
empty source patches. Earlier coverage numbers and function-map comparisons
below qualify their own snapshots.

| Required target | Guest release | Normal scenarios | H16 clock/pause |
|---|---|---|---|
| Ubuntu 6.8.0-147.147 | 6.8.0-147-generic | 27 pass | pass |
| Vanilla 6.8.12 | 6.8.12 | 27 pass | pass |
| Ubuntu 7.0.0-42.42 | 7.0.0-42-generic | 27 pass | pass |
| Vanilla 7.0.14 | 7.0.14 | 27 pass | pass |
| Mainline 7.4-rc1 | 7.4.0-rc1 | 27 pass | pass |

Both mainline IPv6-absent boots and Ubuntu's missing-Ethernet-driver
recovery pass separately. The [RC source/build record](phase6/mainline-rc-qualification-20261102/README.md)
retains archive identities, both build identities and the 43-file source
comparison. All selected files match fresh archive extractions. The
[per-kernel behavior page](../docs/kernel-behavior.md) distinguishes actual
observations, source evidence and userspace limits.

The source/build and parser-hook commit `ba0a3a6` passes
[GitHub CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41374346801).
The matrix record commit `651860a` also passes
[GitHub CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41378384310).
The full matrix consumed unchanged Rust and kernel-runner sources while
that documentation/CI-helper commit was made. Those earlier batches did not change production behavior; the checked-boundary
batch above does.

The integrated [resolver/event/host boundary batch](phase6/resolver-boundaries-20261102/README.md)
records six failure controls, repeated models and DHCP-only guest runs on
all five kernels. Instrumented GNU live repetitions contribute to the
reported coverage. All 4,327 old production mappings remain unchanged;
four test-induced instantiations were added. The
[larger coverage batch](phase6/coverage-batch-20261102/README.md)
adds installer, private descriptor-table, completion, retirement and socket
cleanup cases. Ten instrumented native model runs, three musl model runs,
three stable GNU/musl process repetitions and three further failure controls
pass. Combined with the resolver package, this adds 29 covered lines and
21 covered branch outcomes without changing production function bodies.
The [file-race/inheritance/shutdown batch](phase6/file-races-and-shutdown-20261102/README.md)
adds another 20 covered lines and 12 branch outcomes. All 4,331 production
mappings remain unchanged. Its final expanded profiles pass on all five
required kernels; ten fake repetitions, three musl model repetitions and
serial GNU/musl fault collections pass. The parent commit's push CI failed
at the BusyBox exec fixture. The corrected signed 449c751 passes
[push CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41392740303)
and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41392740327).
The [probe/event batch](phase6/probe-and-event-boundaries-20261102/README.md)
adds 18 covered lines and 11 branch outcomes with unchanged mappings.
All five required binary profiles, three GNU and three musl container
repetitions, ten instrumented fake runs and three failure controls pass.
The [signal/ownership batch](phase6/signal-and-ownership-guards-20261102/README.md)
adds eight lines and seventeen outcomes. All five binary profiles pass
signal delivery and exact task-limit checks. Final model/daemon and process
suites each pass ten instrumented repetitions; GNU/musl checks and eight
controls pass. Later model/IPC changes have their own qualification scope.
All production region locations match; one formerly empty branch list now
reports the existing Signals::attach guard. Signed 958671c passes
[live CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41394844338/job/125113842254)
and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41394844317), while its coverage step fails at an unhandled SIGCHLD stop in
the test tracer. The batch fixes signal forwarding and tests handler delivery.
The
[K41 follow-up](phase6/kernel-notification-control-20261102/README.md)
passes all five kernels and rejects a deliberately ineffective listener.
Bare-kernel guests do not
establish new udev/networkd or Incus results. Broader kernels and live
non-x86 architectures remain unrun.

The [competing-state/input batch](phase6/competing-state-and-input-20261102/README.md)
adds eight covered lines and eighteen outcomes. All 4,331 previous mappings
remain unchanged; one deserializer instantiation raises the count to 4,332.
Ten final instrumented repetitions, three final musl repetitions, three
stable container runs per libc and three instrumented live runs pass.
Ten deliberately broken variants fail at their intended assertions.
All five focused guest profiles pass the expanded CLI/process fixtures.
A full normal rerun exceeded an inherited outer wrapper and is retained
as rejected; a second attempt was deliberately stopped to correct scope.
The sealed full matrix qualifies the unchanged production bodies.
Publication selections still agree. Signed 2eaa987 passes
[CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41403202183)
and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41403202214).
