# Testing

[Documentation index](README.md)

How roadmap step 6 is met: 100 % of code paths covered, every claim of
the specification tested, every test deterministic, every kernel-facing
function source-linked to the kernel, every kernel-relevant unit run
against a live kernel. The design that makes this possible is the
`Kernel` boundary of the [architecture](architecture.md#the-kernel-boundary):
behaviour is tested against a fake kernel that models the kernel facts,
and the fake is itself tested against the kernel.

## Layout

```
src/**            unit tests next to the code (config, planner, ladder, report)
tests/
  rules/          behavioural tests over the fake kernel, one file per spec page (tunnels.rs, sessions.rs, ...)
  properties/     property tests of the promises (G3, G5, G6, G18) over random reload sequences
  kernel/         shared operation cases plus live-only fixture/source checks for K facts
  process.rs      actual-binary CLI and live process cases; binary unit tests live in src/bin/
  process/        instructions for privileged and real-manager process checks
  scenarios/      partial Phase 6 host/manager scenarios plus the Incus system-unit case
  docker/         run.sh scenarios|matrix|incus; full scenario and matrix gates remain open
  tools/
    rulemap.rs    the rule-map check
    srclink.rs    the source-link check
```

Every test names the rules it guards in its doc comment,
`/// spec: T21, K22`, which the rule map reads.

Phase 5's latest executed cases and limits are in repository file
`audit/PHASE5_CONFORMANCE_FIXES_2026-10-30.md`: 27 ordinary binary cases,
seven ordinary and 17 privileged process cases, three file/ownership
fixtures, musl/glibc runs on Ubuntu 6.8.0-147, and fresh QEMU process runs
on 6.12.114, 6.18.59 and 7.3. The initial verification record remains
`audit/PHASE5_VERIFICATION_2026-10-29.md`.

Repository file `tests/process/README.md` gives the container and native
systemd transport commands. The manager test covers the address-family
filter and descriptor protocol. The complete root system-unit mount
sandbox, including the bindv6only write, subsequently passed in QEMU; see
repository file `audit/phase6/P6_ROOT_SANDBOX_2026-10-30.md`. The full
required matrix, remaining scenarios and merged 100% coverage remain open
in `audit/PHASE6_VERIFICATION_2026-10-31.md`.

## The four suites

| Suite | Kernel | Runs where | Guards |
|---|---|---|---|
| Unit and `rules/` | fake | `cargo test --all-features`, no privilege | C, M, T, S, V, E, O, L rules |
| `properties/` | fake | included by the feature-gated `rules` target in `cargo test --all-features` | seeded reload invariants for G3, G5–G7 and G18 |
| `kernel/` conformance | fake **and** real | `cargo test --all-features` for the fake; a privileged container and the QEMU matrix for the real one | K facts, `kernel::linux` |
| `scenarios/` (partial, Phase 6) | real | privileged containers; QEMU for `ipv6.disable=1` and other boot options | H rules, P rules, the unit, G15–G23 end to end |

### The conformance suite

Each K fact has an evidence row naming its source and applicable tests.
Operations exposed by `Kernel` share test bodies between `FakeKernel`
and `LinuxKernel`. A test-only fixture supplies host controls and
observations the daemon must not expose: bring links up/down, inject and
observe frames/counters, create foreign objects/namespaces, delay replies
and force queue loss. K31 uses that fixture to bring a session up before
testing `EBUSY`; K5 must actually transmit and observe drops, not merely
create an unconnected socket. K17 observes asynchronous cleanup and K29
forces buffer loss. Source-only assertions and host/module requirements
are listed separately and never counted as executed shared cases.
A fact that the fake gets wrong must fail its corresponding live case. The
real run also records the kernel version it ran on.

### Kernel targets

`CONTRIBUTING.md` fixes the kernels the live suites MUST run on, as a
moving rule, not a fixed list: **the stock kernels of the two latest
Ubuntu LTS releases, the vanilla release each of them derives from, and
mainline**. The table below is that rule resolved on a date. Whenever
Ubuntu publishes a new LTS, a new `linux-image-generic` for one, or a
new mainline tag appears, the table MUST be updated and the matrix
re-run on the new versions before the phase 6 gate is called green;
a matrix run on a superseded version does not count.

Resolved on 2026-10-31 from the published Ubuntu updates/security
`linux-image-generic` candidates and kernel.org releases and source
indexes. Proposed packages do not replace the published targets:

| Kernel | Rule | How it runs |
|---|---|---|
| Ubuntu 24.04 `6.8.0-147-generic` | older of the two latest LTS kernels | a privileged container on a host running this kernel, or QEMU |
| Ubuntu 26.04 `7.0.0-42-generic` (also 24.04's HWE kernel) | newer of the two latest LTS kernels | QEMU, the `vmlinuz` and modules unpacked from the `linux-image` package of the `ubuntu:26.04` image |
| vanilla `6.8.12` (the last 6.8.y) | vanilla equivalent of the 24.04 kernel | QEMU, built from the kernel.org tarball with `x86_64_defconfig` plus L2TP |
| vanilla `7.0.14` | vanilla equivalent of the 26.04 kernel | QEMU, built the same way |
| mainline `v7.3` | the newest release | QEMU, built the same way |

[Per-target behavior and limitations](kernel-behavior.md) records the
observed errnos, notification scope, fragmentation, container/manager
constraints, boot settings and exact execution scope for every target.

Desired, not gating: every vanilla release between the oldest required
one and mainline (the matrix below), Debian's stock kernels, and
RHEL-ish stock kernels. The matrix driver resolves the required set before and after each run
and rejects a changed target. It also boots mainline with IPv6 disabled
and builds it without IPv6 for H4/T4. Each run
records `uname -r` next to its result, as the probes of
`tests/kernel/README.md` do. The verified range of
[kernel](spec/kernel.md) grows with what the matrix has run.

### The rules suites

At least one behavioral test per numbered rule, with separate cases for
each clause and table row; a single citation is not case coverage. Determinism comes from the
fake's virtual clock (a test advances it; M14 intervals are asserted
exactly), its seeded random source (S4 names are reproducible), and its
explicit notification delivery (a test says when the kernel's
notifications arrive and in which order, which is how the S27 "either
order" and the E21 loss cases are written). No test sleeps.

### Properties

Random sequences of configurations are reloaded against the fake, with
random host events between them; after each step the invariants are
checked: G3 (an index changes only by a matrix row), G5 (no socket is
connected to a peer the configuration does not name), G6 (an entry's
failure left no other entry unapplied that the fake allowed), G18 (a
converged entry received no operation on an identical reload), and that
the planner's output is a fixed point (running it twice changes nothing).

### The scenario suite

Whole-daemon tests in Docker, one per row of [hosts](spec/hosts.md)
and per conditional promise: the daemon binary, a configuration, a
container network built with iproute2, assertions on `ip l2tp`, `ip
link`, the daemon's log and frames delivered between two daemons. The
H20 scenario (a session MTU equal to or larger than the underlay's,
carried by kernel fragmentation, K43) is an acceptance condition of the
phase and of the release and runs on every kernel of the matrix. The
driver waits on events (a log line, a device appearing, a counter
changing), never on a fixed sleep, and each scenario has a hard timeout.
Scenarios that need a boot option (`ipv6.disable=1`, a kernel without
IPv6) or a clock of their own (H16: a container shares `CLOCK_REALTIME`
with the host, and time namespaces offset only the monotonic and boot
clocks) run under QEMU.

One scenario is an **unprivileged system container** under Incus or LXD
(`security.privileged=false`: a user namespace, the container's own
network namespace, `CAP_NET_ADMIN` only inside it, the L2TP modules
loaded by the host), which `CONTRIBUTING.md` requires the daemon to
support (H9). It checks what differs there from a privileged container:
`SO_RCVBUFFORCE` refused with `EPERM` and the `SO_RCVBUF` fallback taken
(K36, R10), module autoload left to the host (K21, R1), the `bindv6only`
write succeeding in the container's own namespace (P25), and the
descriptor hand-over through the container's systemd (P14). The driver
needs an Incus or LXD host; where CI has none, the scenario is reported
as skipped, never as passed.

## Gates

| Gate | Tool | Threshold |
|---|---|---|
| Shell scripts | ShellCheck in POSIX sh mode over tracked and unignored new `.sh` files, including audit helpers | zero unsuppressed findings at any severity; each exception uses a local `# shellcheck disable=SCnnnn` directive with an adjacent reason |
| Coverage | `cargo llvm-cov` over unit, rules, properties, the fake conformance run and the container runs (profiles merged) | 100 % production lines and branches of `src/`; test-only `#[cfg(test)]` bodies/helpers excluded from instrumentation, with all required tests still executing; production exclusions only in `kernel::linux` for branches no kernel of the range reaches, each marked `// coverage: unreachable on <range>, <reason>` |
| Rule map | `tests/tools/rulemap.rs` reads every rule definition of `docs/spec/*.md`, which is a line starting with `X1.` or a table row starting with `\| X1 \|` (letters `A`, `C`, `D`, `E`, `G`, `H`, `K`, `L`, `M`, `O`, `P`, `R`, `S`, `T`, `V`), and `/// spec:` comments attached to `#[test]` or `#[tokio::test]` declarations in `tests/` and `src/` | every active rule has a test declaration citation with path, line and function; removed rules exempt. Lexical traceability only: it does not prove execution, feature selection or semantic coverage |
| Source link | `tests/tools/srclink.rs` reads every `// kernel:` comment of `src/kernel/linux/` | every function cites a K fact; linux-scoped facts have production citations; delegated/source-only facts have explicit evidence-map classifications and test declaration citations |
| Determinism | Ten seeded fake-suite and ten container-suite repetitions in CI, as the plan requires; the Phase 6 page's local container minimum is three | zero flakes before a gate is enabled |
| Warnings | `cargo clippy --all-targets --all-features -- -D warnings`, `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps`, builds with no default features and with `serde` | clean |

Required suites separately record the selected features, ignored/live test
execution and results. Keep explicit per-clause/table-case coverage;
a green rule map alone cannot close a phase. The implemented runners
exercise a partial case set; their existence does not close a gate.
Startup fault-injection subprocesses have a separate test executable:
forking alongside fake socket owners can temporarily retain their descriptors
until exec and invalidate immediate-cleanup assertions.
CI and local `./test-ci-gates.sh` runs share the same blocking checks:
ShellCheck, formatting, warning-denied Clippy and documentation,
no-default/serde library builds, native/musl tests, and strict rule-map and
source-link checks. A green CI run does not establish the coverage or complete kernel matrix
gates. Current review probes and exact commands are in repository file
`tests/kernel/README.md`.

The [initial CI qualification](../audit/phase6/strict-gates-20261031/README.md)
passed all ten seeded fake/live repetitions on its first attempt. The
qualification used one fresh QEMU guest per seed, with at most two jobs
running at once. Regular CI now runs one full live guest per push or pull
request. Each guest executes
the same Rust scenario binary as the Docker runner, plus live kernel and
process suites. QEMU keeps module loading and networking inside the guest;
it does not test the Incus or root-systemd profiles. Each job has a
40-minute limit, the live-suite step has 20 minutes, and QEMU itself has
900 seconds. The ordinary build job has 30 minutes. Failed repetitions
remain failures and retain their logs; the workflow does not retry them.
The ten-run qualification preceded strict map enforcement. A later failure
still requires investigation; the retained qualification does not establish
that every test or kernel target is deterministic.

Coverage instrumentation excludes test-only `#[cfg(test)]` modules/helpers,
as approved on 2026-10-31. Every required test still runs. The coverage step
uses pinned nightly-2026-10-28 and cargo-llvm-cov 0.9.1 with branch reporting;
ordinary checks and shipped musl binaries stay on stable. The native CI
badge report is distinct from the merged live-profile P4 gate. The latest
merged report is 93.32% lines / 80.95% branches, with no production
exclusions; 100% remains required. Repository file
`audit/phase6/upstream-dhcp-queues-20261031/README.md` records fresh native,
live, manager, Incus and root-systemd profiles with released `iphost` 0.4.3,
including a deterministic readiness case. It fixes subscriber history and
queue bounds after 0.4.2 fixed namespace isolation. Complete resource/event-cost
proof and the final matrix remain open.

## Running

```sh
./test-ci-gates.sh                          # the same blocking checks as CI (requires ShellCheck)
cargo test --locked --all-features --target x86_64-unknown-linux-musl # unit, rules, seeded properties, fake conformance
# Planned: tests/docker/run.sh conformance; existing live commands are in tests/kernel/README.md
tests/docker/run.sh scenarios                # the scenario suite
tests/docker/run.sh matrix required          # the required kernels of "Kernel targets" (QEMU, TCG, unprivileged)
tests/docker/run.sh matrix v6.8..v7.3        # every vanilla release of the range
tests/docker/run.sh incus                    # the unprivileged system-container scenario, on an Incus/LXD host
cargo llvm-cov --all-features -- --include-ignored   # with the container profiles mounted back
```

The musl command and the scenarios, matrix and Incus entry points exist;
their complete case set remains Phase 6 work. The separate conformance
entry point is still planned; repository file `tests/kernel/README.md`
gives the existing live commands. Plain `cargo test` skips the
`fake-kernel`-gated rules and conformance targets. Coverage must name and execute
the required features and live suites; do not treat a lenient rule map as
proof that new clauses pass.

The container runs need `--cap-add NET_ADMIN --cap-add NET_RAW` (and
`--privileged` for sysctls), host-kernel L2TP support, no host
networking and no writable host mounts; the QEMU runs need only a user
account and the kernel images the driver builds or fetches.

## Contract correction acceptance cases

The guest-only `no-vrf` profile tests R45 with a modular stock kernel:
`tests/kernel/run-guest.sh IMAGE MODULES CONFIG no-vrf RECORD`. It leaves
the VRF driver unloaded and disables guest module autoload, requires a real
VRF creation refusal, then tests ordinary-device binding and frames over both
families. It is a scoped profile, separate from the normal suite; it never
changes the host's modules or autoload policy. See the
[host-requirement record](../audit/phase6/host-requirements-20261031/README.md).

These cases are required by the 2026-10-29 contract corrections.
Phase 2–3 evidence (repository file `audit/PHASE23_VERIFICATION_2026-10-29.md`) identifies
the implemented policy, adapter and live-boundary cases.
Phase 4 evidence (repository file `audit/PHASE4_VERIFICATION_2026-10-29.md`) adds callback,
queue, service-drop and library handshake cases. Phase 5 and its October 30
follow-up add actual-process crash/re-exec acceptance; the remaining
whole-daemon timing, resource and host-matrix portions belong to Phase 6.

| Rules | Deterministic policy case | Real boundary evidence |
|---|---|---|
| S23, M18, S24 | Lose lifetime notifications while staged; replace the device using both its index and temporary name. No rename/MAC operation may hit the replacement. Verify ambiguity/refusal preserves it, and confirmed absence precedes restaging. | Namespace move/reuse on the live kernel; compare the registration incarnation, not only current name/index. |
| L12, T26, P8, P25 | Delay success to the last instant before 5 s: no tunnel registered meanwhile, then fresh dual-stack socket. Cover failure, exact deadline, late success, still-v6-only read-back, multiple waiters and shutdown. Existing sessions never re-create. | Set `bindv6only=1` in an isolated namespace; confirm fresh socket read-back after write, both V4/V6 fallbacks and the kernel's fixed per-socket option. |
| P14, P26, L13 | Inherit removed or changed-peer tunnels; retain exact names through rejection, distinguish a failed query from a mismatch, and serialize old-name withdrawal before replacement storage. Cover failed/missing acknowledgements and cleanup retries. | With a real systemd store, close only the local duplicate and show the tunnel remains; then withdraw the stored copy and confirm absence. Exercise crash/re-exec with changed config, a delayed removal/barrier and bounded failing shutdown. |
| V3, V15, G23 | Block eight fake libc calls; repeatedly replace/remove names and create/drop services. No ninth system worker starts; permits return only when calls do. Configured DNS, kernel events, readiness and shutdown still progress. Verify one pending/latest result per current key and release of unused discovery refs. | Adapter tests use a controllable blocking resolver rather than waiting on real DNS; test namespace ownership and actual thread/descriptor counts. |
| V10 | A+B, then refresh or withdraw A alone: B remains. Include no-RDNSS RA, interleaved routers, split netlink delivery, lifetime/stale rules and capacity overflow. | Upstream Rust parser/state regressions; raw and ND_USEROPT paths yield equivalent updates. Downstream tests use the released corrected crate. |
| V14 | Enable fallback: DHCPv6 timeouts/SERVFAIL with working RA; positive/negative DHCPv6 finality; partial-family success; recovery next refresh; both sources fail. | Upstream transport tests verify default compatibility, per-family results and policy-dependent 33/63 s upper bounds. Downstream tests enable the released option explicitly. |

Use barriers, injected results and virtual clocks for delayed calls and
deadlines; no fixed sleeps or uncontrolled Internet DNS in unit tests.
Upstream and daemon tests have separate ownership:
[upstream instructions](upstream-iphost.md).

## Kernel test pitfalls

Facts that cost time once and shape how the tests are written:

- The kernel never echoes a route notification to the netlink port that
  requested the change; a test listening for its own change needs a
  second connection.
- A VRF whose table has no IPv4 `unreachable default` route falls through
  to the main table for IPv4 lookups.
- A socket bound to an ordinary device with no route to an IPv4
  destination still connects: the kernel assumes the destination is
  on-link and sends ARP out of the device (K28). A successful IPv4 connect
  proves no route.
- `ip netns exec` fails inside a Docker container (it cannot remount
  sysfs); `nsenter --net=/run/netns/<name>` works, and does not switch
  `/sys`, so read a namespace's counters with `ip -s link`.
- iproute2 6.15 parses `ip link add a type dummy` as an address; write
  `ip link add name a type dummy`.
- Classic BPF loads multi-byte fields in network byte order while netlink
  headers are in host byte order: a message type is compared byte-swapped.
- The `l2tpeth` device of a session keeps the name the kernel recorded at
  creation in `ip l2tp show session`, whatever its current name (K16);
  `ip link del` on such a device is refused `EOPNOTSUPP`, in any
  namespace, and the device can be moved to another namespace while its
  session stays in the origin one.
- Deleting a session and creating one with the same identifiers at once
  can be refused `EEXIST` for a moment (K18); tunnel deletion is
  asynchronous on every kernel (K17).
- A netlink socket whose queue is full loses kernel unicast replies and
  raises `ENOBUFS` on the next receive (K29); with `NETLINK_NO_ENOBUFS`
  the reply is simply missing. The subscriptions never set it.
- A tunnel registered on an unconnected socket drops the frames of its
  sessions (`tx_dropped` on the device) and still receives frames from
  the peer; the kernel's own router solicitations on a fresh device count
  as dropped frames before any test frame is sent.
- Two UDP sockets share a port only when both set `SO_REUSEADDR`.
