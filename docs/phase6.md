# Phase 6 instructions: the proof

[Documentation index](README.md) · [Plan](plan.md#phase-6--proof) · [Testing](testing.md)

Written for the coding agents and contributors who execute Phase 6. The
[specification](spec/README.md) is normative; the [plan](plan.md) says
what Phase 6 delivers; [testing](testing.md) defines the gates. This
page turns those into ordered work packages with commands, deliverables
and acceptance criteria. Where this page and the specification differ,
the specification is right; where it and the plan differ, the plan is.

## Entry state

Phase 6 starts from the tree after the Phase 5 completion check and its
fix commit (repository files `audit/PHASE5_COMPLETION_CONFORMANCE_2026-10-30.md`
and `audit/phase5-completion/`). Everything in that report's fix list is
done except E5, the strict traceability gates, which are this phase's
first package, and the follow-up list F of the same report: F1 (an
undecodable or foreign-family record fails a whole rtnetlink dump) and
F2 (event-path re-creation always stages) are fixed before Phase 6
starts; F3 to F7 are folded into the packages below (F3 into P2's H17
scenario, F4 into P7's hosts page sentence, F5 into P1's E1 test, F6
into P7's packaging page, F7 into P1's service tests). The live reconnection scenarios of that check
(`audit/phase5-completion/reconnect/scenario.sh`) and its networkd and
udev experiment (`audit/phase5-completion/networkd/`) are the seeds of
the scenario suite below; read them before writing new scenarios.

## Rules that hold for the whole phase

- **Nothing is proved by reading.** A gate is green when the command in
  this page ran and its log is in the verification record. A `/// spec:`
  tag is traceability, not proof; a passing test that would also pass
  without the behaviour it names is a defect of the test.
- **Never weaken a rule to make a gate pass.** A rule that cannot be
  tested as written is a question for the maintainer, asked with the
  rule number, what the test would need, and the smallest change that
  would make it testable. Stop that package until answered; continue
  the others.
- **Stop at the upstream boundary.** A need in `l2tp` or `iphost` is
  written into [dependencies](dependencies.md#upstream-needs) and fixed
  upstream first (`CONTRIBUTING.md`, step 5). No workaround in the daemon.
- **No new dependency without a row in [dependencies](dependencies.md).**
  Test tooling is pure Rust or POSIX `sh`; no Python, Node or Perl on
  the host or in the images. `cargo-llvm-cov` is the one tool installed
  for this phase (`cargo install cargo-llvm-cov --locked`, plus
  `rustup component add llvm-tools-preview`).
- **The host is not root.** Privileged work runs in disposable
  containers (`docker run --rm --privileged --network none`) or QEMU
  guests; nothing changes the host's network, sysctls or units. The
  user systemd manager may be used through `systemd-run --user`.
- **Commits** go through `./commit.sh`, pushes through `./sync.sh`, one
  package or one gate per commit, the gate's log committed with it under
  `audit/phase6/`. Never `git add -A`.
- **Records tell the truth.** Every run records `uname -r`, the exact
  command, the feature set, the counts, and what was skipped and why. A
  skipped scenario is reported as skipped, never as passed; a gate that
  ran on a superseded kernel version does not count.
- **Determinism before a gate is enabled.** A fake-kernel suite runs ten
  times with different seeds, the container suite three times, with zero
  flakes, before its strict flag goes into CI.

## The six gates

| Gate | Green when | Package |
|---|---|---|
| Rule map | `RULEMAP_STRICT=1 cargo test --test rulemap` passes: every active rule of every spec page is cited by a test declaration | P1 |
| Source link | `SRCLINK_STRICT=1 cargo test --test srclink` passes: every `kernel::linux` function cites a K fact and every K fact is cited | P1 |
| Scenario suite | `tests/docker/run.sh scenarios` passes on the host kernel: one scenario per H rule and per conditional promise G15–G23, plus G11 interoperability with 0.1.5 | P2 |
| Kernel matrix | `tests/docker/run.sh matrix required` passes on every kernel of the [kernel targets](testing.md#kernel-targets) table as resolved on the run's date | P3 |
| Coverage | `cargo llvm-cov` over unit, rules, properties, fake conformance and the container profiles reports 100 % of lines and branches of `src/`, with only the marked `kernel::linux` exclusions | P4 |
| Incus/LXD | `tests/docker/run.sh incus` ran, not skipped, in an unprivileged system container | P5 |

Exit of the phase: all six green on the running kernel and on every
required kernel target, the root system-unit sandbox check (P6) run,
the verification record written (P7), and the strict flags on in CI.

## P1. Traceability: close E5

Current state (repository file `audit/phase5-completion/fixes/strict-rulemap.log`):
340 rules, 330 active, 101 without a test citation; five K facts never
cited by a `kernel::linux` function (K13, K14, K33, K38, K40).

1. Classify every uncited rule by the kind of test that proves it, and
   write that test, not a placeholder:
   - **H rules (H1–H19)**: each is a scenario of P2; the scenario's test
     function carries the tag. Do P1's H part together with P2.
   - **R rules (the host, the operator, the peers, other managers)**: a
     requirement is tested by what the daemon does when it is not met.
     `R49`/`R4`/`R46` (missing capability): run the binary in a container
     with the capability dropped and assert the one-time report and the
     fallback. `R1` (modules): a guest without `l2tp_eth` and the H15
     report. Operator rules (R18–R30 and the like) are tested where the
     daemon tolerates or refuses the operator's mistake; most already have
     a configuration or reconciler test to extend with the tag rather than
     a new test. Peer rules by frames the test injects.
   - **G rules**: G1 (never exits on input) is a fuzz-style test over the
     fake kernel's reply variations plus the process test with malformed
     files; G2 and G4 by the property suite (`tests/properties/planner.rs`)
     with assertions named; G8 by the readiness scenario; G9, G20 by the
     shutdown scenario with `ip l2tp show`; G10 by `capget` in the live
     test; G11 by the 0.1.5 interoperability scenario; G12, G13 by
     counting kernel requests and log lines on the fake kernel; G14 by
     the service tests; G15–G17, G19, G21 by scenarios with timing
     asserted on the monotonic clock.
   - **A rules**: architecture rules are tested where they are
     observable. A5 (requests never on the monitor socket): a live test
     that reads the monitor socket's port and asserts no request carries
     it. A8–A12 (records, ownership): the planner properties. A15–A21
     (concurrency, extension): the runtime and service tests. A1–A4 are
     module-map statements; cite them from the existing boundary test of
     L3 and from `tests/tools/rulemap.rs` itself where they describe the
     test layout.
   - **K facts never cited**: K13, K14, K38 and K40 are resolver-side
     facts delegated to `iphost` ([kernel evidence](kernel-evidence.md)),
     K33 (addresses dropped on down) is relied on by the reconciler's
     S12 deferral, not by `kernel::linux`. The source-link gate as
     written requires a `kernel::linux` citation for each. Do not add
     fake citations. Ask the maintainer which of two changes they want:
     the gate reads the evidence map's classification and accepts a
     delegated or source-only fact when `docs/kernel-evidence.md` says
     so and a test cites the fact, or the five facts move to a separate
     table in `kernel.md` that the gate does not count. Proceed with the
     other packages meanwhile.
   - **O2, O4, O9, E26**: log-level and message-content tests on the
     report module and the process tests (E26 is the restart request
     through the control handle and `SIGUSR2`).
2. When the count reaches zero on the host, run the suites ten times
   (see determinism), then set `RULEMAP_STRICT=1` and `SRCLINK_STRICT=1`
   in `.github/workflows/ci.yml` and remove the "lenient until phase 6"
   comments from `Cargo.toml` and `testing.md`.

Acceptance: both strict commands pass locally and in CI; the record
lists the rules that gained tests with their test locations.

## P2. The scenario suite

Deliverable: `tests/scenarios/` as Rust integration tests (one file per
spec page: `hosts.rs`, `promises.rs`, `managers.rs`), a single POSIX
runner `tests/docker/run.sh` with the sub-commands of
[testing](testing.md#running), and a review image built from
`tests/kernel/Dockerfile.review` (iproute2 with L2TP, busybox, no
Python). The runner builds the static daemon and the test executables
for `x86_64-unknown-linux-musl`, mounts the checkout read-only at its
absolute path, and runs the tests `--ignored --test-threads=1` in a
privileged container with `--network none`.

Design rules, learned in Phase 5 and the completion check:

- A scenario is two network namespaces joined by a veth pair, one daemon
  on each side (`--foreground --config … --config-dir …`), built with
  `ip` from inside the test through `nsenter --net=/run/netns/<name>`
  (`ip netns exec` fails in Docker). Connectivity is proved by frames:
  bring the `l2tpeth` devices up with addresses and ping, or send a
  frame and read the peer device's counters; `tx_dropped` growing on a
  disconnected tunnel proves K5. Never infer from a log line alone.
- Waits are event-driven with a hard timeout: poll a counter, a device
  or a log line at 100 ms until it appears or the scenario fails; no
  fixed sleep as a synchronisation step. Timing assertions (G15–G17, the
  convergence bounds table) measure on `Instant` from the event the
  test caused.
- Every daemon is started with a cleanup guard that kills it and deletes
  the namespaces on panic.
- The 0.1.5 baseline binary is built once by the runner from
  `git archive v0.1.5` with its own `Cargo.lock` into a cache directory
  (it builds under the cooldown proxy), for the G11 scenario only.

The scenarios, one test function each, tag in the doc comment:

| Tag | Host condition the test builds | Assertion |
|---|---|---|
| H1 | dual stack, IPv4 and IPv6 peers | both on `AF_INET6` sockets, frames both ways |
| H2 | IPv6 stack present, no IPv6 address or route | IPv4 peer connects, IPv6 peer disconnected, ready before any route |
| H3 | `disable_ipv6=1` on `all` and `default` | as H2, sockets still `AF_INET6` |
| H4, T4 | a QEMU kernel booted with `ipv6.disable=1`, and one built without IPv6 (P3) | `AF_INET` sockets, every rule of T4 |
| H5 | IPv6-only | the mirror of H2 |
| H6, G21, P1 | no route at all at start | ready at once, tunnels created disconnected, connect within 1 s of the first route |
| H7, E4, T27 | VRF with and without members, member join and `nomaster`, zoned link-local peer | source from the VRF domain, disconnect on `nomaster`, zone member rule |
| H8 | a table of 100 000 routes, no default route | no request from the daemon touches routes (count `RTM_GETROUTE` through a second netlink socket), convergence time unchanged |
| H9 | the daemon in a non-initial namespace with `/proc` unmounted | works; `SO_RCVBUFFORCE` refused handled (K36) |
| H10 | a child VLAN of a session device moved to another namespace | shutdown removes it with the parent; the daemon never touches it |
| H11 | the networkd/udev images of `audit/phase5-completion/networkd/` | direct creation gets the configured name's `.network` and persistent MAC; a staged session (hwaddr configured) is renamed and the limitation of H11 holds as documented |
| H12 | a foreign `ip l2tp` tunnel and session holding configured identifiers and a foreign device holding a configured name | conflicts counted, left out after ten, created when freed; foreign objects untouched |
| H13 | bind device unplugged, replugged, replaced under the same name | the convergence bounds table rows |
| H14 | address churn on the bind device, both families | one reconnect per same-family change, none otherwise |
| H15, R1, R49 | container without `l2tp_eth`; capabilities dropped one at a time | one report each, readiness withheld only for the module/`CAP_NET_ADMIN` case, fallbacks for the other two |
| H16 | clock stepped with `date -s` inside the namespace | no effect on timers |
| H17, M16, G12, G23 | 300 tunnels and 300 sessions | readiness time, memory and descriptor counts bounded as the rules say; an unrelated link event costs no kernel request |
| H18, P25, T26 | `bindv6only=1` with the fix on and off | the handshake, the fallback, the read-back |
| H19, P22 | started by a POSIX `sh` script acting as init: parent exit, PID file, signals | the process contract |
| G11 | the new daemon on one side, 0.1.5 on the other | frames both ways with the 0.1.5 configuration format |
| G15–G20 | the convergence bounds table, one row per assertion | each bound measured |

Acceptance: `tests/docker/run.sh scenarios` passes on the host kernel
three times in a row; every H rule and G15–G23 carry a citation.

## P3. The kernel matrix

Deliverable: `tests/kernel/matrix.sh` (POSIX) driven by
`tests/docker/run.sh matrix required|v6.8..v7.3`, which builds or
fetches each kernel, boots it under TCG QEMU with an initramfs holding
the static binary and the test executables, runs the conformance suite,
the process suite and the scenario subset that needs no second
container, and requires the result marker, not QEMU's exit code.

- The **required set** is the table in [testing](testing.md#kernel-targets),
  re-resolved on the run's date: the stock kernels of the two latest
  Ubuntu LTS releases, their vanilla equivalents, and mainline. Ubuntu
  kernels come from the `linux-image-*-generic` package of the
  `ubuntu:24.04` and `ubuntu:26.04` images (unpack `vmlinuz` and the
  modules; the init loads `l2tp_core`, `l2tp_netlink`, `l2tp_ip`,
  `l2tp_ip6`, `l2tp_eth`, `vrf`, `dummy`, `veth`). Vanilla and mainline
  kernels are built from kernel.org tarballs in a `debian:trixie-slim`
  container (the host lacks flex and bison): `x86_64_defconfig` plus
  L2TP, VRF, dummy, veth, bridge and 802.1Q built in; about a minute on
  this host. One extra build has IPv6 disabled for H4 and T4.
- The **desired set** is every release from v6.8 to the newest; run it
  when the required set is green and record which ones ran.
- Memory `-m 2048` (the initramfs holds unstripped test binaries); strip
  only the copies that go into the guest.
- Update the table in `testing.md` whenever Ubuntu or kernel.org moves,
  and re-run before calling the gate green.

Acceptance: `CONFORMANCE_RESULT=0` and `SCENARIO_RESULT=0` for every
required kernel, the `uname -r` of each in the record.

## P4. Coverage

- Build with `cargo llvm-cov` on the `x86_64-unknown-linux-gnu` target
  (instrumentation and profile merging are simplest there); the musl
  binary stays the shipped artefact and is still exercised by P2 and P3.
- Profiles from container and QEMU runs are written to a directory the
  test sets through `LLVM_PROFILE_FILE` and mounted back; the runner
  merges them with the native profiles (`cargo llvm-cov report` after
  `--no-report` runs).
- Branch coverage needs a nightly toolchain for `-C instrument-coverage`
  branch regions. Use nightly for the coverage job only, pinned in CI;
  the shipped binary stays on stable. If the maintainer prefers a
  stable-only job, report line and region coverage and say so in the
  record; that is a decision to ask for, not to take.
- Gate: 100 % of lines and branches of `src/`. The only allowed exclusion
  is a `kernel::linux` branch no kernel of the verified range reaches,
  marked `// coverage: unreachable on <range>, <reason>` and listed in
  the record. A branch that is reachable but untested is a missing test,
  not an exclusion.

Acceptance: the merged report at 100 % with the exclusion list; the
command in CI as a separate job.

## P5. The unprivileged system container

What it checks is in [testing](testing.md#the-scenario-suite): a
`security.privileged=false` container with the L2TP modules loaded by the
host, `CAP_NET_ADMIN` only inside, `SO_RCVBUFFORCE` refused and the
fallback taken (K36, R10), module autoload left to the host (K21, R1),
the `bindv6only` write in the container's own namespace (P25), and the
descriptor hand-over through the container's systemd (P14).

The maintainer installs Incus on the development host for this package:
`dev` in the `incus-admin` group, the `images:` remote reachable
(`ubuntu/24.04`, `debian/12`), no managed bridge needed, and the host's
L2TP, VRF and dummy modules loaded at boot, because the unprivileged
container cannot load them and that is what H9 and K21 test. Check with
`incus list` before starting; where it is absent (CI, another host) the
runner reports `skipped: no Incus access` with a non-zero exit distinct
from failure. The gate is green only when it ran. The scenario: launch
`images:ubuntu/24.04` unprivileged, push the static daemon, a
configuration and the unit, install with `--setup-systemd` inside, and
assert the five checks above plus a networkd `.network` match on the
directly created session device (H11) and the P14 hand-over across a
`kill -9` under the container's systemd.

## P6. The root system-unit sandbox

The one check the Phase 5 review left open (C6 of the 2026-10-29 review):
the supplied unit under a real root systemd, with every mount and
capability restriction active. Run it in a QEMU guest of P3 that boots a
minimal systemd (an Ubuntu 24.04 root filesystem from the `ubuntu:24.04`
image with `systemd` installed, the daemon installed by `--setup-systemd`
inside the guest), and assert: the unit starts and `network-online.target`
waits for it; the `bindv6only` write succeeds under
`ProtectKernelTunables=yes` through `ReadWritePaths`; the PID file lands
in `/run/rs-l2tpd/`; `capsh --print` of the main process shows exactly
the three capabilities; `kill -9` of the daemon keeps the tunnels alive
through the descriptor store and the restarted instance adopts them;
`rs-l2tpd --restart --pid-file /run/rs-l2tpd/rs-l2tpd.pid` keeps the
interface indices; `systemctl stop` removes everything and exits 0.

Acceptance: the guest's journal and the assertions in the record.

## P7. The verification record and the documentation

- `audit/PHASE6_VERIFICATION_<date>.md`: every gate, the exact command,
  `uname -r` per run, counts, durations, the skipped list with reasons,
  the coverage exclusion list, and links to the logs under
  `audit/phase6/`.
- `docs/plan.md` Phase 6 status, `docs/testing.md` (the gates table
  loses "planned", the kernel table gets the run date), `docs/README.md`
  and the top-level `README.md` status paragraphs, `tests/docker/README.md`
  rewritten for the real runner, `.github/workflows/ci.yml` with the
  strict flags, the coverage job and the determinism repeats.
- Documentation stays standalone: name repository files outside `docs/`
  in prose, never link them.

## Order and parallelism

P2 first, because P1's H rules and most G rules are its scenarios, and
P3 and P5 reuse its tests. P1's non-scenario rules and P4's tooling can
start in parallel with P2. P3 after P2 passes on the host kernel. P6
needs P3's guest tooling. P5 waits for the maintainer's access decision.
P7 is written as the gates turn green, not at the end.

## Stop and ask when

- a rule cannot be tested as written (name the rule, the obstacle, the
  smallest change);
- `l2tp` or `iphost` lacks something the test needs;
- the source-link gate's treatment of delegated facts (P1) has not been
  decided;
- the coverage job's toolchain (P4) has not been decided;
- Incus/LXD access (P5) is missing;
- a scenario shows the daemon doing something the specification does
  not say, even when the suite is green: that is either a defect or a
  spec gap, and both are the maintainer's call.
