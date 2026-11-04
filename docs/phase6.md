# Phase 6: verification gates

[Documentation index](README.md) · [Plan](plan.md#phase-6--proof) · [Testing](testing.md)

Phase 6 is complete. These gates remain the acceptance criteria for further
changes. The [specification](spec/README.md) defines behavior; a passing
citation check alone does not prove an assertion or execute an ignored test.
Repository file `audit/VERIFICATION.md` indexes the current source and results.

## Current status

Production source `c599b1f` passes all three
[CI jobs](https://github.com/menhera-org/rs-l2tpd/actions/runs/41755915522)
and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41755915465).
Merged production coverage is **8,582/8,582 lines and 1,844/1,844 condition
outcomes**, with unchanged exclusions. The local raw LLVM summary is
99.45% lines and 98.26% outcomes; it remains a separate measurement.
Strict maps cover all 333 active rules and all 43 kernel facts.

All thirteen required profiles pass on unchanged production/test source and
stable publication selections: five full normal suites, five clock/pause
cases, both IPv6-absent boots and missing-driver recovery. Each normal
target passes 27 scenarios and 37 process cases. Three consecutive musl
scenario/Incus pairs and the unmodified root-systemd guest also pass.

All six Debian 12 and Rocky 9/10 optional profiles have run. Rocky 9/10
pass normal and clock checks. Debian 12's normal and clock profiles fail
existing MAC/UP-device rename assertions;
its process and normal scenario suites were not reached. Results remain
separate from the required Phase 6 gate.


## Rules for verification

- A gate passes only after its command executes successfully on identified
  source and its results are retained. Record selected features, ignored/live
  execution, exact kernel releases, artifact identities and skips/failures.
- Keep semantic clause/table cases separate from declaration traceability.
  A test that passes without its claimed behavior does not prove that behavior.
- Never weaken a rule or add a coverage exclusion to make a run pass.
  An untestable rule, missing upstream capability or unexplained behavior
  discrepancy needs the maintainer's decision; continue independent work.
- Fix required `l2tp`/`iphost` capabilities upstream first. The documented
  checked-`libc` exception for broken `nix` wrappers requires GNU/musl tests.
- Keep verification tooling pure Rust or POSIX `sh` and list its dependencies
  in [dependencies](dependencies.md). Do not change host networking, sysctls
  or units. Run privileged work inside disposable networkless Docker/Incus
  containers or QEMU guests. No managed bridge or host interface attachment.
- Commit with `./commit.sh` and push with `./sync.sh`; retain only your own
  changes. Never `git add -A`. Machine-specific facts do not belong in records.
- Report a skip as a skip. Missing Incus access does not pass its gate;
  a superseded required kernel does not satisfy the moving target rule.
- Qualify determinism before enabling a strict gate: ten seeded fake runs
  and the required ten CI live repetitions, plus three local scenario runs.
  Routine CI's one live guest does not substitute for that qualification.

## The six gates

| Gate | Acceptance | Package |
|---|---|---|
| Rule map | Every active numbered rule has a test-declaration citation; strict rule map passes | P1 |
| Source link | Every `kernel::linux` function cites a K fact; every fact has its classified production/test evidence | P1 |
| Scenarios | All normal host/manager scenarios execute successfully, including H20 fragmentation | P2 |
| Required kernels | All thirteen required profiles pass with stable publication selections and source identities | P3 |
| Coverage | Checked merged production source lines and executable condition outcomes both reach 100%, with only approved exclusions | P4 |
| Incus/LXD | Unprivileged system-container scenario executes successfully | P5 |

The root system-unit sandbox (P6), complete clause-case evidence and current
documentation/records (P7) are additional phase-exit requirements.

## P1. Traceability

```sh
RULEMAP_STRICT=1 cargo test --locked --test rulemap
SRCLINK_STRICT=1 cargo test --locked --test srclink
```

The common CI script enables both strict flags. Rule tags belong on test
declarations, not helper functions. Keep a case for every distinct clause,
table row and failure convention. Architecture/host requirements need tests
of their observable consequences rather than placeholder citations.

The source-link gate reads [kernel evidence](kernel-evidence.md). Linux-scoped
facts need production citations. Delegated and source-only facts need explicit
classification and test citations; do not manufacture Linux production links
for resolver internals or device lowering that the daemon never performs.

## P2. The scenario suite

```sh
tests/docker/run.sh scenarios
```

The runner builds static musl executables and uses the prepared review image
in a disposable privileged container with `--network none`. It mounts the
checkout read-only. Rust fixtures create all namespaces, links, routes and
addresses inside the container and clean up on failure. The archived v0.1.5
peer is built with its own lockfile in an isolated cache for interoperability.

Scenarios cover H1–H20, G11 and the conditional timing/resource promises.
Prove connectivity with actual frames and receive/drop counters, not logs
alone. Event waits have hard deadlines; do not use fixed sleeps for ordering.
Fake clocks assert exact retry deadlines, while live convergence includes the
scheduling/kernel-operation delays stated by the contract.

H20 is mandatory on every normal kernel target: session MTUs 1500 and 9000,
underlay MTU 1500, IPv4/IPv6 and VRF/ordinary binding. Check bidirectional
full-size frames, bulk traffic, sender fragments, session receive counters
and no transmit drops. Socket options are read back separately. Netfilter
can keep IPv6 reassembly statistics at zero; delivery counters remain required.

Run three consecutive local scenario/Incus pairs without flakes. Shared-kernel
scale and request-count windows run serially; see [testing](testing.md) for
neighbor-budget and cross-namespace notification interference.

## P3. The kernel matrix

```sh
tests/docker/run.sh matrix required
tests/docker/run.sh matrix v6.8..v7.3
```

Resolve the [required targets](testing.md#kernel-targets) before and after the
run: the latest two Ubuntu LTS kernels, their vanilla equivalents and mainline.
Record parsed publication selections and package/source digests. Kernel.org
HTML indexes are fetched and parsed in temporary storage, never committed.
Reject changed targets or source patches.

Each normal boot runs conformance, binary/process checks and all 27 scenarios.
Each required kernel also gets an H16 boot with guest wall-clock steps and a
controller-confirmed QMP pause/resume. Run clock-sensitive profiles serially.
Mainline additionally boots with `ipv6.disable=1` and with `CONFIG_IPV6=n`;
modular Ubuntu gets missing-Ethernet-driver recovery.

Require the expected guest release and all suite/result markers, including
`H16_CONTROLLER_RESULT=0` for clock runs. A zero QEMU exit is insufficient.
The helper's conditional `kho=off` is a cold-boot initramfs setting only;
see [kernel behavior](kernel-behavior.md).

Optional distribution kernels extend the evidence without replacing required
targets. Reproduction helpers and exact package metadata are recorded with
the optional results; kernel-only guests do not qualify distribution userspace.

## P4. Coverage

Use pinned `nightly-2026-10-28`, cargo-llvm-cov 0.9.1 and LLVM tools for GNU
branch instrumentation. Stable musl remains the shipped build and has its
own live qualification. The separate CI job collects ten native seeds, a full
instrumented guest and thread/fork-limit profiles from unchanged source.
Repository file `tools/coverage/README.md` documents collection and checking.

The gate merges counts only for matching production source spans and condition
occurrences across executable copies. Both outcomes of every executable
condition must run. Folded outcomes follow LLVM's classification; raw
per-instantiation totals remain separate and must be retained.

Test-only `#[cfg(test)]` bodies/helpers are excluded from instrumentation,
but every required test still executes. The only production exclusions are
marked `kernel::linux` branches unreachable throughout the verified range.
A reachable untested branch is missing evidence, not an exclusion.
Retain source/mapping inventories, complete compressed exports, raw summary,
diagnostics and the exclusion list. Reject changed sources, inconsistent
mappings or unsupported export schemas. Calibration must reject missing arms,
repeated-guard misses, changed source and invalid input before collecting P4.

## P5. The unprivileged system container

```sh
tests/docker/run.sh incus
```

Require usable Incus/LXD access and host-provided L2TP, VRF, dummy and veth
modules. The driver explicitly sets `security.privileged=false`, attaches no
host network device and deletes the container on success or failure. Missing
access exits 77 with an explicit skip; it is not a pass.

Assert namespace-local `bindv6only`, actual `SO_RCVBUFFORCE=EPERM` and ordinary
buffer fallback, real systemd storage/adoption, re-exec and cleanup. H11 checks
both concurrent persistent-MAC/activation outcomes while preserving the active
device, then separately orders persistent assignment while down and requires
stability after re-creation. The staged configured-MAC fixture supplies explicit
`MACAddressPolicy=none` authority for both creation names. Do not promise that
persistent assignment always wins a concurrent manager race or lower an active
device to force it. [H11](spec/hosts.md#other-network-managers) states the limits.

## P6. The root system-unit sandbox

Run `tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD` with the
prepared `nd-test:u2404` image: Ubuntu 24.04 with systemd, udev, dbus,
iproute2 and procps. The runner consumes this prebuilt image; provisioning
must use an offline package source with Docker networking disabled. The
previous preparation recipe remains in
[Git history](https://github.com/menhera-org/rs-l2tpd/blob/c599b1f9c2343a3ffe6be315a6d77c4b68106744/audit/phase5-completion/networkd/Dockerfile).
Install with `--setup-systemd` inside the
guest and leave the supplied unit unmodified. Assert startup ordering, the
tunable write through `ReadWritePaths` under `ProtectKernelTunables=yes`, the
dedicated PID directory and exact three capabilities. Verify crash/store
survival, adoption, CLI restart preserving interface indexes and clean stop.
Retain the guest journal and assertions. A transport-only user-manager check
does not establish this mount-sandbox result.

## P7. Records and documentation

Update repository file `audit/VERIFICATION.md` after the runs. Include source
identities, exact commands, kernel releases, selected features, suite counts,
coverage distinctions, skips/failures and links to current records. Preserve
superseded evidence in Git history before removing it from the main tree.
Do not commit fetched kernel.org HTML.

Keep the plan, testing guide, kernel behavior/evidence, interface, dependency
inventory and runner instructions consistent. Documentation under `docs/`
stays standalone: name repository paths outside it in prose. Keep normative
rules intact unless the maintainer has authorized a contract change.
