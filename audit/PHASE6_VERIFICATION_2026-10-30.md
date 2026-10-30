# Phase 6 verification — 2026-10-30

Status: **in progress; Phase 6 is not complete**. No strict CI flag has
been enabled. The entry commit was `886eae9`.

## Gate status

| Gate/package | Executed evidence | Status |
|---|---|---|
| Source link, P1 | `SRCLINK_STRICT=1 cargo test --locked --all-features --test srclink -- --nocapture`: 4 passed, 0 failed; 43 active facts, 37 production-cited, 6 classified facts, no uncited production function | Local check passes; CI/determinism gate remains open |
| Rule map, P1 | Current strict run: 343 rules, 333 active, 263 cited, 70 without citations (entry: 101 missing) | Open |
| Scenarios, P2 | Expanded 18-case subset passed three times; H4 boot cases also pass; missing cases remain | Open |
| Required kernel matrix, P3 | Kernels built; both stock guests passed conformance/process stages but scenario stages timed out; full reruns and matrix dispatch pending | Open |
| Coverage, P4 | Native baseline recorded separately below; live profiles not merged | Open |
| Incus, P5 | Combined MAC contract executed successfully three times in an unprivileged system container; buffer fallback also executed | Local gate passes |
| Root system-unit sandbox, P6 | Actual root systemd QEMU guest, mounts/capabilities/tunable/order/store/restart/cleanup assertions, 1 passed | Local gate passes |

Initial host checks used `6.8.0-147-generic`. Later QEMU records identify
their guest releases separately. The complete moving required kernel set
has not passed.

## P1 source-link classification

On 2026-10-30 the maintainer selected explicit evidence-map classification
for K13, K14, K33, K38 and K40. No production citation was fabricated.
The source-link check now reads the scope column of
`docs/kernel-evidence.md`: linux facts require production citations;
delegated/source-only facts require nonempty evidence and a test
declaration citation. Missing/invalid scopes and duplicate evidence rows
fail. Both traceability tools use the same test-declaration scanner;
ordinary comments and helper-function comments do not count.

The new live K33 test lowers an IPv6-addressed device, observes address
removal through the production address dump, then repeats with
`keep_addr_on_down=1` and observes preservation. The existing released
unified-resolver test gains K13/K38 citations for its actual DHCPv6 bind
and Reply exchange. K14/K40 retain the released RA adapter's existing
citations; its raw-source run with `accept_ra=0` does not claim to execute
capability-denied netlink fallback.

Live build command (all features, musl):

```sh
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --test kernel-linux --no-run
```

The resulting executables were run in
`docker run --rm --privileged --network none`, with the checkout mounted
read-only at its absolute path and image `rs-l2tpd-audit-vm:local`.
Exact test filters, each with `--ignored --exact <filter> --nocapture`:

- `lowering_a_device_discards_ipv6_addresses_unless_preserved`: 1 passed,
  0 failed, 14 filtered out, 0.03 s.
- `reconciler::resolvers::tests::released_ra_adapter_preserves_omitted_addresses_and_bounds_its_repository`:
  1 passed, 0 failed, 83 filtered out, 0.05 s.
- `reconciler::resolvers::tests::released_unified_adapter_enables_per_family_failure_fallback`:
  1 passed, 0 failed, 83 filtered out, 0.05 s.

Logs:

- [Strict entry rule map](phase6/entry/rulemap.log).
- [Strict entry source link, before correction](phase6/entry/srclink.log).
- [Strict source link with classifications](phase6/entry/srclink-classified.log).
- [Live build](phase6/entry/build-evidence-live.log).
- [Classified-fact live execution](phase6/entry/classified-facts-live.log).
- [Both traceability tools, report mode](phase6/entry/traceability.log).
- [Clippy, all targets/features, warnings denied](phase6/entry/clippy.log).

## Coverage baseline

The coverage toolchain is pinned to `cargo-llvm-cov` 0.9.1 and nightly's LLVM
tools. The nightly manifest date is 2026-10-28
(`rustc 1.101.0-nightly (41089d07a 2026-10-27)`).
The native run used all features, target
`x86_64-unknown-linux-gnu`, and branch instrumentation:

```sh
cargo +nightly llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
cargo +nightly llvm-cov report --target x86_64-unknown-linux-gnu --branch
```

Baseline only: 7,586/9,937 lines (76.34%) and 1,184/1,772 branches
(66.82%). The report is not a combined native/live result and no
coverage exclusion has been introduced. Ignored live tests remain
unexecuted by this native command, as the log records.

- [Native tests with coverage](phase6/entry/coverage-native.log).
- [Native coverage report](phase6/entry/coverage-native-report.log).
- [Verification tool requirements](../docs/dependencies.md#verification-tools).

## Remaining work and exclusions

P1's remaining behavioral-rule cases, the full scenario suite, its complete
determinism/CI gate, the required matrix, merged 100% coverage,
the root system unit, and final documentation/CI integration remain open.
The implemented ordinary suites and 12-case host subset have repetition
evidence below; the approved combined Incus case now passes locally.
No scenario has been counted as skipped-and-passed. No coverage exclusions
have been approved or used.

## Work performed after the source-link commit

F3 is reproduced by `events::a_cached_master_is_not_queried_again_on_each_converge`
on both VRF and ordinary masters. An injected `link_by_index` error
remains unconsumed only if convergence avoids the cached parent lookup.
The regression fails before the fix and passes after it. The existing
membership cache is now reused; a changed parent is still queried, and a
failed query is not cached.

- [F3 before](phase6/entry/f3-before.log).
- [F3 after](phase6/entry/f3-after.log).

The F5 survivor-name test now runs with synchronous and asynchronous
session deletion: the asynchronous case retains the survivor's index,
waits for deletion, retries the occupied name and still accepts a later
manager rename. The F7 convergence-reload test now gates both direct
creation and staged publication. The seeded reload property now asserts
G2 foreign tunnel/session/device preservation and G4 preservation of a
manager-raised session's administrative state, including across shutdown
for the foreign objects.

`cargo test --locked --all-features` passes; all ordinary suites also
passed ten repetitions with `TEST_SEED=1` through `10`, with no failures.
These are repetitions of the implemented fake/ordinary suites, not
proof of the still-missing scenario cases. Strict CI flags remain off.

- [All-feature run](phase6/entry/all-features-current.log).
- [Current Clippy run](phase6/entry/clippy-current.log).
- [Seeded repetition logs](phase6/determinism/).

## Initial H11 / P5 persistent-MAC blocker (decision now resolved)

Reproduction:

```sh
tests/docker/run.sh incus
```

The driver launched `images:ubuntu/24.04` with no profiles/devices and
`security.privileged=false`; no host network interface was attached.
The container ran kernel `6.8.0-147-generic` and systemd 255. The
production buffer test passed with `FORCE_RESULT=EPERM` and
`SUBSCRIPTION_RCVBUF=425984`. The actual supplied unit installed and
started, created the direct-name session, corrected `bindv6only` from 1
to 0 and reached readiness. Its descriptor store contained one socket
in the initial unit probe.

After fixing fixture boot/reload handling, the manager test still fails:
networkd applies `/etc/systemd/network/10-phase6.network` to
`incusl2tp`, raises it, and assigns `198.18.0.1/24`. udev selects
`99-default.link` with `MACAddressPolicy=persistent`, but its write
then fails with `Device or resource busy`. The interface remains up
and addressed. The assertion waiting for persistent MAC application
timed out. That original run was not counted as passing; the assertion was
kept until the maintainer decided the intended contract.

This is the K31 MAC-while-up refusal. P5 asks for a persistent MAC on a
directly created session, while H11 says direct creation avoids the
staging limitation. G4 forbids lowering a manager-raised interface to
repair the race. A maintainer decision is required under Phase 6's
“Stop and ask when” rule: either order udev completion before networkd
activation in this scenario and document the required fixture condition,
or explicitly accept/document the manager race while retaining the
daemon's interface-preservation guarantee. The maintainer subsequently
approved the combined approach described below.

The later crash/adoption, re-exec, persistent re-creation and staged-MAC
assertions were **not reached in that original failing run**. The root QEMU sandbox
check remains separate and unexecuted; Incus's systemd drop-ins do not
prove that gate.

Evidence from the original failing diagnostic run:

- [Build, all features / musl](phase6/incus-20261030T064600Z-3051287/build.log).
- [Expanded container configuration, no inherited devices](phase6/incus-20261030T064600Z-3051287/config.log).
- [Kernel](phase6/incus-20261030T064600Z-3051287/kernel.log).
- [Production buffer fallback, 1 passed](phase6/incus-20261030T064600Z-3051287/buffer.log).
- [System-container case, 1 failed in 23.76 s](phase6/incus-20261030T064600Z-3051287/scenario.log).
- [Manager state and udev EBUSY](phase6/incus-20261030T064600Z-3051287/managers.log).
- [Daemon journal](phase6/incus-20261030T064600Z-3051287/journal.log).
- [Cleanup](phase6/incus-20261030T064600Z-3051287/cleanup.log).
- [Driver command transcript](phase6/entry/incus-gate-networkd.log).

All probe containers were deleted. Phase 6 is not complete.

## Approved combined H11/P5 contract and successful execution

The maintainer approved the combined approach, with precise documented
limitations, on 2026-10-30. H11 and the Phase 6 P2/P5 instructions now
distinguish concurrent manager behavior from an explicitly ordered
persistent-MAC requirement. The daemon does not lower active interfaces
to repair udev's failed policy write; its configured-MAC rules remain S12.

The concurrent case requires the configured-name networkd address and
accepts either persistent assignment or kernel-random retention with
the observed udev MAC-while-up EBUSY report. Other assignment types or
unexplained policy failures fail. Reload, crash adoption and re-exec must
preserve the current MAC and interface index. The ordered case stops
networkd, requires udev to finish with the interface down, then allows
activation. Two clean creations with the same name and machine identity
must have the same persistent MAC and different interface indices.
This does not prove unconditional persistent assignment under concurrent
activation or stability when machine identity/name/policy changes.

Executed command, all features / musl, kernel
`6.8.0-147-generic`:

```sh
tests/docker/run.sh incus
```

| Run | Production buffer case | System-container case | Scenario time | Record |
|---|---|---|---|---|
| 1 | 1 passed, FORCE=EPERM | 1 passed | 19.11 s | [record](phase6/incus-20261030T071634Z-3063126/) |
| 2 | 1 passed, FORCE=EPERM | 1 passed | 12.46 s | [record](phase6/incus-20261030T071930Z-3065199/) |
| 3 | 1 passed, FORCE=EPERM | 1 passed | 19.59 s | [record](phase6/incus-20261030T071956Z-3066542/) |

Every run observed the concurrent EBUSY outcome, then successfully
assigned the same persistent MAC on two separately ordered creations.
The runs also completed the actual supplied unit's tunable correction,
exact three-capability check, descriptor-store survival after SIGKILL,
automatic restart/adoption with unchanged interface index, requested
re-exec, clean deletion and PID removal, stable ordered re-creation,
and staged configured-MAC/networkd case. The buffer test required the
EPERM branch and compared the production subscription buffer against
the ordinary-buffer fallback; all observed 425984 bytes.

No container was skipped. Each driver transcript records commands;
each run directory holds the build/feature selection, kernel, expanded
configuration, buffer result, scenario result, journal, manager diagnostics
and cleanup log. The containers inherited no profiles or host network
devices, and all were deleted. Root QEMU mount-sandbox P6 remains open.

- [Run 1 transcript](phase6/entry/incus-combined-1.log).
- [Run 2 transcript](phase6/entry/incus-combined-2.log).
- [Run 3 transcript](phase6/entry/incus-combined-3.log).
- [Format and warnings checks](phase6/entry/combined-mac-checks.log).
- [Current strict source-link check](phase6/entry/srclink-current.log).
- [Current strict rule-map result: 78 missing citations](phase6/entry/rulemap-current.log).
- [Three repetitions of the 12-case host subset](phase6/P2_HOST_SUBSET_2026-10-30.md).

The H11/P5 decision is resolved. Phase 6 as a whole remains incomplete.

Final P5 repetitions also explicitly check MAC/address/UP preservation
after both crash adoption and requested re-exec. All three passed with
the cleanup-failure check enabled: 17.56 s, 18.94 s and 12.14 s for the
system-container case, plus the separately executed buffer case.
[Final P5 verification](phase6/P5_VERIFICATION_2026-10-30.md) records
the exact scope, counts, logs and remaining P6 distinction.


## P2 follow-up: compatibility, init and route-table independence

G11/G22 now executes an archived v0.1.5 peer with its original lockfile
and compatible configuration. H19/P22 now executes the daemonizing
parent/PID/signal contract through a POSIX shell. H8 now observes every
rtnetlink request through nlmon while startup/reload/shutdown run with
100,000 routes per family and no defaults. Capture controls and loss
accounting prevent an empty or dropped capture from passing.

The expanded subset passed three consecutive runs: 16 passed, zero
failed, 68.20 s / 67.09 s / 66.09 s, kernel 6.8.0-147-generic, all
features, musl. Formatting, clippy with warnings denied, and the capture
parser self-check also passed.
[Scope and evidence](phase6/P2_COMPATIBILITY_AND_ROUTES_2026-10-30.md)
list the remaining scenarios; the complete P2 gate is still open.


## T5 socket contract and H20 fragmentation

The newly specified fragmentation options are now set before the first
connect. A live regression fails before the fix and passes after it on
both socket families, including the IPv4 option on IPv6 sockets. The
single direct syscall is L2's bounded, source-linked exception; all
other options use the existing safe l2tp API. Each option's actual
kernel refusal is tested through a child-only seccomp filter, requiring
one report, continued readiness and traffic, and clean shutdown.

H20 passes all eight IPv4/IPv6 × 1500/9000 × unbound/VRF combinations,
with whole MTU frames, 1 MiB transfers both ways, sender fragment
counters, unchanged drops and no daemon action during traffic. The
expanded 18-case subset passed three times (72.92/73.85/74.49 s).
Ordinary tests, clippy and the strict source-link gate pass.
[Evidence and limits](phase6/P2_FRAGMENTATION_2026-10-30.md).

The maintainer updated today's Ubuntu targets to 6.8.0-148.148 and
7.0.0-42.42 and warned of imminent security revisions. The required
matrix must re-resolve targets before being called green; the existing
6.8.0-147 host evidence is historical for that stock-kernel target.

## QEMU and root sandbox checkpoint

H4/T4 passes with IPv6 disabled at boot and compiled out. All required
vanilla images and both published stock Ubuntu package sets are prepared;
full matrix execution and freshness comparison remain open.
[P3 bootstrap evidence](phase6/P3_BOOTSTRAP_2026-10-30.md).

P6 passed under real root systemd with every supplied mount restriction
active, without daemon-unit overrides. The refactored Incus contract also
passes and its container was deleted.
[P6 evidence](phase6/P6_ROOT_SANDBOX_2026-10-30.md).

The maintainer clarified that 6.8.0-148.148 is not ready. Published stock
metadata currently resolves to 6.8.0-147.147 and 7.0.0-42.42; upcoming
security updates must trigger target refresh and reruns before completion.
