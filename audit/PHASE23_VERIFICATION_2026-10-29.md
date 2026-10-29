# Phases 2 and 3 verification — 2026-10-29

Phases 2 and 3 are complete within the exits of [the plan](../docs/plan.md):
the kernel boundary and reconciler policy. The service and binary modules
are still placeholders. This record does not claim a working daemon,
100% path coverage, every release kernel, or completed process promises.

## Executed checks

All Cargo commands selected the locked dependencies. Normal and live test
executables used `--all-features --target x86_64-unknown-linux-musl`.
The fake conformance case runs fifteen shared operation bodies; its one
outer Rust test is not counted as fifteen separate test declarations.

| Check | Result | Evidence |
|---|---|---|
| Unit, rules/properties, fake conformance | 48 + 63 + 1 tests pass; physical tests deliberately ignored in this invocation | [unit.log](evidence/phase23/unit.log) |
| Determinism, `TEST_SEED=1` through `10` | Ten executions of each of those three targets; all 30 suite results pass | [determinism.log](evidence/phase23/determinism.log) |
| Host 6.8.0-147-generic, isolated privileged container | 9 production/resolver live unit tests, 11 kernel tests including shared bodies, 5 review probes pass | [kernel-6.8.log](evidence/phase23/kernel-6.8.log) |
| Alpine 6.12.114-0-virt, TCG QEMU | Same 9 + 11 + 5 tests pass; `REVIEW_RESULT=0` | [qemu-6.12.log](evidence/phase23/qemu-6.12.log) |
| Alpine 6.18.59-0-virt, TCG QEMU | Same 9 + 11 + 5 tests pass; `REVIEW_RESULT=0` | [qemu-6.18.log](evidence/phase23/qemu-6.18.log) |
| Upstream 7.3.0, TCG QEMU | Same 9 + 11 + 5 tests pass; `REVIEW_RESULT=0` | [qemu-7.3.log](evidence/phase23/qemu-7.3.log) |
| Actual user systemd manager + isolated kernel namespace | Manager retains the only tunnel socket reference after local close; processing-barrier withdrawal releases it; both halves pass | [manager](evidence/phase23/store-manager.log), [kernel](evidence/phase23/store-kernel.log) |
| Released iphost 0.4.1 regressions | 56 library tests pass with `--no-default-features --features custom,ra,dhcpv6`; source copied from the selected registry package into a disposable directory | [iphost.log](evidence/phase23/iphost.log), [package commit](evidence/phase23/iphost-vcs.json) |
| Clippy, all targets/features, `-D warnings` | Pass | [clippy.log](evidence/phase23/clippy.log) |
| Library without default features, musl | Pass | [no-default.log](evidence/phase23/no-default.log) |
| Library with only serde, musl | Pass | [serde.log](evidence/phase23/serde.log) |
| Rustdoc, all features, `RUSTDOCFLAGS=-D warnings` | Pass | [docs.log](evidence/phase23/docs.log) |
| Rule/source tools | Pass in their explicitly lenient Phase 6 mode; zero uncited kernel functions, including scoped/qualified functions | [maps.log](evidence/phase23/maps.log) |

Build selection and executable paths are in [build.log](evidence/phase23/build.log).
[Test executable hashes](evidence/phase23/test-sha256.txt) and
[kernel/config hashes](evidence/phase23/kernel-sha256.txt) identify the artifacts.
The 7.3 kernel was rebuilt with `CONFIG_NET_VRF=y` and
`CONFIG_IPV6_MULTIPLE_TABLES=y`; L2TP, dummy, veth and namespaces are built in.
The successful kernel build used a disposable Debian container for its
toolchain. No host packages or project interpreter dependencies were added.

## Required kernel evidence

The [per-K evidence map](../docs/kernel-evidence.md) names all 42 rows,
including removed K12, and separates shared operations, live-only host cases,
delegated requirements and source assertions. Source assertions are not live
test passes. K13, K14, K33, K38 and K40 remain outside the production
`kernel::linux` functions; the global source gate still reports them. No
unrelated citation was added to make that gate appear strict-green.

New physical cases force actual lifetime queue overflow, forge messages from
another port on both lifetime and monitor sockets, suppress a mutation's reply
while proving the mutation happened, and reuse an old index and creation name
within a lifetime generation. Foreign cookies of every length 0–8 are emitted
only by a raw test fixture, then read through the production parser.
Disconnected sessions are tested with emitted frames and counters, including
reception with correct, wrong and missing cookies.

The expanded QEMU conformance run exposed a real boundary discrepancy:
newer IP-session lookup can return the namespace-wide session despite a
different requested tunnel ID. The adapter now verifies the returned pair
and checks it before identifier deletion, sharing one absolute deadline.
The conformance case proves that a wrong-tunnel delete preserves the original.
Relevant source: v6.12 `net/l2tp/l2tp_core.c:315-321` and its v3 lookup,
called by `l2tp_nl_session_get`.

Removing the old fixture's fixed sleep also exposed a test assumption on 7.3:
session-record absence can precede the device-removal observation. The test
now waits for both with a hard timeout. The production reconciler treats those
as separate observations, and no source fact was changed to conceal a failure.

## Reconciler cases

All behavioral cases use the fake kernel, a seeded random source and its
virtual clock. Physical adapter tests are separately marked ignored and run
explicitly above. Test names below are in `tests/rules/` unless qualified.

| Contract | Explicit cases |
|---|---|
| M17 identity matrix, G3/G5/G6/G7/G18 | `properties/planner.rs`: 32 seeds × 64 changes per invocation, with creations, removals/recreations, family/peer/bind/name/address changes, entry renames and injected failures. Wait for actual convergence before asserting the identical-reload fixed point; readiness alone is not convergence. |
| M7 degradation rows | Connected creation; tolerated endpoint/MAC correction; missing bind/peer and occupied publication name; lost identity; ten-attempt identifier exclusion; independent host-defect retry. |
| T16 transient errno rows | `every_transient_connect_errno_retries_the_new_peer_in_place`: ENETUNREACH, EHOSTUNREACH, EACCES, EINVAL, EADDRNOTAVAIL, ENODEV, ENETDOWN. AF_INET fallback never attempts an IPv6 connect. Configuration prevention and wrong-operation kernel refusals have separate cases. |
| S23/M18/S24 | Staged proof loss with old index and temporary name reused; ambiguous and mismatching stored records refuse recovery; failed dump/deletion retain ownership state; confirmed absence precedes one restaging attempt. No rename or MAC operation reaches the replacement. |
| L12/T26 | Two waiters coalesce; success one nanosecond before 5 s opens fresh dual-stack sockets; failure, exact expiry, late success, still-v6-only read-back, read-back error and shutdown are covered. Registered socket/session identities never change because an answer arrives late. |
| L13/P14 policy | Exact inherited name, uncertain verification retry, changed-peer retirement, missing/failed barriers, local close at deadline, kernel absence before reuse, stale acknowledgements, capacity saturation, bounded failed shutdown. Matched adopted sessions keep manager names; unmatched/foreign-cookie sessions are deleted before ID reuse. |
| V15/V3 | Eight controlled calls block while interest is removed. One hundred replacement owners are created/dropped without starting a ninth system lookup. Configured work proceeds independently; actual lookup-thread count is checked. Permits return only after blocked calls finish. Latest results replace earlier ones; old jobs are removed. |
| V15 namespace/resources | Live workers inherit each owner's namespace. Removing the final watch releases current jobs, dispatcher, discovery threads and descriptors; counts are observed through test-only `/proc` fixtures. Workers retain only their admitted inputs. Only the non-blocking dispatcher joins at shutdown, never a libc worker. |
| V10 released adapter | Controlled raw RAs preserve omitted addresses, process withdrawal and no-RDNSS advertisements, and enforce the repository capacity. Released upstream regressions separately cover raw/netlink equivalence, interleaved routers, expiry/stale behavior and deterministic eviction. |
| V14 released adapter | Controlled DHCPv6 and RA lists plus DNS servers: SERVFAIL fallback, positive/negative primary finality, one-family fallback, recovery on the next lookup and both sources failing. The public adapter reports the enabled 63-second bound. Upstream transport/deadline cases run separately. |
| V7/V9/V11/V12 | Old-generation queued answers are ignored; bind/zone devices must be non-VRF and compatible. Unchanged discovery survives monitor loss. Invalid replacement stops queries. A missing default DUID uses RA temporarily, retries its address read at 30 s, then retains that identity. |
| M6/S11/S15/S28 | Acyclic name chains need no temporary rename; cross-tunnel cycles do. Session ID reuse waits for confirmed deletion. Adopted sessions are matched against accepted identities, not reconstructed as fictitious valid configurations. |
| M14/M15/E20/E27 | One-second retries and absolute polling deadline; other-family/unrelated events cannot postpone it; incomplete loss scans remain pending; foreign same-ID hints only queue verification; 2-second tunnel cleanup and store-withdrawal deadlines; slow conflict retry and explicit reload retry. |
| M16 | Name/index/source maps route relevant events. One hundred unrelated link/address pairs against one hundred tunnels issue no kernel-object queries. |

## Reproduction and remaining phase boundaries

[Kernel test instructions](../tests/kernel/README.md) give the container,
QEMU and two-half manager commands. Normal verification:

```sh
cargo test --locked --all-features --target x86_64-unknown-linux-musl
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --locked --lib --no-default-features --target x86_64-unknown-linux-musl
cargo build --locked --lib --no-default-features --features serde --target x86_64-unknown-linux-musl
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps --all-features
```

The determinism run repeats `--lib --test rules --test kernel-fake` with
`TEST_SEED=1` through `10`. The physical suites run their ignored tests with
one test thread, on each named kernel. QEMU uses TCG, q35, `-cpu max`, 768 MiB,
two vCPUs, a new initramfs and no host networking or writable host mounts.
The `init.sh` result marker is required in addition to each suite result.

Still required in the existing later phases: actual runtime callback/channel
concurrency (including E19/E26 and the L12/L13 event/control APIs), binary
crash/re-exec and descriptor protocol, whole-daemon timing/resource promises,
the full release/Ubuntu kernel matrix and disabled-IPv6 boots, strict rule and
source gates, and 100% combined line/branch coverage. The real-manager fixture
proves reference ownership and acknowledged withdrawal, not the future binary's
restart/shutdown implementation. No later phase is marked complete here.
