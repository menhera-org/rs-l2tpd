# Phase 1 review remediation — 2026-10-28

This records changes against [the review](PHASE1_DOCS_REVIEW_2026-10-28.md).
The implementation/specification contradictions identified there are corrected.
Existing Phase 1 behavior agrees with the corrected contracts; its two new
regressions pass. The rule-map code now associates citations with test
declarations rather than accepting arbitrary production comments.

This is **not completion of Phases 2–5**. Their kernel, reconciler, runtime and
binary modules are still skeletons. Correcting their contracts and naming
acceptance cases does not prove those future implementations. No unrelated
implementation changes were reverted or overwritten.

## Disposition of the findings

| # | Correction | Evidence and remaining implementation gate |
|---|---|---|
| 1 | C16, T27, L4 and O8 distinguish static validation from runtime device kind/MAC/membership checks; V12 retains the unified resolver's RA fallback | New `host_dependent_conditions_are_not_parse_errors` passes. Phase 3 must exercise absent/replaced devices and invalid membership. |
| 2 | C10/C11 include ignored valid DHCPv6 fields; malformed irrelevant fields remain hard errors | Existing identity/DUID tolerance tests and new `irrelevant_dhcpv6_fields_still_validate_their_values` pass. |
| 3 | M17/S17/G3 preserve sessions when an entry rename retains the referenced tunnel's kernel identity | Existing `kernel_identities` regression passes. Planner execution remains Phase 3. |
| 4 | S4 reserves creation names for the session lifetime; S22 requires a complete, unique, matching stored-name record before name deletion and explicitly accepts the residual race | Duplicate stored names and ambiguous raw deletion reproduced on both kernels. Phase 3 must refuse ambiguity/mismatch; the kernel primitive itself is not an atomic conditional delete. |
| 5 | K41/E27 treat events as hints and verify local objects before any recovery | Foreign-namespace deletion with colliding IDs reproduced on both kernels while the local session remains. A pre-deletion announcement needs coalesced follow-up verification; no live object is deleted on the hint alone. |
| 6 | The architecture selects a bounded raw generic-netlink path, with persistent loss state outside the queue | Default upstream unbounded queues are not called contract violations. Phase 2 must test finite buffers and event floods, including foreign namespaces; forwarding from an unbounded iterator is expressly insufficient. |
| 7 | A minimal upstream sender-port check and regression are supplied in [upstream/](upstream/README.md) | Regression fails before the filter; all 128 upstream library tests pass after it. The transport preserves SocketAddr but does not filter it. Patch prepared in an isolated clone, not applied to the sibling checkout or published. |
| 8 | E20 specifies a local scan of every configured tunnel/session after L2TP loss, including adopted/unmanageable sessions; failed scans stay pending | Phase 2–3 must test dropped deletion events and loss during resync. No periodic full reconcile is introduced for converged state. |
| 9 | A7/M18/S9 and the interface sketch carry generation plus registration incarnation; capture is armed before creation | Phase 2 must test remove/reuse of an index within one generation and capture/reply loss. A live-index set alone is insufficient. |
| 10 | Lifetime/request deadlines consistently use five seconds, separate from the tunnel-deletion retry window | Documentation corrected; exact fake-clock boundary tests belong to Phase 2. |
| 11 | The raw request adapter has one in-flight request, an absolute deadline, transport reopening and uncertain-mutation recovery | Phase 2 must test a missing ACK, multipart timeout, family lookup timeout and late mutation. Existing upstream blocking-call defaults remain unchanged. No abandoned-worker strategy is permitted. |
| 12 | The reconciler's idle wait selects receive and shutdown on its own runtime; signal collection coalesces requests without blocking on queue space | Phase 4–5 must test idle shutdown, full queue, running reload and check/wait races. The old AtomicBool/Notify plus blocking_recv mismatch is removed. |
| 13 | S28 preserves every matching adopted session as unmanageable, without guessing its current interface name from a stored name | The stored/current name distinction is live-tested. Phase 3–5 must preserve renamed and mid-staging adopted devices; the latter may remain unpublished and must be reported. |
| 14 | T27/E1–E4/G5 track both configured bind and effective zone dependencies and their membership | Phase 3 must test zone-only peers, VRF membership changes, replacement and rename of either dependency. |
| 15 | Planner, M4 and G6 preserve cross-tunnel name/ID release dependencies; unrelated work still proceeds | Live reuse probe exercises eventual release. Phase 3 must test cross-tunnel swaps and delayed release in the fake. |
| 16 | P21/interface explicitly allow AF_UNIX for the notify socket | Actual user-systemd restriction test stores and removes a descriptor with AF_UNIX, and fails with EAFNOSUPPORT without it. Full future unit testing remains Phase 5. |
| 17 | P26 specifies a versioned re-exec marker independent of LISTEN variables, including zero descriptors, original arguments/path, foreground mode and PID-file inode authority | Phase 5 must test empty-config re-exec, fresh descriptor-store startup, invalid marker and replaced PID file. |
| 18 | V7/V13/E10/E11 invalidate answers and outstanding results by resolver configuration incarnation | Phase 3 must test a late answer from the pre-reload resolver. |
| 19 | G7 now states the actual C12 distinction: hard errors retain values; tolerated peerless corrections may disconnect while preserving objects | Existing tolerated reload tests pass. No stronger traffic-preservation promise is made. |
| 20 | S15 cookie changes follow S4–S7 staging before publication | Phase 3 must test that the final name is not exposed before address handling. |
| 21 | Phase exits explicitly defer file/process/service cases to their owning phases; conformance fixtures supply test-only host controls | The new live probes are labeled assumption tests, not tests of an unimplemented Kernel trait or reconciler. The Phase 6 matrix/coverage gates remain future work. |
| 22 | Rule-map scanner records path, line and function only for cited test declarations; docs distinguish lexical traceability, execution and per-clause coverage | Scanner regression passes and excludes production/helper comments. Feature selection, ignored suites and semantic coverage must still be checked separately. |

All eight smaller corrections are addressed: historical baseline wording,
Cargo warning command syntax, duplicate TOML dependency key, K11 reference,
H7 output-only VRF semantics, dependency/version status, per-installation unit
paths, and known shipped installer-unit content for upgrade detection.

Additional source-confirmed correction: K18's upstream boundary is **v6.12**,
not v6.11. v6.11 calls session cleanup synchronously; v6.12 queues work.
Distribution backports make release-number-only branching unsafe.

The user's resolver constraint is explicit throughout C16/V9 and the dependency
plan: **no resolver kind uses a VRF device as its bind interface or explicit
server zone**. Real member links are allowed. Static validation cannot classify
a host device; runtime validation must reject a VRF before using that operation,
and repeat validation on replacement and relevant events. No `BindDevice::Vrf`
is selected by the daemon.

## Tests actually run

| Check | Result | Evidence |
|---|---|---|
| All-feature musl unit/tool suite | 35 configuration tests, 3 rule-map tests and 1 source-link test pass; 5 live tests explicitly ignored here and run separately below | [unit.log](evidence/unit.log) |
| Format; all-target/all-feature Clippy with warnings denied | Pass | [fmt.log](evidence/fmt.log), [clippy.log](evidence/clippy.log) |
| Musl library builds without default features and with serde only | Pass | [no-default.log](evidence/no-default.log), [serde.log](evidence/serde.log) |
| All-feature rustdoc with warnings denied | Pass | [docs.log](evidence/docs.log) |
| Live Docker namespace, host Linux 6.8.0-147-generic | All 5 probes pass | [kernel-6.8.log](evidence/kernel-6.8.log), [host.txt](evidence/host.txt) |
| QEMU TCG, Alpine Linux 6.12.114-0-virt, no KVM or elevated host privileges | All 5 probes pass; guest reports REVIEW_RESULT=0 | [qemu-6.12.log](evidence/qemu-6.12.log), [image hashes](evidence/qemu-image-sha256.txt) |
| Real systemd address-family filter and descriptor-store add/remove | Positive case passes with stored count 1 then 0; negative case fails as expected without AF_UNIX | [systemd-notify.log](evidence/systemd-notify.log) |
| Upstream sender regression without the patch | Fails as expected | [upstream-regression-before.log](evidence/upstream-regression-before.log) |
| Isolated upstream clone with the patch | 128 library tests pass; all-target/all-feature Clippy passes | [upstream-unit.log](evidence/upstream-unit.log), [upstream-clippy.log](evidence/upstream-clippy.log) |

The lenient rule map reports **38 of 329 active rules linked to test
declarations; 291 have no citation** ([rulemap.log](evidence/rulemap.log)).
The source-link and rule-map Phase 6 completeness gates are not enabled.
Passing their current tool tests does not mean the rewrite meets all rules.

The five probes exercise:
1. two renamed sessions retaining the same creation name, and the raw name lookup selecting only one;
2. a foreign namespace's delete notification while matching local IDs remain intact;
3. 32 delete/re-create cycles with bounded retry on EEXIST;
4. an unconnected tunnel/session surviving a duplicated descriptor and disappearing after the final close;
5. an actual outbound Ethernet attempt counted as dropped while the tunnel is unconnected.

Both reuse runs observed zero EEXIST retries. This proves successful repeated
reuse, **not synchronous kernel deletion**. The source comparison establishes
that distinction. The probes do not substitute for adversarial scheduling in
the future fake kernel.

Commands and fixtures are in [tests/kernel/README.md](../tests/kernel/README.md).
Tests used isolated Docker namespaces and a disposable QEMU root; no sudo,
setuid privilege acquisition, host network mutation or upstream checkout edit.

## Source evidence

Pinned upstream files consulted for these corrections:

- [Linux v6.8 L2TP netlink](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/l2tp/l2tp_netlink.c): IFNAME lookup takes precedence over IDs; multicast notifications cross namespaces and precede deletion.
- [Linux v6.8 core](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/l2tp/l2tp_core.c): stored-name lookup returns a matching session; tunnel cleanup is queued.
- [Linux v6.11 core](https://raw.githubusercontent.com/torvalds/linux/v6.11/net/l2tp/l2tp_core.c) and [v6.12 core](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/l2tp/l2tp_core.c): the session workqueue transition; corresponding netlink files also checked.
- [Linux v7.3 core](https://raw.githubusercontent.com/torvalds/linux/v7.3/net/l2tp/l2tp_core.c): retained asynchronous session deletion and unconnected transmit guard. This was source inspection, not a v7.3 VM run.
- [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#RestrictAddressFamilies=) and [sd_notify](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html): address-family restriction and Unix-datagram notification transport.
- Cached published `l2tp` 0.4.2 `event.rs`, and `netlink-proto` 0.13.0 connection/protocol source: received sender metadata is preserved until the event stream discards it.

Downloaded kernel files are identified by [SHA-256](evidence/kernel-source-sha256.txt).
These upstream tags are not presented as the exact source of the Ubuntu or
Alpine distribution binaries; runtime results record those builds separately.

## Limits before continuing

The code change in this repository is the rule-map correction plus focused
regressions/fixtures. No existing Phase 1 production bug required an artificial
behavior change to make contradictory prose pass. The upstream sender fix is
a tested patch artifact, not a published dependency update.

The complete kernel release matrix, 100% path coverage, future reconciler
safety policies, runtime shutdown implementation, re-exec protocol, full system
unit and packaging upgrade execution have **not** been tested because those
implementations do not yet exist here. They remain explicit phase exit gates.

Residual risks are documented rather than hidden: S22's verification/delete
race against a concurrent foreign writer; lookup/bind replacement races;
adopted sessions cannot regain device-management authority; an advisory
same-ID foreign event can leave a bounded verification task pending because
the existing kernel API cannot distinguish it from queued local deletion.
