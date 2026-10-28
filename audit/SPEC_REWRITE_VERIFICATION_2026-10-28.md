# Verification of the specification rewrite — 2026-10-28

Checks commit `dd411b8` ("docs(audit): Spec rewrite", the remediation of
[the Phase 1 review](PHASE1_DOCS_REVIEW_2026-10-28.md), recorded in
[PHASE1_REMEDIATION_2026-10-28.md](PHASE1_REMEDIATION_2026-10-28.md))
against the kernel sources at tags v6.8, v6.10, v6.11, v6.12, v6.13,
v7.0, v7.1, v7.2 and v7.3, and against live runs of the probes of
`tests/kernel/review.rs` on four kernels. Every changed specification
line of `docs/spec/*.md` was read; the kernel claims among them are
listed below with their verdict. Design decisions that make no kernel
claim are listed separately with what was checked about them.

## Live matrix

| Kernel | How | Result |
|---|---|---|
| 6.8.0-147-generic (Ubuntu) | host kernel, privileged container `rs-l2tpd-audit-vm:local` | 5 of 5 probes pass (re-run here, same as Codex's [kernel-6.8.log](evidence/kernel-6.8.log)) |
| 6.12.114-0-virt (Alpine 3.22) | TCG QEMU, Codex's run | 5 of 5 ([qemu-6.12.log](evidence/qemu-6.12.log)) |
| 6.18.59-0-virt (Alpine 3.24) | TCG QEMU, this review | 5 of 5 ([qemu-6.18.log](evidence/qemu-6.18.log)) |
| 7.3.0 upstream, `x86_64_defconfig` + L2TP built in, built in a disposable `debian:trixie-slim` container | TCG QEMU, this review | 4 of 5 with the committed probe: the foreign-namespace deletion is **not announced** ([qemu-7.3.log](evidence/qemu-7.3.log), [kernel-7.3-build.log](evidence/kernel-7.3-build.log)); 5 of 5 after the probe was taught the 7.3 behaviour (below) |

The probe binary with the sender-port filter of `../l2tp-rs` (commit
`f5e6a59`, unreleased, path-patched in a scratch copy of the repository)
also passes 5 of 5 on 6.8: kernel multicasts arrive with sender port 0,
so the filter keeps them.

## Kernel claims of the rewrite

| Where | Claim | Verdict |
|---|---|---|
| K18 | Session deletion is synchronous through v6.11 and queued to a workqueue from v6.12 | **Confirmed.** `l2tp_session_delete` unhashes and closes inline at v6.8 (1548–1560), v6.10 (1593–1605) and v6.11 (1648–1660); from v6.12 (1726–1733) it only sets `dead`, takes a reference and queues `session->del_work` (`l2tp_session_del_work`, 1737). Unchanged through v7.3. The pre-rewrite K18 ("asynchronous from 6.11") was wrong; the rewrite corrected it. |
| K16 | The name lookup (`L2TP_ATTR_IFNAME`) is namespace-wide, takes precedence over supplied identifiers, and returns a match, not a name-plus-ID check | **Confirmed** at v6.8 and v7.3: `l2tp_nl_session_get` takes the `IFNAME` branch first and never reads the IDs in it; `l2tp_session_get_by_ifname` walks the per-namespace v3 hash (v6.8–v6.10) or every tunnel of the namespace (v6.11+) and returns the first `strcmp` match. The probe reproduces two live sessions with the same stored name on all four kernels. |
| K16 (added here) | A session dump before 6.12 can silently skip an entry when another process deletes one between two batches | **Found during this review**, not in the rewrite: v6.8–v6.11 `l2tp_nl_cmd_session_dump` iterates `l2tp_session_get_nth(tunnel, si)` by position; v6.12+ resumes by key (`l2tp_session_get_next`). S22's new "dump must complete without loss" cannot detect this on older kernels. Added to K16 and to S22's accepted race. |
| K41 | "In v6.8 the notification helpers use `genlmsg_multicast_allns`, so identical IDs in another namespace can produce a matching event" | **True for v6.8–v7.2, false from v7.3.** `l2tp_tunnel_notify`/`l2tp_session_notify` call `genlmsg_multicast_allns` at v6.8, v6.10–v6.13, v7.0, v7.1 and v7.2 (lines 118/146 or 119/147) and `genlmsg_multicast_netns(family, tunnel->l2tp_net, …)` at v7.3 (119–120, 148–150). Reproduced: the foreign-namespace announcement arrives on 6.8, 6.12 and 6.18 and does not arrive on 7.3. The rewrite's text was incomplete, and the committed probe asserted the pre-7.3 behaviour unconditionally, so it fails on 7.3. Both corrected. |
| K41, E27 | Announcements precede deletion completion | **Confirmed** on every tag: `l2tp_nl_cmd_session_delete` calls `l2tp_session_notify(… L2TP_CMD_SESSION_DELETE)` before the pseudowire's `session_delete`; the tunnel command notifies before `l2tp_tunnel_delete`, which queues the work. |
| K5 (probe) | An unconnected L2TP/IP tunnel drops outbound frames | **Confirmed** by source (`tunnel->fd >= 0 && sk->sk_state != TCP_ESTABLISHED` → `NET_XMIT_DROP`, v6.8 `l2tp_core.c:1054`, v7.3 `:1273`) and by the probe on all four kernels. |
| K17, K37 (probe) | A duplicated descriptor keeps the tunnel and its sessions; the last close removes them | **Confirmed** on all four kernels. |
| K18, K19 (probe) | Identifier reuse after deletion | 32 delete/re-create cycles with zero `EEXIST` on all four kernels, including 7.3 where deletion is asynchronous. As the remediation says, this does not prove synchronous deletion; the source does. |
| S28 | The kernel reports a creation-time name, not a current device index or name | **Confirmed**: `L2TP_ATTR_IFNAME` is the only device attribute in `include/uapi/linux/l2tp.h` at v7.3; `session->ifname` is copied once after `register_netdev` (`l2tp_eth.c:307` v6.8, `:299` v7.3); l2tp_eth devices have no `rtnl_link_ops`, so rtnetlink cannot name their session either. |
| K11 | Cross-reference moved from K13 to K23 | **Correct**: K23 is the `IPV6_V6ONLY`-fixed-at-creation fact; K13 is port 546. |
| H7 | A VRF binding affects sending only; reception follows K15 | **Consistent** with K15, which this review did not re-run (verified on 2026-10-27). |
| P21 | `AF_UNIX` must be allowed for `NOTIFY_SOCKET` | **Confirmed** by Codex's user-systemd run ([systemd-notify.log](evidence/systemd-notify.log)): the store works with `AF_UNIX` in `RestrictAddressFamilies` and fails with `EAFNOSUPPORT` without it. |
| dependencies | `nix` needs the `uio` feature for `sendmsg` | **Confirmed**: nix 0.30.1 declares `sendmsg` inside `feature! { #![feature = "uio"] … }` (`src/sys/socket/mod.rs:647`). |
| dependencies | `netlink-packet-generic` and `netlink-packet-l2tp` are already in the lockfile | **Confirmed** (`Cargo.lock:258`, `:268`). |
| dependencies, `audit/upstream/` | `l2tp` 0.4.2 drops the recvmsg sender address before decoding | **Confirmed** against the published crate; the sibling checkout `../l2tp-rs` has since taken an equivalent fix (`f5e6a59`, "fix(events): skip messages not sent by the kernel", unreleased, version bumped to 0.4.3 in its manifest). The dependency table's statement about 0.4.2 stays true until that is published and pinned. |

## Design changes that make no kernel claim

Checked for internal consistency and against the sources they cite; no
contradiction found.

- C10/C11/C16, L4, O8, M13: static validation never queries the host;
  device kind, hardware address and VRF membership become runtime
  conditions. Consistent with Phase 1's tests
  (`host_dependent_conditions_are_not_parse_errors`).
- M17/S17/G3: a renamed tunnel entry whose kernel identity is unchanged
  keeps its sessions. Consistent with C14.
- S4/S22: creation names reserved for the session's lifetime; deletion
  by name only after a unique, fully matching dump record. The
  pre-6.12 dump caveat above is the one addition.
- E20/E27/K41: announcements advisory, verified by a local query; loss
  on the L2TP subscription triggers a local scan. With 7.3's
  namespace-local announcements the rule still holds; the only change is
  that one cause of a false match disappears there.
- A6/A14/P12/L6: persistent loss flags outside the queue, a signal
  collector that never blocks on queue capacity, five-second request
  deadlines. A14's five seconds agrees with E21.
- A7/M18/S9: per-registration incarnations. Needed because a device
  moved into the namespace keeps its index, which the 2026-10-27 audit
  showed live.
- T27/E1–E4/G5/G19: the configured bind device and the effective zone
  device are two dependencies. Relies on K27, unchanged and not re-run.
- V7/V13/E10/E11: resolver configuration incarnations invalidate answers
  and late results.
- V9/C16/K9/R45: **policy change to confirm with the maintainer.** The
  rewrite forbids a VRF as `bind_interface` for every resolver kind,
  including the address kind, which the previous text allowed (queries
  routed in the VRF's table, K28). The remediation calls this "the
  user's resolver constraint"; nothing in this repository's history
  records that decision, and the kernel does not require it. If it was
  not the maintainer's instruction, the address-kind VRF text should be
  restored; `iphost` 0.4.0 offers `BindDevice::Vrf`.
- P26: the `RS_L2TPD_REEXEC=1:<pid>` marker and the PID-file identity
  hand-over. Read by the binary, not the library, so L1 holds.
- P21/interface: `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET
  AF_INET6`.
- G6/G7/M4: cross-tunnel release-before-claim edges; hard mistakes
  retain values, tolerated endpoint mistakes may disconnect.

## Changes made by this review

- `docs/spec/kernel.md`: K41 states the 7.3 change with its source
  lines and the four live results; K16 gains the pre-6.12 dump-skip
  fact; the verified-behaviour paragraph records the matrix.
- `docs/spec/events.md` (E27) and `docs/spec/sessions.md` (S22): the
  two caveats above.
- `tests/kernel/review.rs`: the foreign-namespace probe expects the
  announcement before 7.3 and its absence from 7.3 on, and checks the
  local session either way; `tests/kernel/README.md` says so.
- `audit/evidence/qemu-6.18.log`, `qemu-7.3.log`,
  `kernel-7.3-build.log`: the new runs.

## Not checked

Everything the remediation lists as deferred to Phases 2–6 remains
deferred. Claims re-stated unchanged from the 2026-10-27 audits (K15,
K22–K29, K34) were not re-run. The Alpine kernels carry distribution
patches; the 7.3 kernel is upstream as released. No aarch64 run.
