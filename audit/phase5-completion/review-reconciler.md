# Spec-conformance review: reconciler, runtime, services

Scope: `src/reconciler/*.rs`, `src/runtime.rs`, `src/service.rs`, `src/blocking.rs`,
`src/error.rs`, `src/lib.rs` at commit 0cf9252, against `docs/spec/`
(promises, model, tunnels, sessions, events, resolvers, library, process P16/P17)
and the README "Current contract gaps". Every finding below was read in the code;
findings 1–3 were additionally reproduced with throwaway tests on the fake kernel
(scratchpad `probe/tests/probe.rs`, not in the repo). No repo file was edited.

## Findings (ranked)

### 1. Medium-high — a tunnel re-creation discards the resolver answer in force (V6, V7, T16; G19)

`src/reconciler/tunnels.rs:169` (`remove_unwanted_tunnels` → `self.resolvers.forget(id)`).
A `peer_tunnel_id` change legitimately re-creates the tunnel (T23), but on the way the
watch and its `selected` address are forgotten. V7: "No other change discards answers";
V6: a working tunnel is never disconnected by a resolver outage. The README's historical
table lists exactly this ("A tunnel re-creation drops its resolver and its answer") as a
defect to fix.

Scenario (reproduced): `[tunnels.a] remote_addr="peer.example" ip_version="V4"`, answer
`192.0.2.2`, connected. Reload with `peer_tunnel_id = 21`. Kernel ops: close, wait,
socket/register — then **no connect**; `answers.watching()` shows a new lookup id and
the socket stays disconnected until the resolver answers again. If DNS is down at that
moment the tunnel is dark indefinitely although the previous answer was valid.

Fix shape: keep the `Watch` across a same-`tunnel_id` re-creation (only drop it in
`Resolvers::reload` when the key changes, or when the tunnel entry leaves the config);
`remove_unwanted_tunnels` can distinguish "entry removed" from "identity changed" by
checking whether the accepted config still has an entry with this `tunnel_id`.

Test gap: nothing covers answer retention across re-creation.

### 2. Medium — a session whose device moved out of the namespace blocks its own re-creation silently and forever (S21, T25, G13, M3)

`src/reconciler/sessions.rs:177-180` (the `reserved.values().any(|(_, old_sid)| *old_sid == sid)`
gate in `create_wanted_sessions`) together with `src/reconciler/tunnels.rs:185-195`
(`release_departed` releases a reservation only when `self.k.session(tid, sid)` is `None`).

After an observed removal with the kernel session still present (device moved to another
netns, S19), `delete_session` returns `Proof::Removed → true` without deleting (S21,
correct) and the record is forgotten, but its creation-name reservation stays until the
kernel session disappears — which, for a moved device, is when the tunnel is torn down.
Any re-creating change of that entry (cookie, `peer_session_id`, …) is then never
attempted: `incomplete = true` every second, no kernel operation, no report, `left_out()`
empty, `applied()` never true (the service never logs "reload completed").

S21 says the opposite: "A re-creation that the kernel then refuses is a conflict and is
handled as one" (10 attempts, one warning, left out, 30 s retry). Reproduced: 15 s after
the reload, ops are empty, `ready()` false (relevant for P26 re-exec adoption too),
`next_deadline` armed forever.

Fix shape: the sid gate should only apply to reservations whose session the daemon itself
asked the kernel to delete (K18 window), not to sessions it merely forgot (S21); or let
the creation proceed and count EEXIST through `conflict()`.

Test gap: `a_moved_session_is_forgotten_without_deleting_a_replacement` stops after the
removal; nothing exercises the re-creation path S21 describes.

### 3. Medium-low — the monitor-resync warning repeats every second while the dump fails (G13, O3, M13)

`src/reconciler/events.rs:355` logs `warn!` unconditionally at the top of `monitor_resync`,
and `src/reconciler/timers.rs:84-86` re-enters it on every tick while `monitor_pending`.
Reproduced: one `Notice::Loss` with 5 injected `dump_links` EIOs produced 6 warnings for one
episode. Retries must be silent (G13); route the message through `Report::begin` keyed on a
synthetic entry, or log only when `monitor_pending` was previously false.

### 4. Low — the session "create" episode is never ended (G13: "once when it ends")

`src/reconciler/sessions.rs:186-197`: a transient staging failure opens `(label, "create")`
via `report.begin`; a later successful `stage` only calls `conflict_over`, never
`report.end`/`forget_condition`. Consequences: no end-of-episode report, and a second
transient staging failure of the same entry (after an S27 re-creation, say) is logged at
debug only, because the episode is still "open". Tunnels do this right
(`tunnels.rs:221` `report.end(&label, "defect", …)`).

### 5. Low — E3 handling is lost on a transient query error

`src/reconciler/events.rs:214-219` → `observed_removal` (`sessions.rs:506`) returns
`false` on `Err(_)` without setting `verify`, `incomplete` or any deadline. A `LinkDel` of
an owned session device whose `session()` query fails once (EIO/ENOBUFS) is then not
followed up until some unrelated reconcile; the record stays `Proved` although `prove`
would now say `Removed`. The E27 path handles the same case correctly by leaving `verify`
set (events.rs:338-341). Set `verify = true` on `Err` here too.

### 6. Low — same-identifier re-creation leaves a one-second kernel query running forever (E27, G12)

Deleting and re-staging a session with the same ids (cookie change, S27) means the
kernel's announcement of *our own* deletion arrives after the new record exists:
`events.rs:119-126` sets `verify`, `verify_session` finds the session present and leaves
`verify` set, `timers.rs:72-80` + `arm_tick` then query `session()` every second for the
life of the entry. E27 allows pending verification but bounds it by "until absence or a
different incarnation is confirmed"; the code has no incarnation notion, so it never
confirms. Same for `tunnel_announced` after `Ok(Some)`. Cheap, but it is permanent
per-second polling, contrary to M15's "MUST NOT poll where it can be notified".

### 7. Low — per-event host-state caches are bounded by the host, not the configuration (G23, M16)

`src/reconciler/events.rs:151-159`: every `LinkNew` on the host inserts into `vrfs` /
`masters`, whatever the configuration. Needed to answer E4/E6 without a kernel query, but
G23 bounds memory by configuration plus monitor buffers. Consider retaining only
controllers that some tunnel's `bind_index` names, and masters of devices whose master is
such a VRF. Also `arm_tick` (`timers.rs:99-110`) and `handle` do an O(all entries) scan per
event rather than per concerned entry.

### 8. Low — `disconnect failed` is logged at error level on every retry (G13)

`src/reconciler/tunnels.rs:388, 415`: a failing `connect(AF_UNSPEC)` is reported with
`log::error!` on each 1-s retry. Realistically never fails on Linux, but it is the one
transient in this file not routed through `Report`.

### 9. Low — adoption aborts the whole tunnel on one unmatched-session deletion failure (M4)

`src/reconciler/tunnels.rs:57, 77`: `record_adopted` uses `?` on `scan_sessions` and on
each `delete_session` of an unmatched session; the `Err` makes `verify_inherited`
(`store.rs:204-213`) close the duplicate and retry the *entire* adoption next second,
while session records already inserted for matched sessions (lines 84-100) stay behind
without a tunnel record. Harmless on retry (they are overwritten), but a persistently
undeletable foreign session blocks adoption of the whole tunnel and every configured
session on it. Per-session failures should be recorded and retried individually.
(Fake-only side effect: `k.close(adopted.socket)` flips `tunnels[id]` to `None` in the
fake, so `tunnel_socket(id)` reads as mid-deletion between retries.)

### 10. Low — dead write in resync

`src/reconciler/events.rs:359`: `dump_addrs()` is fetched and discarded. One full address
dump per loss for nothing; either use it (to seed sources?) or drop the call.

### 11. Low (robustness note) — S27 re-creation converges only by accident

`events.rs:217, 335` call `create_wanted_sessions()` directly after forgetting a deleted
session, but that call never creates anything: the predecessor's creation-name reservation
still maps to the sid, so the gate in finding 2 sets `incomplete` and the 1-s reconcile does
the real work (reproduced: creation, hwaddr and publication all happen in the next
`reconcile_current`). The behaviour is correct, but if finding 2 is fixed by removing the
gate, these two call sites must schedule `reconcile_at` explicitly or the re-created
session will stay staged under its `rsl2tp-t` name with no hwaddr (`stage` does not call
`converge_session`).

## "Current contract gaps" (README, 2026-10-29) — status in this slice

| Contract | Code | Proof |
|---|---|---|
| S23, M18, S24 | Met: `Identity::Lost{staged}` → `restage` → `delete_verified` (unique stored-name match on tid/sid/peer/cookies) → confirmed absence → re-stage; no index/name re-identification anywhere (`sessions.rs:116-154, 512-519`). | `staged_loss_never_modifies_a_reused_index_and_name`, `mismatched_stored_records_cannot_authorize_staged_recovery`, `failed_staged_verification_and_deletion_preserve_the_record` (tests/rules/sessions.rs). Adequate. |
| L12, T26, P8, P25 | Met: provisional socket + read-back, request with id/deadline, no registration while pending (`tunnels.rs:242-275`), coalesced, late answers ignored, fallback on fail/timeout/still-v6only, shutdown cancels (`mod.rs:174-187, 251-254`, `timers.rs:44-52`). | `tunable_success_waits_and_opens_fresh_sockets_for_all_waiters`, `failed_expired_and_still_v6only_writes_use_the_fallback_once`, `shutdown_cancels_the_tunable_handshake`, `failed_readback_never_registers_a_socket_as_dual_stack`, runtime tests. "Racing sysctl writer" is covered only as outcome 2 (success answer, socket still v6-only); no test has the tunable flip back *between* reloads. |
| P14, P26, L13 | Met in the library: exact inherited names retained (`store.rs:79-82`), uncertain `adopt` retried (`store.rs:235-239`), definitive rejections retired with withdrawal before close (`store.rs:215-234, 244-301`), stale acks ignored, replacement storage blocked until the old name is retired (`blocks`, `store_socket`), bounded shutdown attempt with residual reported. P26 re-exec itself is in the binary, outside this slice. | tests/rules/store.rs (5 tests), runtime tests `adopted_names_are_verified_or_retired…`, `shutdown_keeps_withdrawal_and_kernel_deletion_windows_separate`, service tests. Adequate for the library half. |
| V3–V4, V15, A9, G23 | Met: process-wide `Workers` with separate `[system, configured]` budgets of 8, permits held until the call returns, one job/latest result per key, no replacement worker for a stuck call, dispatcher per owner (`workers.rs`). | `eight_blocked_calls_survive_cancellation_without_a_ninth_worker`, `obsolete_calls_keep_separate_budgets_and_latest_results`. Namespace-ownership test is `#[ignore]`. Adequate. |
| V10 | Delegated to `iphost` 0.4.1; daemon adapter unchanged. | Adapter test `released_ra_adapter_preserves_omitted_addresses…` is `#[ignore]` (needs CAP_NET_RAW netns), so the default run proves nothing here. |
| V14 | Met: `Ipv6ResolverConfig::new(..).with_failure_fallback(true)` (`resolvers.rs:630-631`). | `released_unified_adapter_enables_per_family_failure_fallback` is `#[ignore]`; only the `max_lookup_time == 63 s` assertion and fallback flag would be checked when run. |

## Weak or missing tests (lower severity, separate from the findings)

- **C14/M6/S11, "a removed session's name taken by a survivor converges in one reload"** — the
  README calls this a defect of the baseline; no test in tests/rules/sessions.rs exercises
  removal + name reuse. (Reading: it converges on the 1-s retry because the kernel frees the
  name asynchronously; a test should pin that.)
- **V7 across re-creation** — none (would have caught finding 1).
- **S21 re-creation after a move** — none (would have caught finding 2).
- **G13 log counting** — only `report.rs` unit-tests the `Report` type; no behavioural test
  counts warnings per episode (would have caught finding 3). The fake could expose a counting
  logger as it exposes `ops()`.
- `an_externally_deleted_session_is_created_again` (`/// spec: S27, S29, E27`) asserts only
  that the session index changed; it does not assert the re-created device reaches S1
  (configured name and hwaddr). It passes today for the accidental reason in finding 11.
- `one_failed_creation_does_not_block_an_independent_entry` (`/// spec: G6`) covers tunnels
  only; no session-level independence case (a failing `stage` in tunnel a vs a session in
  tunnel b, or the adoption case in finding 9).
- T25 "eventual creation reported" — `a_conflict_leaves_the_tunnel_out_after_ten_attempts`
  checks creation and `left_out()` but not that the info message is emitted.
- `shutdown_closes_the_sockets` (`/// spec: P16, T8`) has no session, so it does not check
  the sessions-before-tunnel order at the reconciler level; that order is only checked
  through `tests/service.rs::blocking_converges_and_drop_removes_children_before_parents`.

## Checked and found clean

- **G3/G4 identity**: tunnels and sessions matched by kernel identity (`tunnel_wanted`,
  `session_wanted`); config renames, `remote_addr`/`ip_version`/`resolver_name`/
  `bind_interface`, `interface_name`, `interface_hwaddr` all applied in place; only
  identity-matrix rows re-create (removal first, creation after the kernel releases). Hwaddr
  applied only when `set_hwaddr` succeeds, `EBUSY` → `Deferred`, applied on the device's own
  down event; the daemon never changes admin state; manager renames/MACs become `Overridden`
  and are not fought; removing `interface_hwaddr` restores the creation address under the
  same deferral. Property test `reload_sequences_converge_without_unjustified_identity_changes`
  guards this.
- **G8/P7 readiness**: `ready()` counts staged sessions, disconnected tunnels, deferred MACs,
  unresolved names, absent bind devices; waits only for conflicts (10 attempts), the 5-s
  tunable handshake and kernel inability, as P8 allows.
- **G6/M4**: `reconcile_current` phases iterate every entry and handle errors per entry; the
  only `?` that crosses entries is finding 9. Tunable handshake delays only new tunnels;
  shutdown drops pending handshake requests.
- **G5/T15/T17**: every target change goes through `reconnect` (disconnect first); an
  unreachable new literal or answer leaves the socket disconnected with the new peer pending;
  a changed/removed host name or resolver config disconnects at once (`Resolvers::reload`).
- **T21/T28/K22**: `reconnect` disconnects whenever the socket is connected, bound or stale,
  then binds the index the name resolves to *now*, then connects; source read back after the
  connect and an unspecified source is treated as a failed connect (T20). The fake refuses a
  bind on a bound socket with `EPERM` (`net_raw = false`), so every rules test implicitly
  guards K22; the zone-binding rule of T27 is modelled and tested.
- **P16/P17/G20**: `shutdown` deletes provable sessions, then closes sockets (withdrawing
  stored ones first), waits up to 2 s per departing tunnel via `shutdown_deletions`, reports
  each failure and still continues; `Runtime::shutdown` bounds the whole thing at 4 s and
  returns `Err` so the exit code reflects failure. Blocking `Drop` performs the same.
- **G12/M16**: all event handlers resolve by `Index` lookups; unrelated link/address events
  issue no kernel query (`unrelated_events_query_no_kernel_objects_even_with_many_entries`),
  except the caches in finding 7.
- **S4/S6/S7**: `rsl2tp-t` + 6 hex digits from `Kernel::random`, checked against devices,
  stored creation names and reservations; 8 draws then a transient failure; a taken configured
  name keeps the session under its staging name and retries every second.
- **M6 ordering**: deletions → tunnel removals → release → creations → in-place updates →
  swaps via `rsl2tp-r` → final renames.
- **T25**: 10 attempts a second apart, warning once when left out, 30-s retry and every
  reload (`conflict.next = now`), info on eventual creation, counter reset on identity change.
- **L1**: no `std::fs`/`std::env`/stdio in the library slice (only `src/bin` and
  `#[cfg(test)]` code); `#![deny(unsafe_code)]`.
- **G22**: nothing in the reconciler depends on cookies, resolvers or a `host` table being
  present; defaults (`fix_bindv6only` on, dual-stack socket, IPv4 peers mapped, AF_INET
  fallback probed per creation) keep a 0.1.5 configuration connecting as before.
- **L5–L8 service contract**: converge ignores reloads (generation fence), run converges
  first, superseded reload results discarded, blocked callbacks never hold shutdown, panics
  surface after cleanup, Control shutdown is a persistent flag outside the bounded queue.
