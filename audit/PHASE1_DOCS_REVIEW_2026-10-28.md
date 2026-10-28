# Documentation re-review before Phase 2 — 2026-10-28

**Follow-up:** [Remediation and executed tests](PHASE1_REMEDIATION_2026-10-28.md)
record the subsequent fixes. This report below preserves the original findings.

**What this change does:** This report reviews the implementation plan against the authoritative specification and checks the specification for internal contradictions. It identifies decisions that must be settled before implementing the kernel boundary and the later runtime; it changes no implementation or specification file.

| Review detail | Value |
|---|---|
| Snapshot | `691adaef3e4b2e1ff8768a6d75ff6133370097ab`, including the existing uncommitted Phase 1 status in `docs/plan.md` |
| Scope | All 7 `docs/*.md` implementation pages and all 16 `docs/spec/*.md` specification pages |
| Supporting inspection | Existing audit decisions; selected Phase 1 configuration types/tests and CI; local `../l2tp-rs` 0.4.2 source; Linux v6.8 L2TP source; official systemd documentation |
| Expected conditions | Early boot, absent/replaced devices, notification loss, namespace isolation, hundreds of sessions, reloads, and descriptor-preserving restarts, as required by the specification |
| Output | This file only. Existing changes in `Cargo.toml`, `docs/plan.md`, and `src/config/` were left untouched |
| Result | 16 must-fix findings, 6 should-fix findings, and a short list of smaller documentation corrections |

The disconnected-socket design is not challenged by this review. The main risks are ownership after notification loss, the L2TP event boundary, shutdown responsiveness, and contradictory configuration and adoption rules. Previous reports remain historical evidence; this report does not treat their conclusions as proof that the current text is consistent.

## Must fix

### 1. Configuration validation requires host state that the configuration layer must not read

**Where:** `docs/spec/configuration.md:98–108` (C16), `docs/spec/tunnels.md:267–286` (T27), `docs/spec/resolvers.md:187–220` (V12), `docs/spec/library.md:41–45` (L4), `docs/spec/observability.md:65–78` (O8), `docs/plan.md:99–137`. **Before:** completing Phase 1 and designing Phase 2 queries.

- **What this is:** Phase 1 validates configuration without a kernel, and `--check` makes no kernel request. C16 and T27 nevertheless classify a device's kind, Ethernet address, and VRF membership as configuration mistakes.
- **Problem:** A resolver using `method = "ipv6"` and default link-layer identity on an `ARPHRD_NONE` device must be left out under C16, but V12 requires its RA half to work; a device absent at boot cannot be classified at all. Likewise, `fe80::1%wan0` with `bind_interface = "vrf-wan"` cannot be accepted or rejected for membership by a pure parser, and the membership can change after validation.
- **Fix:** Define `Config` validity as the static field/reference rules; handle device availability, kind, address and membership as explicit runtime conditions with retries and named fallbacks. Reconcile C16 with V12's RA-only fallback, and specify the runtime outcome for a zone outside its configured VRF instead of calling it a load-time error.
- **If we skip it:** Implementers must either violate check mode/library boundaries or silently omit hard-mistake checks; early-boot configurations can be dropped permanently for temporary host state.

The Phase 1 status already raises part of this issue. The C16/V12 disagreement about the unified resolver is an additional contradiction, not just a missing implementation choice.

### 2. The exhaustive tolerance table omits the resolver-field tolerance

**Where:** `docs/spec/configuration.md:101–108,125–142` (C16, C10, C11). **Before:** closing Phase 1.

- **What this is:** C10 defines which mistakes are corrected and which remove an entry; C11 explicitly limits tolerated mistakes to three rows.
- **Problem:** With `method = "ra"`, `bind_interface = "wan0"`, and `dhcpv6_identity = "anonymous"`, C16 says to ignore the identity with a warning, while C10's “any other mistake” row says to leave out the resolver and its tunnels. The corresponding treatment of a valid `dhcpv6_duid` outside a DHCPv6 method is not stated, although Phase 1 currently treats it as ignored too.
- **Fix:** Add the ignored resolver-field case to C10 and C11, and state whether `dhcpv6_duid` follows it. Preserve the distinction between a valid irrelevant value and the unknown/invalid values that C16 explicitly makes hard errors.
- **If we skip it:** Two implementations can produce different accepted configurations from the same document while each follows a specification table.

### 3. Renaming a tunnel entry both preserves and re-creates its sessions

**Where:** `docs/spec/model.md:139–155` (M17), `docs/spec/sessions.md:163–175` (S17), `docs/spec/configuration.md:181–195` (C14), `docs/spec/promises.md:17` (G3). **Before:** Phase 3 identity matching.

- **What this is:** C14 matches objects by immutable kernel fields rather than configuration names.
- **Problem:** Rename tunnel entry `a` to `b`, retain its identifiers, and update a session's `tunnel_name` from `a` to `b`: C14 and S17's identity definition preserve the session, but S17's first list and M17's `tunnel_name` row require re-creation. G3 also still lists an entry rename as a cause of identity loss, contrary to the explicit rename row of M17.
- **Fix:** Replace “`tunnel_name` changed” with “the referenced tunnel's kernel identity changed” and remove the stale rename exception from G3. Keep the Phase 1 identity test that already covers a tunnel/session entry rename as the intended interpretation.
- **If we skip it:** A harmless configuration rename can destroy session addresses, routes and children in Phase 3.

### 4. Deletion by creation-time name is not the conditional identity check S22 claims

**Where:** `docs/spec/sessions.md:30–43,227–241` (S4, S22), `docs/spec/kernel.md` (K16), `docs/architecture.md:99`. **Before:** Phase 2 deletion API and fake-kernel semantics.

- **What this is:** S22 uses the kernel's stored creation-time name to delete a session after losing its device proof.
- **Problem:** Session A is created as `rsl2tp-t123456` and published as `a`; session B can later draw the now-free temporary device name and publish as `b`. Both retain the same stored name, and deletion by that name can select B even when A was intended: the IDs need not match, contrary to S22's stated residual risk.
- **Fix:** Reserve creation-time names for the full lifetime of owned sessions, including after publication, and specify how deletion refuses ambiguous or mismatching stored-name records. Document that name lookup alone does not atomically check the expected IDs; any additional query followed by deletion retains a race under M10 and needs an explicit accepted limit.
- **If we skip it:** Ordinary temporary-name reuse can delete the wrong session; it does not require the deliberate imitation described in S22.

Source check: Linux v6.8 selects the IFNAME lookup branch before the ID branch, and the core lookup returns the first namespace session with that stored name. See [`l2tp_nl_session_get`](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/l2tp/l2tp_netlink.c) and [`l2tp_session_get_by_ifname`](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/l2tp/l2tp_core.c). This is a source-derived failure case, not a live reproduction in this review.

### 5. L2TP notifications cannot be treated as proof that a local object was deleted

**Where:** `docs/spec/events.md:117–126` (E27), `docs/spec/sessions.md:277–285` (S29), `docs/spec/kernel.md` (K41), `docs/dependencies.md:71`. **Before:** Phase 2 event decoding.

- **What this is:** E27 interprets a deletion announcement matched by identifiers as a deletion of the daemon's configured object.
- **Problem:** On Linux v6.8, another namespace can delete tunnel/session IDs equal to this daemon's live IDs, and this daemon receives the announcement too. The sender is still the kernel, so E22 does not distinguish it; following E27 can falsely report a local tunnel deleted or start replacement/conflict handling for a live session.
- **Fix:** Make K41/E27 explicitly advisory: a matching event triggers a local query, and only verified local state changes records or schedules recovery. Cover foreign-namespace events, delayed events for a previous incarnation, and local deletion still in progress.
- **If we skip it:** Independent containers with the same valid IDs interfere with one another's reconciliation.

Both notification helpers use `genlmsg_multicast_allns` in [Linux v6.8 L2TP netlink](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/l2tp/l2tp_netlink.c). The local `../l2tp-rs/src/event.rs:15–29` and `handle.rs:741–763` already warn about this and say to query local state.

### 6. The chosen L2TP event path violates the bounded-memory promise

**Where:** `docs/dependencies.md:71`, `docs/architecture.md:235–239,319–324`, `docs/spec/architecture.md:81–96` (A6), `docs/spec/promises.md:44` (G23). **Before:** accepting the Phase 2 upstream boundary as complete.

- **What this is:** The plan deliberately accepts an unbounded upstream event queue because it assumes events arrive at an operator's typing speed.
- **Problem:** An automated L2TP user can create and delete objects faster than the consumer handles them, including from another namespace. The local upstream implementation uses both an unbounded async receiver and an unbounded `std::sync::mpsc` channel; a later `try_send` into the daemon's bounded queue does not bound either earlier queue.
- **Fix:** Require a bounded event path with an observable loss marker all the way from the netlink reader, either upstream or through the daemon's existing raw-netlink approach. Remove the typing-speed justification; the stream also decodes creation and modification events, not only deletions.
- **If we skip it:** Memory grows with event backlog, contrary to G23, and the fake's finite-buffer tests cannot establish the real path's resource guarantee.

Supporting source: `../l2tp-rs/src/event.rs:8,58–62,118–149` and `../l2tp-rs/src/blocking.rs:406–435`. These were read from the local 0.4.2 tree; published-package equivalence was not independently checked.

### 7. The selected upstream event API loses the sender address needed by E22

**Where:** `docs/spec/events.md:203–208` (E22), `docs/plan.md:163–169`, `docs/architecture.md:319–324`, `docs/dependencies.md:71`. **Before:** Phase 2 event subscription API.

- **What this is:** Every notification must be accepted only when its netlink sender port is zero.
- **Problem:** The local `Events::poll_next` receives `(message, address)` but discards the address before decoding, and the blocking `EventIter` exposes only the decoded event. The daemon cannot apply the specified sender check through that API; checking a message header is not a substitute for the received sender address.
- **Fix:** Require upstream to validate sender port zero before decoding, or preserve the sender metadata through the subscription boundary. Add a conformance case for a non-kernel sender, and record this requirement beside the event-queue requirement.
- **If we skip it:** The Phase 2 implementation cannot meet E22 using the dependency path the docs prescribe.

Supporting source: `../l2tp-rs/src/event.rs:89–104` discards the `SocketAddr`; `blocking.rs:461–466` returns only the event result. This is a source-level API mismatch, not a claim that an unprivileged process can bypass K30.

### 8. Lost L2TP deletion events have no specified recovery scan

**Where:** `docs/spec/events.md:171–201` (E20–E21), `docs/spec/sessions.md:264–285` (S27–S29), `docs/dependencies.md:71`, `docs/spec/model.md:64–68` (M5). **Before:** Phase 2 loss events and Phase 3 recovery.

- **What this is:** The dependency page says a lost deletion is covered by a session query at the next reconcile; the architecture forwards L2TP queue overflow as a resync.
- **Problem:** For an adopted or previously unmanageable session, lose its L2TP deletion event while there is no usable device proof. E20's resync checks bindings, connected tunnels and deferred hardware addresses, but specifies no session-existence scan; a fully converged daemon also has no periodic full reconcile to supply the assumed “next reconcile.”
- **Fix:** Define a separate L2TP-loss recovery action that queries configured sessions on owned tunnels and schedules missing ones for creation, with a persistent resync marker that survives a full queue. Query failures must leave recovery pending; this must not restore a lost device ownership proof.
- **If we skip it:** A configured session deleted during event loss can remain absent indefinitely.

### 9. The lifetime boundary does not expose the registration proof the reconciler needs

**Where:** `docs/architecture.md:95,110–119,160–168,240–245,317–319`, `docs/spec/sessions.md:71–94` (S8–S9), `docs/spec/architecture.md:98–109` (A7). **Before:** freezing the Phase 2 trait.

- **What this is:** S8 captures a session's index from its registration broadcast, matched by the temporary name; subsequent changes must prove that same registration is still alive.
- **Problem:** The sketch returns only `()` from `create_session`, and `Lifetime` offers only `lookup(index)` and a generation, with no path to obtain the original index/proof. A live-index set alone also cannot distinguish an old removed device from a device moved in under the same index within the same generation, the case S19 explicitly permits.
- **Fix:** Specify registration capture on the dedicated lifetime task before issuing creation, and return or retrieve the captured index together with a proof tied to that registration. Define how observing removal permanently revokes that proof even if the index becomes live again; do not repair the omission with a lookup by the final name or the upstream handle's fallback.
- **If we skip it:** Phase 3 must bypass the advertised kernel boundary or use an identity proof weaker than S8/S9.

### 10. The implementation design shortens the identity-loss timeout from five seconds to two

**Where:** `docs/architecture.md:240–245` versus `docs/spec/events.md:189–201` (E21); previous decision W1 in `audit/SPEC_REVIEW_2026-10-28.md`. **Before:** Phase 2 lifetime implementation.

- **What this is:** A lookup timeout ends the lifetime generation and permanently makes published devices unmanageable.
- **Problem:** A valid reply arriving after three seconds succeeds under E21, but the architecture's two-second deadline has already ended every proof in the generation.
- **Fix:** Use the normative five seconds here and in the fake's deadline tests. Keep this separate from the two-second tunnel-deletion wait, which serves a different purpose.
- **If we skip it:** Loaded hosts suffer avoidable permanent identity loss and the conformance suite tests the wrong timeout.

### 11. Generic-netlink calls may block the entire reconciler indefinitely

**Where:** `docs/architecture.md:121–137,319–324`, `docs/spec/architecture.md:153–154` (A14), `docs/spec/events.md:189–201` (E21). **Before:** Phase 2 request adapter.

- **What this is:** The design puts synchronous kernel calls on the sole reconciler thread and explicitly exempts the blocking L2TP handle from a timeout.
- **Problem:** If a request never completes, the upstream blocking handle waits in `rx.recv()` without a deadline. The fact that the kernel normally answers synchronously does not bound a missing reply, so no later entry, timer, restart or shutdown can run on that thread.
- **Fix:** Require finite, recoverable request completion at the adapter/upstream boundary and define the ownership reconciliation after a timed-out mutation. Do not solve it by abandoning an unbounded number of blocked threads; align shutdown's promised bound with the longest permitted in-flight operation.
- **If we skip it:** A single lost/stuck operation defeats failure containment and can hang shutdown forever.

Supporting source: `../l2tp-rs/src/blocking.rs:172–187`; the five-second `SO_RCVTIMEO` on the daemon's separate rtnetlink socket does not bound this wait.

### 12. The shutdown notification cannot wake the documented blocking receive

**Where:** `docs/architecture.md:231–250`, `docs/spec/process.md:101–111` (P12), `docs/plan.md:271–275`, `docs/spec/library.md:63–72` (L6). **Before:** Phase 4 loop and Phase 5 signals.

- **What this is:** Shutdown uses a persistent flag plus `Notify`; the reconciler reads an mpsc channel with `blocking_recv`.
- **Problem:** With an empty queue and no armed timer, setting the flag and notifying does not wake `blocking_recv`; the later claim that every wait uses `select!` describes a different mechanism. Separately, a single `sigwait` thread blocked while enqueueing a reload cannot observe a later SIGTERM merely because shutdown has its own flag.
- **Fix:** Specify one receive/wakeup mechanism that actually waits on both events and shutdown, and make the signal collector keep consuming shutdown signals while a reload is pending for queue space. Exercise an idle daemon and a full reload queue, not only a busy event loop.
- **If we skip it:** Shutdown can wait indefinitely despite the separate shutdown flag.

### 13. Adoption requires a current session-device name that its inputs cannot establish

**Where:** `docs/spec/sessions.md:289–304` (S28), `docs/spec/kernel.md` (K16), `docs/spec/process.md:129–164,166–210` (P14/P26), `docs/spec/model.md:155` (M17). **Before:** Phase 2 adoption inputs and Phase 4/5 restart.

- **What this is:** S28 keeps an identity-matching session only when its device currently has the configured name; otherwise it deletes and re-creates it.
- **Problem:** An ordinary published session was created as `rsl2tp-tXXXXXX`, so `SESSION_GET` still returns that temporary name, not its current name or index. Finding a device under the configured name does not prove it is this session's device; additionally, S28 explicitly destroys manager-renamed sessions while P26/M17 promise that a hand-over preserves their interfaces.
- **Fix:** Choose and state a feasible adoption policy: preserving all matching sessions as unmanageable avoids guessing their current device identity, while stronger publication recovery needs additional trustworthy hand-over information or a kernel facility. If re-creation remains intentional for some adopted sessions, state that exception in the identity matrix and restart promises instead of promising unconditional preservation.
- **If we skip it:** Restart can destroy a healthy session or associate the publication decision with a foreign device that happens to hold its configured name.

Supporting source: the local `../l2tp-rs/src/session.rs:122–171` exposes the stored creation-time name, with no current device index in `SessionInfo`. The earlier Q1 decision is acknowledged; the missing observation needed to implement it is the issue.

### 14. Zoned peers need two device dependencies, but the event rules model only one bind name

**Where:** `docs/spec/tunnels.md:267–286` (T27), `docs/spec/events.md:12–51` (E1–E4), `docs/spec/promises.md:19` (G5), `docs/architecture.md:159`. **Before:** Phase 3 binding records and event indexes.

- **What this is:** T27 says a VRF-bound connection to `fe80::1%wan0` ends bound to the member `wan0`; a zone also works without `bind_interface`.
- **Problem:** E1–E3 and G5 describe one configured bind name, so comparing the effective device `wan0` with configured name `vrf-wan` would incorrectly call the binding invalid. Conversely, indexing only `bind_interface` misses a rename/replacement of a zone-only peer's `wan0`, and a zoned member leaving its configured VRF must invalidate the relationship even though the member still exists.
- **Fix:** Distinguish the configured bind device/VRF from the effective zone device, index both relevant names and lifetimes, and state the disappearance/rename/membership outcomes. Qualify G5's “device of that name” for the T27 exception and keep address-event matching on the effective device as T27 already requires.
- **If we skip it:** Link-local tunnels either disconnect spuriously or keep using an interface/routing domain that no longer satisfies their configuration.

### 15. The planner removes dependency edges that the specification requires across tunnels

**Where:** `docs/architecture.md:190–196`, `docs/spec/model.md:70–78` (M6), `docs/spec/architecture.md:111–114` (A8), C8/C14. **Before:** Phase 3 planner.

- **What this is:** The architecture says operations on different tunnels carry no ordering edge; A8 permits independence only where they share no name or identifier.
- **Problem:** Two sessions in different tunnels may exchange interface names, or a removed session in tunnel A may release a globally unique session ID needed in tunnel B. Those operations do have a release-before-claim dependency, including waiting for asynchronous deletion; issuing deletion first is not proof the ID is already free.
- **Fix:** Preserve cross-tunnel edges for shared session IDs and interface names, and let only unrelated operations proceed independently. Add a cross-tunnel swap and an asynchronous deletion/reuse case to the planner acceptance examples.
- **If we skip it:** A valid single reload can produce avoidable conflicts or fail to converge its name exchange correctly.

### 16. The documented systemd socket restriction prevents its descriptor-store protocol

**Where:** `docs/interface.md:106–119`, `docs/spec/process.md:259–284` (P21), P14. **Before:** Phase 5 unit.

- **What this is:** The interface page restricts address families to netlink and IP, while P14 requires sending descriptor-store notifications to `NOTIFY_SOCKET`.
- **Problem:** On a host whose resolver needs only IP sockets, following those restrictions excludes the Unix-domain socket the daemon must create for its own store messages. The daemon can run but cannot store or withdraw tunnel descriptors.
- **Fix:** Explicitly include `AF_UNIX` alongside `AF_NETLINK`, `AF_INET` and `AF_INET6` for the notification protocol, independent of resolver needs. Test the notification operation under the actual unit restrictions rather than only parsing its keys.
- **If we skip it:** The shipped unit defeats the crash-preservation feature it is documented to enable.

Systemd documents that [`RestrictAddressFamilies`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#RestrictAddressFamilies=) limits socket creation, and that [`NOTIFY_SOCKET`](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html) is a Unix datagram endpoint. Inherited journal descriptors do not provide that outbound notification socket.

## Should fix

### 17. The restart protocol does not identify re-exec versus a fresh start with stored descriptors

**Where:** `docs/spec/process.md:28–43,166–210` (P4/P26), `docs/plan.md:282–285`, `docs/architecture.md:264–268`. **Before:** Phase 5 restart.

- **What this is:** P4 requires daemonisation and readiness on a fresh start; P26 forbids both after re-exec and keeps the PID file.
- **Problem:** Both entry paths announce descriptors through the same LISTEN variables, so their presence cannot tell the new program whether to double-fork. An empty configuration can also re-exec with no tunnel descriptors at all, and the new process no longer has the old process's in-memory PID-file inode record.
- **Fix:** Document an explicit internal re-exec marker and the minimum process state it conveys, including foreground mode, original options/path, and the rule for preserving or safely reacquiring the PID-file record. Include empty-config re-exec and fresh store adoption as separate tests.
- **If we skip it:** An implementer must invent a second startup protocol, with a risk of changing the supervised PID or mishandling the PID file.

### 18. Resolver configuration changes both retain and discard the cached answer

**Where:** `docs/spec/resolvers.md:89–93,253–260` (V7/V13), V4, E10–E11. **Before:** Phase 3 resolvers.

- **What this is:** V7 exhaustively lists invalidation causes and says nothing else discards an answer; V13 adds a resolver-configuration change.
- **Problem:** Keep `resolver_name = "wan-dns"` but change that resolver's server list or bind interface: V7 retains the old answer, while V13 discards it and queries anew. An in-flight old lookup can also return after the change with the same resolver name unless the configuration incarnation is distinguished.
- **Fix:** Add resolver configuration identity to V7's invalidation rule and state that results from the prior resolver configuration are ignored. Make the selected policy agree across V4, V7, V13 and E10.
- **If we skip it:** The daemon can apply an answer obtained through the previous resolver configuration after a reload.

### 19. G7 promises more reload protection than C12 provides

**Where:** `docs/spec/promises.md:21` (G7), `docs/spec/configuration.md:129–134,151–152,171–172` (C10/C12). **Before:** Phase 1 contract closure and Phase 3 reload tests.

- **What this is:** G7 says a mistake never takes a running entry down and the worst result is no change; C12 applies tolerated mistakes as at startup.
- **Problem:** Replace a working tunnel's literal with an unusable `remote_addr`: C12 accepts the corrected peerless configuration and T17 disconnects it. This preserves its interface but does change working connectivity because of a configuration mistake.
- **Fix:** State precisely that hard mistakes retain previous values, while tolerated endpoint mistakes may disconnect a tunnel but preserve its interfaces. Alternatively change C12's policy, but do not leave the stronger promise in place while implementing the existing table.
- **If we skip it:** Documentation and tests can disagree about whether an invalid endpoint reload must preserve traffic.

### 20. Cookie-driven re-creation bypasses mandatory staging in its written instructions

**Where:** `docs/spec/sessions.md:30–43,154–158` (S4/S15). **Before:** Phase 3 session creation.

- **What this is:** S4 requires every session to be created under a random temporary name before publication.
- **Problem:** S15 instead says the replacement device is created under its configured name; a cookie update followed literally exposes that name before the configured hardware address has been applied.
- **Fix:** Say that cookie changes re-create through the ordinary S4–S7 staging/publication path, reusing the configured name only at publication.
- **If we skip it:** The replacement path can reintroduce the network-manager race that staging was designed to prevent.

### 21. Phase exits and the conformance plan claim proof before their prerequisites exist

**Where:** `docs/plan.md:46–53,115–137,173–179,227–228`, `docs/testing.md:41–53,87–92`, `docs/architecture.md:76–113`. **Before:** declaring Phase 1/2 complete.

- **What this is:** The plan uses rule coverage and a shared fake/real kernel conformance suite as phase exit criteria.
- **Problem:** Phase 1 requires every C rule to pass although C1/C3/C4 file handling is deferred to Phase 5; Phase 3 requires every G rule although G14/G20 need the later service/process layers. Also, “every K fact” cannot use only the listed production trait: for example, K5 needs sending frames and observing drops, and K31 needs bringing a device up, neither of which the daemon's production API provides.
- **Fix:** Enumerate the rules each phase can actually close and carry deferred rules explicitly to their owning phase. Define a small conformance-fixture interface for host setup and observations, and distinguish kernel requirements/source assertions from executable fake/real operation tests; keep test-only controls out of the production trait.
- **If we skip it:** Work is either blocked by impossible early exit gates or reported complete using tests that do not establish the stated claims.

### 22. A rule citation is being treated as evidence that a passing test exists

**Where:** `docs/testing.md:89`, `docs/plan.md:28–31,321–324`, `tests/tools/rulemap.rs:56–82`. **Before:** enabling the Phase 6 gate.

- **What this is:** The docs promise every rule has a test, while the described scanner collects `spec:` text anywhere under `src/` and `tests/`.
- **Problem:** A production comment such as `// spec: T27, R47` is counted even without an associated test; a test behind an unexecuted feature or ignored by the actual test command is also indistinguishable. One citation of C7 cannot show that each of its field cases was exercised, despite the plan's stronger per-row commitment.
- **Fix:** Describe the scanner honestly as a traceability check unless it maps rule IDs to identifiable test functions that the required suites execute. Maintain explicit case coverage for multi-clause rules and table rows instead of inferring it from one tag.
- **If we skip it:** A green rule map can claim implementation proof for rules with no running behavioral test.

This observation is about the documented proof method; this review does not modify the existing scanner or audit the full Phase 1 implementation.

## Smaller corrections and remaining design choices

| Location | Concrete issue | Smallest correction |
|---|---|---|
| `docs/README.md:23–27`, `docs/interface.md:7–9`, `docs/spec/README.md` known-gaps heading, `docs/plan.md:19–22` | “Current tree” still describes the removed pre-rewrite daemon; the current binary is a stub that exits 2, and the old 17,000-line modules were deleted in Phase 0. | Label the known-gaps tables as the historical `741117b` baseline, and describe the current rewrite status separately. |
| `docs/testing.md:92`, `docs/plan.md:249,257` | `cargo clippy -D warnings` and `cargo doc -D warnings` are not the command forms used by the working CI gate. | Use `cargo clippy … -- -D warnings` and `RUSTDOCFLAGS='-D warnings' cargo doc …`, as `.github/workflows/ci.yml` already does. |
| `docs/interface.md:135–139` | The library TOML example repeats the same dependency key twice in one table, so copying the block gives an invalid document. | Show the two alternatives in separate examples or comment out one. |
| `docs/spec/kernel.md`, K11 | Its link cites K13 for `IPV6_V6ONLY` being fixed at creation; K13 now concerns port 546. | Cite K23. |
| `docs/spec/hosts.md:44–53`, H7 | “Sends and receives through the VRF's table” suggests receive isolation, while K15/T1/S14 explicitly say L2TP/IP data reception ignores the tunnel socket and binding. | Describe the VRF rule as output/source selection and refer to K15 for input behavior. |
| `docs/dependencies.md:20,73`, `docs/plan.md:69–73` | The nix feature list still says socket only although the manifest enables process/signal/fs too; the iphost row still says the manifest must move to 0.4.0 although it has; the upstream section says nothing blocks Phase 2 despite findings 6, 7 and 11. | Refresh the checked-state statements and record the remaining API requirements rather than treating all upstream checks as closed. |
| `docs/packaging.md:25–26,79–80` | The same supplied unit is installed beside binaries in two different directories, `/usr/local/sbin` and `/usr/sbin`, with no stated rule for its `ExecStart` path. | Specify how each installation selects its own binary, preferably a unit template rendered with the installation path; test both paths, including a host where both binaries exist. This is an underspecified packaging choice, not proof that the future unit is already wrong. |
| `docs/packaging.md:26` | Preserving an edited unit by comparing against “any version this binary ever installed” requires a defined source of prior-version content; comparing only with the current embedded unit mistakes a normal older unit for an operator edit. | State whether known shipped unit versions/hashes are embedded or another ownership marker is used, and test an unedited old unit upgrade as well as an edited one. |

## Recommended order

| Milestone | Resolve |
|---|---|
| Close Phase 1's contract | 1–3, 19, and the Phase 1 exit criterion in 21 |
| Start/finalize Phase 2 boundary | 4–11, the adoption inputs of 13, and the conformance fixture in 21 |
| Implement Phase 3 | 3–5, 8–10, 13–15, 18–20 |
| Implement Phases 4–5 | 11–13, 16–17; packaging path and unit ownership choices |
| Enable Phase 6 proof gates | 21–22 and corrected commands |

Each substantive finding includes a counterexample suitable for a focused regression or conformance test. The report recommends documentation decisions; it does not silently amend authoritative behavior or declare existing Phase 1 code wrong where the specification itself disagrees.

**Verdict: fix the Phase 1 contract conflicts and Phase 2 ownership/event-boundary findings before treating those phases as complete.** Later-phase fixes can be recorded now without implementing those phases early.

**Not checked:** No build, unit suite, privileged container experiment, or QEMU matrix was run; this was a documentation/source review, not a full code audit or revalidation of every kernel fact. Published upstream artifacts were not compared byte-for-byte with the inspected local dependency tree.
**Risk:** The documented design currently permits wrong-session deletion, false deletion handling across namespaces, missed recovery, and unbounded waits/queues if followed literally. No fixes were applied outside this report.
