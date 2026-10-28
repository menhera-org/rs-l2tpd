# Roadmap step 2, second pass: rule-by-rule tables — 2026-10-28

The five independent auditors' working tables, kept as written (headings demoted one level). The second pass of the step 2 report (`STEP2_CODE_VS_SPEC_2026-10-27.md`, section "Second pass") consolidates their defects; every defect it lists was checked there, the individual rows below were not all re-checked. Paths named "scratchpad" were throwaway copies outside the repository.

## Audit 2: process (P), promises (G) and requirements (R) against the code

Scope: docs/spec/process.md, promises.md, requirements.md, read against src/bin/main.rs, src/service.rs,
src/runtime.rs, src/blocking.rs, the relevant parts of src/state.rs and src/netlink.rs, the unit text in
main.rs, and tests/docker/. Static reading only; no binary was run.

Independence note: a Grep I ran over the repo matched two lines of docs/spec/README.md beyond line 60
(the rows on bindv6only and restart). I saw those two lines only. Both facts were also plain from the
code: no `fix_bindv6only` or `SIGUSR2` anywhere in src/.

Line numbers are as of HEAD 741117b.

### Process (P)

| rule | verdict | evidence (file:line) | test | note |
|---|---|---|---|---|
| P1 start before the network is ready | DEFECT | runtime.rs:1323-1345 (candidates are peer, then discard addresses), runtime.rs:2045-2068 (`prepare_discard_route` returns Err for the 10 s grace), runtime.rs:2081-2086 (null device fails, then the connect fails), service.rs:178-181 (converge retries until Ok) | degraded-start.sh "readiness waits for every configurable interface" asserts the opposite of the spec (readiness held about 10 s for a route to `100::`) | With no default route, an unreachable peer falls back to the discard address. That address has no route, so the whole reconcile fails for 10 s. If the null device cannot be created after that, it keeps failing. Tunnel and session creation is delayed or blocked. Defect 1. An absent bind device does not delay (runtime.rs:2096-2104), but see G5. |
| P2 start-up order; leniency; empty config is ready at once | PARTIAL | main.rs:1084-1132 | degraded-start.sh "nothing usable", "an empty configuration" | The command line is parsed before logging starts (main.rs:1087 then 1094); the spec says logging first. This is minor, since `--verbose` selects the level. Leniency conforms (main.rs:1109-1130). An empty config reconciles to Ok at once. |
| P3 `--check` | CONFORMS | main.rs:1116-1126 (before `daemonize` and `Service::new`); config loading does no resolution (config.rs:1360) | degraded-start.sh "--check with mistakes" | Exits 1 on errors or warnings. Opens no socket, device or PID file. |
| P4 double fork; parent 0/1; intermediate exits; umask; only PID file | CONFORMS | main.rs:119-173 (fork, setsid, fork, `_exit(0)`, umask 022), main.rs:548-564 (R gives 0; F, EOF or error give 1) | implicit in every docker script (`wait $parent`) | |
| P5 kernel interfaces opened before apply; open failure is a host defect, retried; P25 tunable checked | DEFECT | service.rs:139, runtime.rs:721-723, state.rs:914-916, l2tp handle.rs:145-149 (`NetNs::current`, genl socket) | none | Any failure in `Service::new` (no /proc, refused netlink or genl socket, monitor setup) goes up through `?` to main.rs:1147. The daemon exits 1 and is not retried. The L2TP genl family is resolved lazily, so a missing module is retried. The P25 check is absent (GAP). Defect 6. |
| P6 readiness = every eligible entry exists (temporary name, deferred MAC count); exactly once; never revoked | DEFECT | service.rs:170-198 (ready only when `reconcile` returns Ok), runtime.rs:1068-1107, state.rs:1659-1682, 586-606, 484-500 | session-children.sh:152-175 (readiness comes only after the foreign holder of the name is deleted, which shows the defect) | A session staged under its temporary name, whose publication fails (the configured name is held), returns `Error::Other`. That is not a conflict, so every reconcile aborts and readiness is withheld indefinitely, although the device exists (defect 2). Reported once, by the PID file then the parent exit: conforms (main.rs:1163-1177). |
| P7 readiness must not wait for resolver, route, source, bind device, IPv6, deferred MAC, publication, foreign-configured interface, conflicts once spent | DEFECT | as P1 and P6; runtime.rs:2709-2711 (FQDN, no wait), runtime.rs:2096-2104 (bind device, no wait), state.rs:1202 (no IPv6 falls back) | degraded-start.sh (encodes the wait), ipv6-disabled.sh, source-and-peers.sh `literal` | Holds for resolvers, bind devices and IPv6. Fails for routes (the discard route grace) and for publication. |
| P8 may wait for bounded conflict retries, concurrently with the rest | DEFECT | runtime.rs:864-881 and 1100-1107 (`note_conflict` false for the first 9 refusals, so `return Err`), runtime.rs:1489-1505 | source-and-peers.sh `conflict` (checks the end state only) | For refusals 1-9, the reconcile aborts at the conflicting entry. Tunnels after it in `BTreeMap` order and all sessions are not created for about 10 s. The retries are not concurrent. Defect 3. |
| P9 retries every second; events handled; reloads before readiness ignored | CONFORMS | service.rs:184-196 | degraded-start.sh (log "will retry") | |
| P10 PID file: fresh inode, atomic replace, directory ownership, no chmod, warn, precreated-file fallback, no symlinks, trusted directory symlinks, **remembers inode** | PARTIAL | main.rs:185-538 (temp file then `renameat`/`linkat`, `secure_pid_directory`, `update_precreated_pid_file`, `validate_pid_entry` with `AT_SYMLINK_NOFOLLOW`) | main.rs unit tests `write_pid_file_*` (main.rs:1531-1723) | The published inode is never recorded (`write_pid_file` returns `()`). The fallback runs only for `PermissionDenied` (main.rs:482). A read-only filesystem (`EROFS`) does not get the precreated-file path (low). |
| P11 removed only if still our inode; stale file replaced; published before parent exit; publication failure: keep running, parent exits 0 | DEFECT | main.rs:540-546 (`fs::remove_file` without checking), main.rs:1163-1176 (on failure: `signal_failure`, shutdown, exit 1) | none | Removal is unconditional (defect 4). A failed publication tears everything down and exits 1 (defect 5). Stale-file replacement and "before the parent" conform. |
| P12 SIGHUP/SIGTERM/SIGINT/SIGUSR2; coalescing; reload not lost; shutdown bypass; precedence; idempotent second shutdown; serialised | PARTIAL | main.rs:837-868; service.rs:103-116, 265-268 | service.rs tests `shutdown_survives_a_full_queue_*`, `reliable_reload_waits_for_queue_capacity` | SIGUSR2 is not handled (GAP), and its default action kills the process (defect 7). Coalescing is partial: the HUP task forwards each signal tokio observes as its own queued `ReloadRequested`, so SIGHUPs sent while a reload runs cause several reloads. Not losing a reload, the shutdown bypass, precedence (loop-top check, service.rs:266) and a second SIGTERM doing nothing (the task ends, tokio keeps the handler) all conform. |
| P13 reload semantics; retry 1 s; blocked callback; error keeps config; panic ends after removal | DEFECT | service.rs:291-326 | defect 8 has none | Shutdown waits for a blocked callback: `spawn_blocking(...).await` is not raced against `shutdown_rx`, and tokio's `Runtime` drop at main.rs:1139 also waits for blocking tasks (defect 8). A panic returns at service.rs:311 without `runtime.shutdown()`. Objects go only by `Drop` (sockets closed), unordered and unwaited, and the daemon-owned null device is left (PARTIAL). Error handling, the 1 s retry and replacement by a new reload conform (service.rs:272-281, 300-306). |
| P14 FDSTORE hand-over | GAP | no `NOTIFY_SOCKET`/`LISTEN_FDS` in src | none | |
| P26 own restart (re-exec) | GAP | no SIGUSR2 or exec path | none | |
| P15 restart as fast as first start | GAP | follows P26 | none | |
| P16 shutdown order: timers, sessions then tunnels by socket close, PID file, exit; foreign left | PARTIAL | runtime.rs:1966-1986, runtime.rs:799-808 (tunnels deleted **first**; their sessions are dropped from the plan at line 807 and go with the socket), state.rs:1446-1465 | network.sh matrix, tunnel-ownership.sh, session-children.sh | Sessions are never explicitly deleted before their tunnel. The outcome is the same, through the kernel's tunnel close, but the M6 order is not followed. `reconnect_retries` timers are not stopped in `shutdown` (only in `Drop`, runtime.rs:2161-2173). Socket-close deletion keeps foreign replacements: conforms. |
| P17 wait up to 2 s per tunnel deletion; non-zero exit; later steps still run | DEFECT | state.rs:1446-1458 (drops the socket with `auto_delete(false)`, no wait), runtime.rs:1963-1965 (doc comment says it waits) | none | No wait for the kernel's deferred teardown, so a quick restart can meet EEXIST (defect 9, low). A failed deletion aborts the ordered reconcile (`try_apply!`), but the null-device removal, the PID-file removal and exit 1 still happen (main.rs:1188-1195). |
| P18 nothing survives a crash | DEFECT | state.rs:1008-1090 (`LinkDummy` `rsl2tpnull*` and discard routes) | discard-recovery.sh `existing` (shows a leftover device is treated as foreign) | The null device and its routes outlive SIGKILL. At the next start a leftover `rsl2tpnull0` is treated as foreign and a new `rsl2tpnull1` is made. Devices pile up across crashes. Defect 10. |
| P19 no panic on input | CONFORMS (spot check) | non-test `expect`s are internal invariants only (runtime.rs:824-1071, 1345, 1422, 1444, 2559) | none specific | Not exhaustive. |
| P20 concurrent instances | CONFORMS | conflict path runtime.rs:1489; deletion by socket close only, state.rs:1446 | source-and-peers.sh `conflict` | The shared-PID-file case is covered by defect 4. |
| P21 supplied unit | DEFECT | main.rs:965-1001 | main.rs `systemd_unit_keeps_its_contract_and_is_hardened` (`setup` feature; does not check the missing items) | Missing `NotifyAccess=all` and `FileDescriptorStoreMax=`. `ProtectKernelTunables=yes` makes /proc/sys read-only, which forbids the bindv6only write the rule requires. `ProtectSystem=full` leaves /var etc. writable, not "read-only except the PID file". Present and correct: Before/RequiredBy, Type=forking, PIDFile, TimeoutStartSec=infinity, Restart=on-failure, NoNewPrivileges, ProtectHome, RestrictAddressFamilies, no capability restriction. Defect 11. |
| P22 process contract | PARTIAL | main.rs:837-868 | | SIGUSR2 is missing (see P12, defect 7). The rest conforms. |
| P23 no systemd/dbus dependency; only /proc; no /sys | CONFORMS | Cargo.toml:24-43; no `/sys` in src (only `--setup` reads /proc/self/exe, main.rs:1007) | | |
| P24 glibc and musl | UNTESTABLE-STATICALLY | target/ has -gnu and -musl builds | build both and run docker on each | |
| P25 bindv6only | GAP | no `fix_bindv6only`, no read-back | none | |

### Promises (G)

| rule | verdict | evidence (file:line) | test | note |
|---|---|---|---|---|
| G1 never exits because of input or another process | DEFECT | main.rs:1163-1176, main.rs:1177-1183, main.rs:1147 | none | Exits when another process put a foreign-owned file or symlink at the PID path (defect 5). Exits when the parent died before readiness, because the readiness write gets EPIPE (defect 12). Exits on SIGUSR2 (defect 7). |
| G2 never touches foreign objects | CONFORMS (paths read) | state.rs:1446-1458, 1492-1525; runtime.rs:2096 | tunnel-ownership.sh, session-identity.sh, discard-recovery.sh | Other auditors cover sessions in depth. |
| G3 identity changes only per matrix | UNTESTABLE-STATICALLY (scope) | runtime.rs:960-1021 (renames by index through a temporary name) | session-identity.sh, address-changes.sh | Sessions auditor. |
| G4 never takes a device down | UNTESTABLE-STATICALLY (scope) | state.rs:520-530 (MAC deferred while up) | networkd-sessions.sh, README "MAC-changing" | |
| G5 never connected to an unnamed peer; no peer means not connected; bound tunnel connected only while bound | DEFECT | runtime.rs:2096-2104 plus 1323-1331 (absent bind device: unbound socket connected to the **real peer**), runtime.rs:1367-1379 (bind device vanished: same), runtime.rs:2190-2201 (no peer: connected to `100::` or `192.0.0.8`) | degraded-start.sh (asserts `to 100::`) | A tunnel with `bind_interface` whose device is absent at start sends to its peer through the main table and its default route. The device or VRF binding is bypassed. A peerless tunnel is connected to a discard address instead of being left unconnected. Defect 13. |
| G6 one entry never delays another | DEFECT | runtime.rs:864-881, 1100-1107, 2059-2067, state.rs:1682 | none | A conflict during its first 9 refusals, a missing discard route, a publication failure or any non-conflict error (for example EMFILE) aborts the whole reconcile. Every later entry waits. Defects 2 and 3. |
| G7 bad reload never takes an entry down | CONFORMS (loader) | main.rs:780-815 | main.rs tests `lenient_loading_*`, degraded-start.sh reload cases | Config auditor. |
| G8 readiness never early; never waits for routes, publication, etc. | DEFECT | as P6/P7 | as P6/P7 | Never early: conforms. Waits for a route (discard grace) and for publication. |
| G9 no tunnel or session outlives the process | CONFORMS | sockets owned by `TunnelState` (state.rs:796-811), `auto_delete(false)` (state.rs:1256) | network.sh (SIGTERM cleanup) | The null device outlives the process: see P18. |
| G10 capabilities; no `bpf()`; changes no kernel setting except bindv6only | PARTIAL | classic filter via `setsockopt` (netlink.rs:62); routes and a dummy device created (state.rs:1008-1090) | | No `bpf()` call. The daemon writes routes into main and VRF tables and creates a dummy link, which the spec retired (R2, discard.md). The bindv6only exception is not implemented. |
| G11 cookies never logged; nothing wire-changing unless configured | CONFORMS (scope) | runtime.rs:2515-2522, config.rs:242-246 | network.sh `COOKIES=1` | `--check` prints cookies in the rendered config (main.rs:1117). Not logging; O8's auditor should judge. |
| G12 bounded event cost; route changes not subscribed | DEFECT | runtime.rs:2256-2262 (`Ipv4Route`, `Ipv6Route` groups) | link-monitor-burst.sh, monitor-resync.sh | The filter limits the cost, but the subscription the spec forbids is there (also R5, R35). Defect 14. |
| G13 lasting condition reported once; retries silent | DEFECT | service.rs:181 (`warn!` every second in converge), service.rs:278 (`warn!` every second after readiness) | degraded-start.sh greps the repeated message | A missing module, a missing privilege, a held name or a missing discard route logs a warning every second for as long as it lasts. Defect 15. |
| G14 library same rules | PARTIAL | blocking.rs:39-160 wraps the same `Service` | service.rs tests | Inherits the Service defects (P13, G6, G13). |
| G15 readiness in bounded time | DEFECT | as P1/P6/P8 | | Unbounded when a published name is held, or when the discard route cannot be provided. At least 10 s with no default route. |
| G16 existence | UNTESTABLE-STATICALLY | | network.sh, address-changes.sh | Other auditors. |
| G17 convergence bounds | PARTIAL | `PEER_RETRY_INTERVAL` 1 s (runtime.rs:70), `CONFLICT_RETRY_INTERVAL` 30 s (runtime.rs:72), DNS 30 s (runtime.rs:53), resync on monitor reopen (runtime.rs:2290-2298), reload retry 1 s (service.rs:261) | source-and-peers.sh, discard-recovery.sh, monitor-resync.sh | The bindv6only row is GAP. Other rows look plausible; other auditors own them. |
| G18 stability | UNTESTABLE-STATICALLY | | network.sh (unchanged reload) | |
| G19 fidelity | PARTIAL | | | The substitute for "no peer" is a connected discard address, not the disconnected state (see G5). |
| G20 shutdown | PARTIAL | as P16/P17, main.rs:1188-1195 | network.sh | No explicit sessions-first order, no 2 s wait, PID-file removal unconditional (defect 4). The exit code does reflect failures. |
| G21 early start | DEFECT | as P1 | degraded-start.sh | |
| G22 compatibility | UNTESTABLE-STATICALLY | | network.sh baseline matrix | |
| G23 resources | UNTESTABLE-STATICALLY | timers keyed per interface index and replaced, not accumulated (runtime.rs:1902-1918) | | |

### Requirements (R): the daemon's behaviour when one is unmet

| rule | verdict | evidence (file:line) | test | note |
|---|---|---|---|---|
| R1 L2TP modules; when missing: reported once, retried 1 s, readiness withheld; no l2tp_ip6 gives AF_INET | PARTIAL | genl family resolved lazily (l2tp handle.rs:157); service.rs:178-187; state.rs:720-726, 1200-1205 | ipv6-disabled.sh | Retried and withheld: conforms. Reported every second (G13). The AF_INET fallback conforms. |
| R2 removed | DEFECT | state.rs:1008-1090 | degraded-start.sh, discard-recovery.sh, networkd-routes.sh | The retired null device and routes are still built. Other auditors own this. |
| R3 CAP_NET_ADMIN missing | PARTIAL | the EPERM path is like R1 | none | Same logging issue as R1. |
| R4 CAP_NET_RAW for `ra` resolvers | GAP | no configured resolvers in src | none | |
| R5 netlink sockets; no route group | DEFECT | service.rs:139 (exits on open failure); runtime.rs:2260-2261 | | See P5 and G12. The watcher's own reopen is retried (runtime.rs:2266-2272). |
| R6 BPF filter refused: warn and continue | CONFORMS | netlink.rs:61-67 | | |
| R7 /proc missing: reported, readiness withheld | PARTIAL | `NetNs::current` in l2tp handle.rs:147, via state.rs:915 | none | Exits 1, which withholds readiness, but P5 requires a retry. |
| R8 monotonic clock | CONFORMS | tokio `Instant`; runtime.rs:40 | | |
| R9 EMFILE: transient, retried | PARTIAL | runtime.rs:873-881 | none | Retried, but aborts the reconcile for every later entry (G6). |
| R10 8 MiB receive buffers, FORCE then plain | CONFORMS | netlink.rs:16-120 | link-monitor-burst.sh | |
| R11 objects in other namespaces | UNTESTABLE-STATICALLY | | session-identity.sh `moved` | |
| R12 init system treats parent exit as readiness | CONFORMS | main.rs:166-171 | | |
| R43 only /proc; no systemd/libc dependency | CONFORMS | see P23 | | |
| R44 bindv6only=0 or opt-out | GAP | | | |
| R45 VRF kernel support | UNTESTABLE-STATICALLY | | address-changes.sh VRF cases | |
| R46 CAP_NET_BIND_SERVICE for dhcpv6 | GAP | | | |
| R13 config files lenient | CONFORMS | main.rs:649-815 | main.rs config tests, degraded-start.sh | |
| R14 identifier uniqueness; namespace conflict retried then left out | PARTIAL | runtime.rs:1489-1512 | source-and-peers.sh `conflict` | Left out after 10 tries, but blocks other entries while retrying (defect 3). |
| R15 cookies agreed | CONFORMS (no action needed) | | | |
| R16 names resolvable eventually | PARTIAL | runtime.rs:2709-2711 | discard-recovery.sh `dns` | Waits on a discard address, not disconnected (G5). |
| R17 managed tunnels not deleted by hand | CONFORMS | state.rs:1447-1449 | tunnel-ownership.sh | |
| R18 sessions removed by hand get re-created | UNTESTABLE-STATICALLY (scope) | | | Sessions auditor. |
| R19 no foreign `rsl2tp-t*`/`rsl2tp-r*` | UNTESTABLE-STATICALLY (scope) | runtime.rs:961-968 (allocates an unused temporary name) | | |
| R20 removed | n/a | | | |
| R21 one instance per identifier set, own PID path | CONFORMS | as P20 | | See defect 4 for a shared path. |
| R22 a kill leaves nothing | PARTIAL | as P18 | | The null device and routes stay. |
| R23 no re-assertion | CONFORMS (scope) | | | |
| R47 link-local peer needs device or zone | UNTESTABLE-STATICALLY (scope) | `ScopeRequired` is treated as unreachable (runtime.rs:2220-2221) | | Config auditor. |
| R24 peer implementation | n/a | | | |
| R25 mirrored identifiers | n/a | | | |
| R26 route and source to peer | PARTIAL | runtime.rs:1323-1345 | source-and-peers.sh `literal` | Uses a discard connection, and without a discard route readiness is delayed (P1). |
| R27 no AF_INET6: IPv6 peer stays disconnected, reported once | PARTIAL | runtime.rs:2218-2221, 1472-1477 | ipv6-disabled.sh | Reported once: conforms. Connected to `192.0.0.8` instead of left disconnected. |
| R28-R31, R34, R36 other managers | UNTESTABLE-STATICALLY (scope) | | networkd-*.sh, session-*.sh | Sessions and tunnels auditors. |
| R35 floods: route changes not subscribed | DEFECT | runtime.rs:2260-2261 | monitor-resync.sh | As G12. |
| R48 bindv6only changed at runtime | GAP | | | |
| R37 Tokio required for Service/Runtime; blocking without | CONFORMS | l2tp handle.rs:142-144; blocking.rs:49-68 | | |
| R38 host requirements for embedders | PARTIAL | as R1-R10 | | |
| R39 every event forwarded | UNTESTABLE-STATICALLY | | | Library auditor. |
| R40 drop without shutdown closes sockets | CONFORMS | runtime.rs:2161-2173; `TunnelState` owns the socket | | |
| R41 log sink | CONFORMS | `log` facade throughout | | |
| R42 no overlapping Runtimes | CONFORMS | conflict path | | |

### Defects

1. **Readiness and creation are held for a route at start-up** (P1, P7, G8, G15, G21). High confidence.
   - **Where:** runtime.rs:1323-1345, 2045-2068, 2081-2086; service.rs:178-181.
   - **Scenario:** a boot with no default route, and a tunnel whose literal peer has no route or whose name is unresolved.
   - **What goes wrong:** `create_tunnel` tries the discard address next. `prepare_discard_route` returns `Err` for 10 s, which aborts the reconcile. No tunnel after it and no session is created, and the parent does not exit.
   - **If the null device cannot be made** (no `dummy` driver, or a refused route): the connect to `100::` fails as unreachable. `create_tunnel` returns `Err` on every reconcile and readiness never comes. degraded-start.sh asserts this old behaviour.

2. **A held configured name blocks readiness and every later entry indefinitely** (P6, P7, G6, G8, G15). High confidence.
   - **Where:** state.rs:1659-1682 with 586-606 and 484-500; runtime.rs:1086-1107.
   - **Scenario:** a session with `interface_hwaddr` (staged), whose final name is held by another device. The staged device exists under its temporary name.
   - **What goes wrong:** `set_link` fails. `Error::Other` is not a conflict, so `try_apply!` aborts the reconcile every second. Readiness is withheld until the name is freed. session-children.sh:152-175 shows this: the test waits for readiness only after deleting `pseudowire0`.
   - **Same aborted reconcile after readiness:** every later session or tunnel is never applied while the name is held.
   - **Unstaged sessions:** created directly under the final name, they take EEXIST. They are classed as a conflict and, after 10 s, left out with no device at all. The spec counts a session under its temporary name as ready.

3. **Conflict retries are not concurrent** (P8, G6, R14). High confidence.
   - **Where:** runtime.rs:864-881, 1100-1107, 1489-1495.
   - **Scenario:** the kernel refuses an entry with EEXIST or EADDRINUSE.
   - **What goes wrong:** on refusals 1-9, `note_conflict` returns false and the reconcile returns `Err` at that entry. Every tunnel with a higher id, and every session, waits about 10 s, until the 10th refusal.

4. **The PID file is removed whoever owns it** (P11, P10, G20). High confidence.
   - **Where:** main.rs:540-546, 1181, 1193.
   - **Scenario:** instance A is running. Instance B is started with the same PID path (or another process writes the path), and B atomically replaces A's file after its readiness. A is then stopped.
   - **What goes wrong:** A's `fs::remove_file` deletes B's PID file, so the init system loses track of B. The published inode is never recorded, so the check is impossible as written.

5. **A failed PID-file publication tears everything down and exits 1** (P11, G1). High confidence.
   - **Where:** main.rs:1163-1176.
   - **Scenario:** the PID path holds a symlink, a file owned by another user, a directory, or a FIFO. Or the directory is owned by a third user or is on a read-only filesystem.
   - **What goes wrong:** after convergence the daemon sends failure to the parent (exit 1), shuts down every tunnel and session, and exits. The spec says: report it, keep running, parent exits 0.

6. **A kernel-interface open failure exits instead of being retried** (P5, R5, R7). Medium confidence.
   - **Where:** service.rs:139, runtime.rs:722, state.rs:915-916, main.rs:1147.
   - **Scenario:** /proc not mounted, a genl or rtnetlink socket refused (seccomp, LSM), or monitor setup failing.
   - **What goes wrong:** `Service::new` fails, `run_daemon` returns `Err`, and the pipe is closed, so the parent exits 1. There is no retry. Under a non-systemd init the daemon is simply gone. Readiness is withheld, but not retried.

7. **SIGUSR2 kills the daemon** (P12, P22, P26, G1). High confidence.
   - **Where:** main.rs:837-868 installs no SIGUSR2 handler.
   - **Scenario:** the restart signal documented in the spec and in contracts.md is sent.
   - **What goes wrong:** the default disposition terminates the process with no ordered shutdown. The PID file is left stale. The kernel removes the tunnels, and the null device and routes stay. With the unit, systemd restarts the daemon 3 s later as a failure.

8. **Shutdown waits for a blocked reload callback** (P13). Medium confidence.
   - **Where:** service.rs:293-297; Runtime drop after main.rs:1139.
   - **Scenario:** a reload whose loader blocks, for example on a hung NFS or FUSE mount of /etc/rs-l2tpd.toml.d, then SIGTERM.
   - **What goes wrong:** the run loop is parked on `spawn_blocking(..).await` and does not watch `shutdown_rx`, so shutdown does not start. Even after it, dropping the tokio runtime waits for the blocking task. The spec says shutdown proceeds and the callback's result is discarded. The same applies to `blocking::Service`.

9. **No wait for tunnel deletion at shutdown** (P17, G20). Low-medium confidence.
   - **Where:** state.rs:1446-1458; the doc comment at runtime.rs:1963-1965 claims a wait.
   - **What goes wrong:** the socket is dropped and the daemon exits while the kernel's deferred teardown may still hold the ids.
   - **Effect:** a quick restart meets EEXIST, which triggers defect 3's blocking and delays readiness by one or more seconds.

10. **The null device and routes survive a crash and pile up** (P18, R22, G10). High confidence.
    - **Where:** state.rs:1008-1090.
    - **Scenario:** SIGKILL, or defect 7, after the null device was created.
    - **What goes wrong:** `rsl2tpnull0` and its routes remain. The next start treats them as foreign (discard-recovery.sh `existing`) and creates `rsl2tpnull1`. Each crash leaks one more device and route set.

11. **The supplied unit contradicts P21.** High confidence.
    - **Where:** main.rs:965-1001.
    - **Problems:**
      - `ProtectKernelTunables=yes` makes /proc/sys read-only, so P25's bindv6only write can never succeed under the unit.
      - `NotifyAccess=all` and `FileDescriptorStoreMax=` are missing.
      - `ProtectSystem=full` leaves /var, /srv, /opt and others writable, against "read-only except the PID file".
    - **Test gap:** the unit test (main.rs:1762) does not check these.

12. **The daemon exits if the parent dies before readiness** (G1, P11's principle). Medium confidence.
    - **Where:** main.rs:1177-1183, main.rs:82-108.
    - **Scenario:** the foreground parent is killed while waiting: Ctrl-C (the grandchild called setsid, so the terminal's SIGINT does not reach it), an init or wrapper `timeout`, or an OOM kill.
    - **What goes wrong:** Rust ignores SIGPIPE, so the readiness `write` fails with EPIPE. `signal_ready` returns `Err`, and the daemon shuts down every tunnel and exits.
    - **Why it matters:** a converged daemon dies because another process went away.

13. **A tunnel whose bind device is absent is connected unbound to its real peer** (G5). High confidence.
    - **Where:** runtime.rs:2096-2104 with 1323-1331; the same at 1367-1379 when the device vanishes during the bind.
    - **Scenario:** `bind_interface = "vrf-blue"` or `"wan0"`, with the device not yet created at start, and a literal peer.
    - **What goes wrong:** the socket is created unbound and `connect`ed to the peer through the main table. Frames leave through whatever device the default route names until the bind device appears.
    - **Related:** G5's "no peer means not connected" is broken everywhere by the discard-address connection (runtime.rs:2190-2201).

14. **Route groups are subscribed** (G12, R5, R35). High confidence; the effect is mitigated.
    - **Where:** runtime.rs:2256-2262.
    - **What goes wrong:** `Ipv4Route` and `Ipv6Route` are joined. The BPF filter drops most of the traffic in the kernel, but where the filter cannot be attached (R6), every route change on a router is read.

15. **Lasting conditions are logged every second** (G13, O3). High confidence.
    - **Where:** service.rs:181 and service.rs:278.
    - **Scenario:** a missing module, EPERM, a held published name (defect 2) or a missing discard route.
    - **What goes wrong:** a `warn!` every second for as long as the condition lasts.

16. **Reload panic skips the ordered teardown** (P13). Medium confidence.
    - **Where:** service.rs:309-311.
    - **What goes wrong:** the early return skips `runtime.shutdown()`. Sessions and tunnels go only by socket close, with no deletion wait, and the daemon-owned null device and routes are not removed. main.rs then removes the PID file and exits 1.

17. **SIGHUPs during a reload are not coalesced** (P12). Low severity, high confidence.
    - **Where:** main.rs:843-850.
    - **What goes wrong:** the forwarding task enqueues one `ReloadRequested` per signal tokio delivers. N SIGHUPs spread across a long reload give N further reloads, not one.

Not checked: I did not run `cargo test` or any docker script. Areas owned by other auditors (session staging internals, resolvers, configuration validation) were judged only where they gate readiness, process behaviour or a G promise.

## Code-vs-spec audit: tunnels (T), hosts (H), kernel (K)

Auditor 2 (T/H/K scope). Static reading of `src/state.rs`, `src/runtime.rs`,
`src/netlink.rs`, `src/config.rs`, `src/service.rs`, `src/bin/main.rs` and the
l2tp crate (`/home/dev/l2tp-rs/src/socket.rs`, `handle.rs`, `tunnel.rs`).
`cargo test --lib`: 114 passed, 21 ignored (all `privileged_*`), 0 failed.

Independence note: a broad `Grep` for `CAP_NET` returned, without my asking for them,
a few lines from `audit/STEP2_CODE_VS_SPEC_2026-10-27.md` and `docs/spec/README.md:118`, both
saying R4 (no `CAP_NET_RAW`) conforms. I did not open those files. Defect 1 below
reaches the opposite conclusion from the code itself.

Overall: the code still implements the **retired discard-address design**. Every
tunnel socket is always connected: to the real peer, or to `100::` / `192.0.0.8`.
A daemon-owned `dummy` null device and routes are the last resort. The monitor
subscribes to the route groups. Many T/H rules are therefore GAP. The DEFECTs are
behaviours that are wrong even judged against that design's own intent, or that
cause concrete harm: leaks, permanent stalls, or a whole reconcile blocked.

"privileged" tests are `#[ignore]` and need root in an isolated netns. They were not run.

### Tunnels

| rule | verdict | evidence (file:line) | test | note |
|---|---|---|---|---|
| T1 socket: one L2TP/IP socket, bound to unspecified addr with tunnel id as conn id, peer tunnel id registered | CONFORMS | state.rs:703-708, 1180-1212, 1250-1254; l2tp socket.rs:300-305 | privileged_add_tunnel_records_unbound_socket (ignored) | |
| T1 "whether or not the socket is connected" | GAP | l2tp socket.rs:269-323 (`TunnelSocket::ip` always connects), state.rs:1263 | — | never registered unconnected |
| T1 bind device by index / unbound while absent | PARTIAL | state.rs:652-669 (SO_BINDTODEVICE by name + index compare) | privileged_add_tunnel_records_bound_interface (ignored) | name, not index; while the device is absent the socket is unbound **and connected** (see T13) |
| T1 peer: real peer or none | GAP | runtime.rs:2190-2201, 2709-2711 | reconcile_uses_discard_addr_for_unresolved_fqdn | discard address instead of none |
| T1 connected iff real peer accepted and bind device present | DEFECT | runtime.rs:1319-1383; state.rs:1263 | reconcile_defers_missing_bind_interface_until_it_appears (mock hides it) | connected to a discard address; also connected while unbound (T13) and while bound to a renamed device (T11) |
| T2 converge at every reconcile/event, in place | PARTIAL | runtime.rs:772-1129, 1583-1920 | many mock tests | in place for peer changes; bind_interface change re-creates (runtime.rs:2564-2565, a gap the spec itself admits) |
| T3 dual-stack AF_INET6, IPv4 as mapped | CONFORMS | state.rs:697-718, 1180-1212 | privileged_ipv4_peer_update_and_source_reselection (ignored) | the "socket is not IPv6-only" condition is never checked (T26) |
| T4 AF_INET fallback on EAFNOSUPPORT/EPROTONOSUPPORT | PARTIAL | state.rs:720-726, 1200-1208 | privileged_ipv4_sockets_use_native_endpoints_and_refuse_ipv6_peers (ignored; uses `use_ipv4_sockets`) | the flag is sticky (`ipv4_sockets` AtomicBool, state.rs:1206) and never probed again, contrary to "probed again at every tunnel creation". An IPv6 peer on AF_INET falls back to a discard address, not disconnected. Reported once (warn at state.rs:1203) |
| T5 no non-default socket options except binding | CONFORMS | l2tp socket.rs:514-529 (IP encap `configure` sets nothing) | — | no IPV6_V6ONLY write either |
| T6 create: bind, bind device, register, sessions; created disconnected, connected in same reconcile | GAP | runtime.rs:1314-1346 | unroutable_literal_peer_gets_a_discard_address_and_is_retried | always created connected (peer or discard) |
| T6 close-on-exec | CONFORMS | l2tp socket.rs:900 (`SOCK_CLOEXEC`) | — | P26 hand-over absent (process scope) |
| T7 EEXIST / EADDRINUSE are conflicts | CONFORMS | runtime.rs:2227-2240 | refused_identifiers_are_retried_then_left_out_until_a_retry_succeeds | |
| T8 delete by closing the socket, never by id | CONFORMS | state.rs:1446-1466, 1256 (`set_auto_delete(false)`) | privileged_* use `assert_kernel_tunnel_deleted` (ignored) | |
| T8 wait up to 2 s for kernel removal before re-creating the same id | GAP | state.rs:1446-1466 (drop only, no wait) | — | a re-create gets EEXIST. That is counted as a conflict and the whole reconcile aborts (Defect 3) |
| T9 never delete a replacement | CONFORMS | state.rs:1446-1466 | — | |
| T10 resolve name → index, SO_BINDTOIFINDEX, record index | PARTIAL | state.rs:652-669, 1227-1248 | privileged_bind_tunnel_interface_records_only_successful_binding (ignored) | SO_BINDTODEVICE by name with a before/after index check, so there is still a race window |
| T10 binding only ever set on a socket that has none | DEFECT | runtime.rs:1598-1608, 1655; state.rs:1405-1421, 1436-1444 | removed_bind_interface_is_rebound_when_it_reappears; reconcile_rebinds_when_bound_device_was_renamed_away (the mock models a forgotten binding as none, which hides it) | in-place rebind of a still-bound socket needs CAP_NET_RAW (K22). See Defect 1 |
| T11 follow the name; renamed away + nothing takes it → disconnect at once | DEFECT | runtime.rs:1598-1608 (only `forget_tunnel_binding`); state.rs:1353-1356 (reconnect returns before the disconnect when the name is missing) | privileged_reconnect_resolves_configured_name_after_rename_and_replacement asserts the socket is **still bound to the renamed device** (state.rs:2594-2605) | see Defect 2 |
| T11 another device takes the name → reconnect to it | PARTIAL | runtime.rs:1655-1678 | reconcile_rebinds_when_bound_device_was_renamed_away | in-place bind, then reconnect. Fails without CAP_NET_RAW (Defect 1) |
| T12 device disappears → disconnect, wait, bind + connect fresh; replacement detected by link event or resync | PARTIAL | runtime.rs:1717-1736, 1583-1620, 1218-1229 | removed_bind_interface_is_rebound_when_it_reappears; interface_resync_recovers_replacement_after_missed_removal | not disconnected: the socket keeps its dead ifindex, so the kernel sends nothing, but the daemon does not disconnect. Rebind is in place (Defect 1) |
| T13 absent at creation → created unbound **and disconnected**; never connected while unbound | DEFECT | runtime.rs:1319-1321, 2089-2113, 1350-1383; state.rs:1200 | reconcile_defers_missing_bind_interface_until_it_appears (asserts unbound, never checks connected) | Defect 4 |
| T14 real peer = literal, or the resolver's selected answer; none until then | PARTIAL | runtime.rs:2699-2714, 614-661 | reconcile_uses_discard_addr_for_unresolved_fqdn | no `resolver_name` and no configured resolvers (other auditor). Discard address instead of none |
| T15 changed answer applied in place; other family never applied | CONFORMS | runtime.rs:1156-1214, 649-661 | dns_family_retarget_keeps_the_new_family_answer_observable | |
| T15 unreachable new answer → disconnected, previous address not returned to | DEFECT | state.rs:1308-1318 (rollback), 1320-1325 (a failed bare connect keeps the old peer); runtime.rs:1193-1201 | — (mock does not model it) | Defect 5 |
| T16 transient, peer pending, retried every 1 s, warn once / info once, readiness not waiting | PARTIAL | runtime.rs:1449-1478, 1516-1576, 70 | unroutable_literal_peer_gets_a_discard_address_and_is_retried | connected to a discard address or the old peer, not disconnected. Readiness is blocked during the discard-route grace period (Defect 6) |
| T16 errno table classes | PARTIAL | runtime.rs:2206-2224 | — | the transient set matches. EAFNOSUPPORT/EPERM are not reported as daemon defects at error level: they abort the reconcile with a warn. `ScopeRequired` (link-local without zone) is treated as transient, but the spec says configuration mistake (T27) |
| T17 peer change to unreachable → disconnected, never the previous peer | DEFECT | state.rs:1308-1318; runtime.rs:1413-1421 (all candidates failed but still connected → `Ok`, left on the old peer) | a_peer_update_to_an_unroutable_address_uses_a_discard_address_meanwhile (mock only) | Defect 5 |
| T18 disconnected tunnels not reconnected for address events; leaving disconnected reselects source | CONFORMS | runtime.rs:1262-1265, 1856-1863; state.rs:1297-1309 | tunnels_without_a_peer_are_not_reconnected_for_address_changes | "disconnected" = connected to a discard address here |
| T19 bound: addr add/remove of its family on device or VRF member | CONFORMS | runtime.rs:1774-1798, 1868-1877, 2462-2472 | address_changes_match_effective_family_and_current_bindings; privileged_vrf_binding_selects_and_refreshes_slave_sources (ignored) | |
| T19 bound: VRF membership change of the bind device | PARTIAL | runtime.rs:1815-1824, 2388-2414 | controller_change_refreshes_only_a_verified_current_vrf_after_slave_deletion | only tunnels bound to the **controller** are refreshed. A tunnel bound to the enslaved device itself is not. Low impact: the source stays on the bound device |
| T19 unbound: own source removed | CONFORMS | runtime.rs:1235-1239, 1270-1274; state.rs:1159-1165 | removed_source_addresses_reconnect_the_unbound_tunnels_using_them | |
| T19 every connected tunnel on resync | CONFORMS | runtime.rs:1218-1229 | monitor_resync_refreshes_sources_without_interface_identity_changes | |
| T20 failed / unspecified-source reconnect → disconnected, peer pending, 1 s retry per device / one for unbound, stop on success, retry resolves name | PARTIAL | runtime.rs:1829-1920, 1246-1309; state.rs:837-862, 1366-1377 | local_address_change_retries_failed_reconnect_after_one_second; reconnect_retries_follow_replacement_interfaces_resolved_by_name; reconnect_retry_continues_when_event_precedes_sender_completion | timers conform. "Disconnected" is only the daemon's flag. After an unspecified-source verify failure the socket stays kernel-connected, and after a missing-name failure it keeps the old connection (Defect 2) |
| T21 reconnect = disconnect, bind to current index, connect; never shortened; siblings independent | PARTIAL | state.rs:1341-1380 (the three steps); state.rs:1320-1325 (a shortened bare connect) | privileged_reconnect_restores_binding_and_kernel_source (ignored) | the shape is right, but binding is by name, and an early return before the disconnect when the name is missing. Siblings independent: runtime.rs:1864-1867 |
| T22 remote_addr / ip_version / resolver_name / bind_interface / endpoint correction in place | PARTIAL | runtime.rs:885-918, 2546-2580 | plan_tunnel_changes_detects_add_delete_update_and_recreate | remote_addr/ip_version in place. bind_interface re-creates (gap the spec admits). resolver_name does not exist |
| T23 tunnel_id / peer_tunnel_id re-create | CONFORMS | runtime.rs:2564-2569 | plan_tunnel_changes_detects_add_delete_update_and_recreate | it also re-creates on bind_interface |
| T24 delete first, wait, create with sessions in the same reconcile; names reused | PARTIAL | runtime.rs:799-808, 821-883 | — | no wait (T8). An EEXIST right after the close aborts the reconcile, so the sessions come back ≥1 s later (Defect 3) |
| T25 1 s retries, 10 attempts, then left out with one warning; 30 s + reload retries; info on recovery; nothing else affected; counter reset on id change | DEFECT | runtime.rs:864-881, 1100-1107, 1489-1505, 1567-1574 | refused_identifiers_are_retried_then_left_out_until_a_retry_succeeds **asserts the defect** (runtime.rs:5830-5833: session 102 is not created during the first 9 attempts) | refusals 1-9 abort the whole reconcile (Defect 3). No info message on recovery (conflicts.remove is silent). Counter keyed by ids, which resets on an id change |
| T26 bindv6only: read IPV6_V6ONLY back, fix or fall back per ip_version | GAP | — (no IPV6_V6ONLY or `fix_bindv6only` anywhere in src/) | — | Defect 8 |
| T27 link-local: zone or bind_interface; zone/bind match; record the member index; unbound zone-less literal is a hard mistake | GAP | config.rs:1076-1097, 1337-1347 (`fe80::1` accepted unbound); runtime.rs:2220-2221 | remote_addr_must_be_unicast (asserts fe80::1 accepted) | no zone syntax (IpHost). A zone-less unbound fe80:: is retried forever as transient |
| T28 every peer change is a reconnect, never a bare connect; source read only after reconnect | DEFECT | state.rs:1320-1325 (`reconnect_ip` without disconnect on same-family change), 1159-1165 | privileged_ipv4_peer_update_and_source_reselection (ignored; asserts the source is **preserved** across a peer update, state.rs:2523-2526) | Defect 7 |
| T29 the daemon's own view says connected | PARTIAL | state.rs:807, 1385-1390; l2tp socket.rs:83-85 | — | the own view exists, but reports discard-connected tunnels as connected, and an unknown tunnel as connected |

### Hosts

| rule | verdict | evidence (file:line) | test | note |
|---|---|---|---|---|
| H1 dual-stack: AF_INET6, mapped IPv4, unreachable → disconnected, nothing else exists | GAP | runtime.rs:1997-2087; state.rs:1008-1111 | discard_route_is_prepared_only_for_tunnels_without_a_peer | discard address, plus a null device and routes when the host does not route the discard address |
| H2 IPv4-only host: IPv6 tunnel disconnected, reported once, sessions exist, no IPv6 config needed | DEFECT | runtime.rs:1323-1327, 2045-2068 | discard_address_falls_back_to_the_other_family (mock only; it does not exercise the grace abort) | `prepare_discard_route(100::)` fails during the 10 s grace, and that **aborts the whole reconcile** before the `192.0.0.8` candidate is tried. Then a dummy device gets an IPv6 route. Defect 6 |
| H3 disable_ipv6: IPv6 peer EADDRNOTAVAIL, disconnected | PARTIAL | same as H2 | — | same 10 s blockage. A null device is attempted, then the v4 discard address |
| H4 no IPv6 in kernel: AF_INET throughout | PARTIAL | state.rs:1180-1212; runtime.rs:2030-2044 | privileged_ipv4_sockets_use_native_endpoints_and_refuse_ipv6_peers (ignored) | works via the v4 discard address. The IPv6 discard route lookup fails, and every creation logs a warn |
| H5 IPv6-only host: IPv4 connect with 0.0.0.0 treated as failed | PARTIAL | state.rs:837-862 (reconnect only); state.rs:1214-1270 (creation never verifies, `connected: true`) | reconnect_verification_rejects_unspecified_local_endpoints | creation with source 0.0.0.0 counts as connected. UNTESTABLE-STATICALLY whether frames then leave with src 0.0.0.0. Test: IPv6-only netns plus an IPv4 default route via dev, check `ip l2tp show tunnel` and tcpdump |
| H6 no routes: everything created disconnected, readiness at once, connect by 1 s retry | DEFECT | runtime.rs:1323-1327, 2059-2068, 2069-2086, 1341-1345 | null_device_waits_for_the_host_to_route_the_discard_address (mock) | no session exists for ≥10 s (20 s when both families are needed). Without the `dummy` driver, **never**. Defect 6 |
| H7 VRF: table, source from VRF domain, member/membership reconnect, replacement rebind, non-VRF controllers not mistaken, member-bound routed by kernel | PARTIAL | state.rs:296-303, 966-982; runtime.rs:1774-1824 | vrf_classification_does_not_treat_other_controllers_or_ports_as_vrfs; controller_change_refreshes_only_a_verified_current_vrf_after_slave_deletion; privileged_vrf_binding_selects_and_refreshes_slave_sources (ignored) | non-VRF controllers are handled correctly. Replacement rebind is in place (Defect 1). An unreachable VRF default route gets the null device installed into the VRF table (GAP) |
| H8 no route notification subscription | DEFECT | runtime.rs:2255-2265 (`Ipv4Route`, `Ipv6Route`); netlink.rs:156-293 | monitor_filter_keeps_link_address_and_discard_route_removals_only | mitigated by the BPF filter. Without it (attach failure, netlink.rs:61-68) every route change is read |
| H9 non-initial netns, no bpf(), works under seccomp/userns | CONFORMS | netlink.rs:61-68 (classic SO_ATTACH_FILTER); l2tp handle.rs:141-160 | receive_buffer_tuning_is_bounded_and_needs_no_capability | procfs needed (NetNs::current), see H15 |
| H10 session children / moved devices | UNTESTABLE-STATICALLY | state/link_identity.rs (sessions scope) | — | sessions scope, not audited in depth |
| H11 networkd/udev: follow by index, never lower, defer MAC, publish staged | PARTIAL | state.rs:548-608, 742-759 | staged_session_preserves_activation_before_or_after_mac_change; hwaddr_change_on_an_up_device_is_deferred_until_it_is_down | the RA/accept_ra part is not implemented (resolvers absent) |
| H12 other L2TP user → conflicts, foreign objects untouched, foreign name delays publication | PARTIAL | runtime.rs:2227-2240; state.rs:1446-1466 | refused_identifiers_are_retried_then_left_out_until_a_retry_succeeds; session_rename_skips_foreign_temporary_names | conflict handling: Defect 3 |
| H13 hot-plug followed by name | PARTIAL | runtime.rs:1583-1736 | removed_bind_interface_is_rebound_when_it_reappears | unplug does not disconnect. Plug rebinds in place (Defect 1) |
| H14 address churn: only bound/family-matching connected tunnels; unbound on own source; disconnected never; disconnect+connect; 1 s retry | CONFORMS | runtime.rs:1774-1920, 1246-1309 | address_changes_match_effective_family_and_current_bindings; address_and_vrf_notifications_do_nothing_without_bound_tunnels; tunnels_without_a_peer_are_not_reconnected_for_address_changes | |
| H15 no modules / CAP_NET_ADMIN / netlink: report once, retry 1 s, withhold readiness, never exit; procfs missing = host defect | DEFECT | runtime.rs:721-724; state.rs:914-926; service.rs:139, 178-181; main.rs:1147 | — | `State::new()` failure (no procfs for `NetNs::current`, or a netlink socket failure) propagates out of `Service::new` and the daemon **exits**. Missing modules or privilege are retried, but warned every second ("will retry"), not once. Defect 9 |
| H16 monotonic timers, resync after suspend | CONFORMS | runtime.rs:1299-1306, 1531-1535; service.rs:261-262 (tokio Instant = CLOCK_MONOTONIC) | — | suspend behaviour UNTESTABLE-STATICALLY |
| H17 hundreds of entries; event cost bounded by the entries it concerns; no interface dumps except seeding | PARTIAL | runtime.rs:1774-1798 (with ≥1 bound tunnel, every address event on **any** interface opens a new rtnetlink socket via `Rtnl::connect` and makes 1-2 link queries, state.rs:970-982); state.rs:390 (null-device full dump) | — | M16 says events that concern no entry need no kernel query |
| H18 bindv6only fixed or per-family fallback | GAP | — | — | Defect 8 |
| H19 non-systemd, musl | UNTESTABLE-STATICALLY | main.rs:1132 (unix_daemon) | — | process scope; build with `--target x86_64-unknown-linux-musl` to test |

### Kernel (requirements and facts as the code uses them)

| rule | verdict | evidence (file:line) | test | note |
|---|---|---|---|---|
| K1-K3 l2tp_core/netlink, l2tp_ip, l2tp_eth | CONFORMS | l2tp crate | privileged_* | |
| K4 l2tp_ip6 only when needed, else AF_INET | PARTIAL | state.rs:1180-1212 | privileged_ipv4_sockets_use_native_endpoints_and_refuse_ipv6_peers (ignored) | sticky fallback (T4) |
| K5 unconnected registered socket drops frames | GAP | l2tp socket.rs:300-305 | — | not used: every socket is connected |
| K6 connect / disconnect / reconnect | CONFORMS | l2tp socket.rs:597-621, 718-746; state.rs:1341-1380 | privileged_reconnect_restores_binding_and_kernel_source (ignored) | |
| K7 link+addr groups, generic netlink, **no route group** | DEFECT | runtime.rs:2256-2262 | — | H8 |
| K8 CAP_NET_ADMIN only | DEFECT | runtime.rs:1655; state.rs:1061-1111 | — | an in-place rebind needs CAP_NET_RAW (Defect 1). The null device needs the `dummy` driver and route writes |
| K9 VRF | CONFORMS | state.rs:652-669 | privileged_vrf_binding_selects_and_refreshes_slave_sources (ignored) | |
| K10 classic BPF filter optional | CONFORMS | netlink.rs:58-68, 166-293 | monitor_filter_keeps_link_address_and_discard_route_removals_only | |
| K11 bindv6only=0 needed only for mapped IPv4 | GAP | — | — | T26 |
| K12 procfs for namespace identity | PARTIAL | l2tp handle.rs:147 | — | missing → exit (H15) |
| K13, K14, K39, K40, K38 resolver requirements/facts | GAP | — | — | no resolvers beyond iphost (resolver auditor) |
| "Not required" list: dummy, routes, route lookups, route groups, CAP_NET_RAW; MUST NOT depend | DEFECT | state.rs:72-126 (`routes()` lookup), 166-199, 1008-1111; runtime.rs:1997-2087, 2256-2262 | — | depends on all of them. Without dummy and without routes nothing is ever created (Defect 6) |
| K15 delivery by session id, cookies only check | n/a | — | — | sessions scope |
| K16 creation ifname copy | n/a here | state.rs:732-740 | — | sessions scope |
| K17 async tunnel deletion | PARTIAL | state.rs:1446-1466 | — | the code does not wait (T8) |
| K18 session deletion sync/async | n/a | — | — | sessions |
| K19 per-ns registries, EEXIST | CONFORMS | runtime.rs:2227-2240 | refused_identifiers_… | |
| K20, K21 | n/a | — | — | nothing in this scope depends on them |
| K22 rebinding a bound socket needs CAP_NET_RAW; disconnect clears | DEFECT | runtime.rs:1655 → state.rs:1405-1421 on a socket left bound by state.rs:1436-1444 | — | Defect 1 |
| K23 IPV6_V6ONLY readable, not writable; mapped connect ENETUNREACH | GAP | — | — | no readback |
| K24 connect keeps the source; cross-family EAFNOSUPPORT | PARTIAL | state.rs:1297-1309 (disconnect across families); 1320-1325 (bare same-family) | privileged_ipv4/ipv6_peer_update_and_source_reselection (ignored) | Defect 7 |
| K25 disconnected record shows the previous peer | CONFORMS | l2tp socket.rs:798-811 (own `connected` flag) | — | |
| K26 errno classes | CONFORMS | runtime.rs:2206-2224 | — | |
| K27 link-local scope binds to the zone device | GAP | — | — | T27 |
| K28 bound-device routing | n/a | — | — | kernel behaviour |
| K29 overrun once, filter drops replies | CONFORMS | runtime.rs:2318-2337, 2452; netlink.rs:189-196 (control msgs accepted) | — | |
| K30 unicast needs CAP_NET_ADMIN | CONFORMS | runtime.rs:2305-2315 (port 0 only) | — | |
| K31-K33, K35 | n/a | — | — | sessions/config scope |
| K34 IPv4 0.0.0.0 / IPv6 EADDRNOTAVAIL | PARTIAL | state.rs:837-862 | reconnect_verification_rejects_unspecified_local_endpoints | not checked at creation (H5) |
| K36 SO_RCVBUFFORCE tried, fallback | CONFORMS | netlink.rs:90-125 | receive_buffer_tuning_is_bounded_and_needs_no_capability | |
| K37 descriptor hand-over | GAP | — | — | process scope |

### Defects

1. **In-place rebind of a still-bound socket: permanent stall without CAP_NET_RAW.** Confidence: high.
   - Location: runtime.rs:1598-1608, 1717-1736, 1655; state.rs:1405-1421, 1436-1444.
   - Code: when the bind device is renamed away or removed, `forget_tunnel_binding` only marks the record invalid. The kernel socket keeps `sk_bound_dev_if`: the old device, or the dead index. When a device of the configured name appears, `handle_interface_change` calls `bind_tunnel_interface` → `SO_BINDTODEVICE` on that still-bound socket.
   - Kernel: `sock_bindtoindex_locked` returns `EPERM` without `CAP_NET_RAW` (K22).
   - Scenario: a daemon running with only `CAP_NET_ADMIN`, a static literal peer, `bind_interface = "vrf-a"`; the VRF is deleted and re-created. Every interface event logs "failed to bind … Operation not permitted". Nothing recovers it:
     - `reconnect_disconnected_tunnels` skips it, because `bound_interface_index` is None while the binding is invalid.
     - `reconnect_unbound_tunnels` skips it, because `tunnel_is_bound` is true.
     - No peer retry is pending.
   - The tunnel stays bound to the dead index forever, until a peer change or a restart.
   - The mock models a forgotten binding as "unbound", so `removed_bind_interface_is_rebound_when_it_reappears` passes. The privileged tests run as root.
2. **Renamed-away bind device keeps carrying traffic.** Confidence: high.
   - Location: runtime.rs:1598-1608; state.rs:1353-1356.
   - Scenario: the bind device `eth1` is renamed to `old1` and nothing takes `eth1`. The daemon only invalidates its record. Any `reconnect_tunnel_to` returns at the name check *before* the disconnect.
   - Outcome: the socket stays bound to `old1` and connected to the peer, so the sessions keep sending through a device the configuration no longer names. Meanwhile the daemon's own flag says disconnected (`connected=false`), so T29/O9 shows a lie.
   - This contradicts T11 and T13. `privileged_reconnect_resolves_configured_name_after_rename_and_replacement` asserts exactly this state (state.rs:2596-2605).
3. **Conflict refusals 1-9 abort the whole reconcile.** Confidence: high.
   - Location: runtime.rs:864-881, 1100-1107.
   - Mechanism: `note_conflict` returns false below 10. The match guard then fails and the generic `Err(e)` arm returns from `reconcile`.
   - Scenario: one session id is held by `ip l2tp`. For about 9 s:
     - no later tunnel (BTreeMap order) is created;
     - no tunnel update is applied;
     - no session of any tunnel is added (sessions run after all tunnels).
   - Readiness is withheld throughout. The same happens on every tunnel re-creation (T23/T24): the closed socket's tunnel id is still registered (K17), so EEXIST blocks the sessions of the entire configuration until the next tick.
   - This violates T25 "nothing else is affected" and M4. The unit test codifies it (runtime.rs:5830-5833).
4. **A device-bound tunnel is connected while unbound.** Confidence: high.
   - Location: runtime.rs:1319-1321, 2089-2113, 1350-1383.
   - Code: when `bind_interface` is absent at creation, or vanishes between the lookup and the bind, the socket is created **unbound and connected to the real peer**.
   - Scenario: `bind_interface = "vrf-blue"` and the VRF is created after the daemon starts at boot. The tunnel connects through the **main** table, and the sessions' frames leave via the default route, outside the VRF, until the VRF appears.
   - This violates T13 ("never connected while unbound") and T1.
5. **Peer change to an unreachable address stays on (or returns to) the previous peer.** Confidence: high.
   - Location: state.rs:1308-1318 (explicit rollback to `previous_remote`), state.rs:1320-1325 (a failed bare connect leaves the old connection in place), runtime.rs:1193-1201 (DNS path, no discard fallback), runtime.rs:1413-1421 (reload path returns `Ok` while still on the old peer).
   - Scenario: the resolver's answer changes from A to B and B has no route. The tunnel keeps sending to A, which the resolver no longer names, and logs "connected to A meanwhile".
   - This violates T15 and T17.
6. **Discard-route grace period blocks everything, and the daemon depends on the `dummy` driver and routes.** Confidence: high.
   - Location: runtime.rs:1323-1327, 2045-2068, 2069-2086, 1341-1345.
   - Code: `prepare_discard_route` returns `Err` during the 10 s grace, and `?` in `create_tunnel` aborts the whole reconcile. The other family's discard candidate is never tried.
   - Scenario A, a host at boot with no routes (H6): no tunnel and no session exists for 10 s, or 20 s when the second family's grace starts afterwards.
   - Scenario B, the same host without the `dummy` module (e.g. a container that cannot load modules): `route_discard_to_null_device` fails, the connect fails, all candidates fail, and the reconcile errors on every tick. **No session interface ever exists** until a route appears.
   - Scenario C, an IPv4-only host with one IPv6 tunnel whose peer is unreachable (H2): every other entry waits 10 s, then a dummy device appears with an IPv6 route.
   - This contradicts H2, H6 and the K "MUST NOT depend" list.
7. **Bare connect on same-family peer changes keeps a stale source.** Confidence: medium-high.
   - Location: state.rs:1320-1325.
   - Scenario: peer A is reached through eth0 (source S0) and the new peer B is routed via eth1. `reconnect_ip(B)` without a disconnect keeps S0 (K24). Frames to B carry eth0's address, and peer or uRPF filtering may drop them.
   - This violates T21 and T28. The privileged test asserts the source is preserved (state.rs:2523-2526).
8. **bindv6only=1 breaks every IPv4 tunnel.** Confidence: high.
   - Location: no handling anywhere in src/.
   - Mechanism: a connect to the mapped peer fails `ENETUNREACH` (K23), which counts as transient, as does the mapped v4 discard address. The tunnel falls back to the `100::` discard address, its peer stays pending forever, and a warning says "cannot reach its peer". The real cause, IPV6_V6ONLY, is never mentioned.
   - Gap against T26 and H18, with this concrete failure.
9. **Start-up exits instead of degrading.** Confidence: medium.
   - Location: runtime.rs:721-724 → service.rs:139 → main.rs:1147.
   - Code: `State::new` (`L2tpHandle::new` → `NetNs::current()`, which needs procfs, plus `LinkIdentityMonitor::new`) failing makes the daemon exit with an error. H15 wants this treated as a host defect: retry every second, never exit.
   - Separately, missing modules or privilege surface as a reconcile error warned **every second** (service.rs:181, 278), not once (M13).
10. **AF_INET fallback is sticky.** Confidence: medium.
    - Location: state.rs:1206, 929-935.
    - Scenario: one `EPROTONOSUPPORT` (l2tp_ip6 not yet loadable at boot) switches every later tunnel to AF_INET for the process lifetime. T4 requires probing again at each creation. Tunnels created later can never have IPv6 peers or move families, even after the module loads.
11. **A tunnel connected at creation with an unspecified source counts as connected.** Confidence: low-medium.
    - Location: state.rs:1214-1270.
    - Code: only reconnects run `verify_reconnected_endpoint`. A creation-time IPv4 connect on an IPv6-only host succeeds with 0.0.0.0 (K34) and is recorded `connected: true`. Unbound tunnels are not reconnected on address *additions* (T19), so it is never re-evaluated until a resync.
    - Needs a live test to tell what is sent (H5).
12. **Per-event netlink socket churn.** Confidence: medium; cost, not correctness.
    - Location: runtime.rs:1785, state.rs:970-982.
    - Code: with any bound tunnel, every address notification on any interface creates a fresh rtnetlink connection (spawned task + socket) for `interface_vrf_master`. That breaks M16/H17 ("no kernel query for events that concern no entry"). On a router with RA/privacy churn this is one socket per notification.

## Audit 2: sessions.md (S) and model.md (M) against the code

Scope: `docs/spec/sessions.md`, `docs/spec/model.md`. Code read: `src/state.rs`, `src/state/link_identity.rs`, `src/runtime.rs`, `src/service.rs`, the relevant parts of `src/config.rs`, and `l2tp` 0.4 (`/home/dev/l2tp-rs/src/handle.rs`, `session.rs`).
Method: static reading. Two defects were confirmed with throwaway mock tests in a scratch copy of the repo (`.../scratchpad/repo`, `cargo test --lib audit_probe`). No repo file was changed.

Line numbers refer to the working tree at `741117b`.

### Rule-by-rule

| rule | verdict | evidence (file:line) | test | note |
|---|---|---|---|---|
| Terms: owned object (session through its creation-time name) | CONFORMS | state.rs:732-740 `kernel_session_is_ours` | none by name | Matches the definition, but see D7 (any lookup error reads as "not ours"). |
| Terms: eligible / ready | PARTIAL | runtime.rs:1100-1106, 1489-1505, service.rs:178-179 | `refused_identifiers_are_retried_then_left_out_until_a_retry_succeeds` | A session whose *name* is taken by a foreign device is classed as an identifier conflict (D2), so after 10 attempts it leaves the eligible set and readiness is reported without it. |
| S1 right state | PARTIAL | composite | — | Fails where S4/S7/S11/S27 fail. |
| S2 never changes admin state / addrs / routes | CONFORMS | state.rs:484-501, 548-580, 586-608 (only `name` and `address` are set; no flags) | `staged_session_preserves_activation_before_or_after_mac_change`, `hwaddr_change_on_an_up_device_is_deferred_without_touching_it` | |
| S3 creation params (ids, cookies, no seq, no L2-specific sublayer, explicit name without `%`, independent of connected) | DEFECT | state.rs:1613-1626 (params OK); config.rs:675-676 accepts any `L2tpIfName`, which allows `%` (netlink-packet-l2tp 0.4 test.rs:661 lists `l2tpeth%d` as a valid name) | `privileged_session_cookies_are_applied` (cookies only) | D10: `interface_name = "l2tp%d"` reaches the kernel, which expands it. Creation does not depend on the connected state: CONFORMS. |
| S4 every session staged, temporary name random and pre-checked, one creation path | DEFECT | state.rs:1647 `create_session_handle(config, hwaddr.is_some())`, 1740-1757 (unstaged path), 338-345 (temp name = counter + pid, not random; not checked before creation, only after EEXIST at 1771-1773) | `staged_session_*` only cover the staged path | D2. A session without `interface_hwaddr` is created directly under its configured name. |
| S5 never lower an early-activated temp device; publish anyway | CONFORMS | state.rs:553-554, 564, 595-606 | `staged_session_preserves_activation_before_or_after_mac_change` | |
| S6 failed staging/publication keeps session and device; removed only on leave/param change/identity loss | CONFORMS | state.rs:1629-1638, 1470-1485, 1678-1682 | `privileged_staged_session_retains_children_across_publication_failures`, `failed_session_rollback_retains_ownership_until_a_successful_retry`, `pending_session_is_resumed_and_parent_teardown_removes_it` | The retry itself aborts the reconcile (D3). |
| S7 id conflict → T25; configured name held by a foreign device → transient, retried every second, kept under temp name; temp name taken → pick another | DEFECT | runtime.rs:2227-2240 (EEXIST is always a conflict); state.rs:1740-1756; runtime.rs:1107 | none for the name-occupied case | D2 (unstaged: conflict misclassification), D3 (staged: the whole reconcile aborts). Temp name taken → another is picked: CONFORMS (state.rs:1759-1776). |
| S8 address by index, captured from the registration broadcast via a subscription opened before creation | CONFORMS | state.rs:1765 arm before create; link_identity.rs:155-177 capture; 461-482 cross-check with l2tp `ifindex()` (l2tp-rs handle.rs:286-345) | `only_a_new_device_captures_creation_and_renames_preserve_identity`, `privileged_modify_session_renames_by_index` | The l2tp fallback looks the index up by name if the broadcast was lost (handle.rs:357-381), and the recover path accepts it only if the name still matches. |
| S9 proof: no removal seen + same-socket lookup ordered after queued notifications; per generation; minimal interval | CONFORMS / UNTESTABLE-STATICALLY | link_identity.rs:400-428, 369-383; state.rs:493, 560, 599 (`verify_identity` just before each SETLINK) | `deletion_and_index_reuse_never_adopt_a_replacement` | Live test: rename and delete the device between the lookup and the SETLINK. Each operation opens a fresh rtnetlink socket (state.rs:237-243). That costs time but does not affect correctness. |
| S10 follow the device, accept overrides, a later rename applies by index, a foreign-held target is transient, up devices can be renamed | PARTIAL | state.rs:1805-1831, 484-501; runtime.rs:1004-1009 | `privileged_modify_session_renames_by_index`, `reconcile_handles_interface_name_swap` | Nothing re-asserts the name: CONFORMS. A foreign-held target name becomes an `Err` through `try_apply!`, which aborts the whole reconcile (D3). |
| S11 swaps and taking a removed session's name, through `rsl2tp-r` temp names under M6; collision batch advances | DEFECT | runtime.rs:960-1021 (renames) run before 1057-1066 (deletions); 2619-2651 | `reconcile_handles_interface_name_swap`, `session_rename_skips_foreign_temporary_names`, `temporary_name_collision_batches_advance_across_retries` | D1 (confirmed). The swap and the collision batch CONFORM; "a removed session's name may be taken by a surviving one" livelocks. |
| S12 never lower; apply when down, defer when up; readiness doesn't wait; deferral reported once, application once; no re-assertion | PARTIAL | state.rs:548-580, 1850-1887; runtime.rs:1685-1713, 941-948, 1041, 2524-2532 | `hwaddr_change_on_an_up_device_is_deferred_until_it_is_down`, `renamed_session_link_events_apply_pending_hwaddr_without_disturbing_up_siblings`, `privileged_session_hwaddr_is_applied_changed_and_restored` | Mechanism CONFORMS. The deferral is logged again on every reconcile (every reload, every 1 s retry, every 30 s conflict retry), because pending sessions are re-added to `to_set_hwaddr` (941-948) and `log_deferred_hwaddr` runs each time (1041). |
| S13 an unusable address is tolerated; the device keeps the kernel address; a corrected value applies in place | PARTIAL | config.rs:85-97 (multicast and zero rejected at load); state.rs:565-569, 595, 1048 | `hwaddr_change_reports_kernel_failures` | A kernel refusal at apply time is a hard `Err`: the reconcile aborts, and a staged session is never published (it stays under `rsl2tp-t…`). This only matters if the kernel refuses a valid unicast address. |
| S14 cookies off unless configured; directionality | CONFORMS | state.rs:512-516, 1619-1620 | `privileged_session_cookies_are_applied`, `cookie_changes_recreate_the_session` | Note for the config auditor: config.rs:2184 "peer_cookie defaults to cookie". |
| S15 cookie change re-creates; new device under the configured name once the old is gone; refusal meanwhile is a transient conflict | PARTIAL / UNTESTABLE-STATICALLY | runtime.rs:2593-2600, 1057-1112; state.rs:1889-1937 | `cookie_changes_recreate_the_session` | There is no wait for the old device. On ≥ 6.11 (asynchronous deletion, K18) the new creation can hit EEXIST, which is counted and aborts the reconcile (D3). It converges by retry. Live test on 6.11+ needed. |
| S16 cookies never logged | CONFORMS | config.rs:242-246 (`Debug` redacts); runtime.rs:2515-2522 | `cookie_parsing_and_rendering` (Debug) | `Display` prints the value, but no log in my area uses it. |
| S17 name/hwaddr and in-place tunnel changes keep the session; ids/cookies/tunnel_name re-create | DEFECT | runtime.rs:2582-2617 (session side OK); 2564-2565 (tunnel `bind_interface` change → delete + add) | `plan_session_changes_detects_modify_recreate_add_delete_and_hwaddr`, `plan_tunnel_changes_detects_add_delete_update_and_recreate` (encodes the wrong behaviour?) | D4. The session-side rules CONFORM. "Anything about the tunnel that changes in place" does not: a `bind_interface` change re-creates the tunnel and every session on it. |
| S18 children never managed; in-place ops keep the parent | PARTIAL | no child logic anywhere (OK) | — | Broken by D4 (a bind change destroys parents and children) and D1 (the surviving device is renamed to a new temp name every second). |
| S19 observed removal vs notification loss told apart; loss on the event monitor alone ends nothing | CONFORMS | link_identity.rs:44-61, 179-199, 202-215, 375-381; runtime.rs:2242-2348 (separate socket) | `monitor_loss_invalidates_existing_and_uncaptured_watches`, `deletion_and_index_reuse_never_adopt_a_replacement` | |
| S20 unmanageable: skip, record as applied, report once; reload completes | CONFORMS | state.rs:1555-1574, 1821-1827, 1866-1874; runtime.rs:984-1020, 1042-1054 | `unmanageable_sessions_do_not_keep_other_changes_from_being_applied` | |
| S21 after an observed removal, forget without deleting; a refused re-creation is a conflict | CONFORMS | state.rs:1901-1919 (`Deleted` → forget) | none by name | |
| S22 after a loss, delete iff the kernel reports the creation-time name, **by `L2TP_ATTR_IFNAME`** (check + delete in one operation) | DEFECT | state.rs:1906-1910 + 1921-1926, 1514-1520, 1539-1546: check by `get(ids)`, then `delete_session(ids)` | none | D7. `l2tp` 0.4 has `delete_session_by_ifname` (l2tp-rs handle.rs:634-642), but it is unused. The check and the delete are two operations, and a failed check silently leaks the session. |
| S23 a staged session that can't be proved: re-identify at the broadcast index if it still bears the temp name in the current generation; otherwise delete via S22 and re-create at most once | PARTIAL | link_identity.rs:434-453, 461-482; state.rs:1642-1687, 1712-1714 | none by name (`pending_session_is_resumed_and_parent_teardown_removes_it` is adjacent) | Re-identification happens only when the identity was never captured. If it was captured and then lost (state.rs:1712), the session goes straight to delete + re-create. The S22 deletion part inherits D7. |
| S24 never modify a device reusing a former session index after a loss | CONFORMS | link_identity.rs:93-103, 188-199 (old identities stay invalid; reseeded entries are new objects) | `deletion_and_index_reuse_never_adopt_a_replacement` | |
| S25 removal with proof; already-gone counts as success | CONFORMS | state.rs:870-883, 1889-1937 | `deletion_result_treats_acknowledged_deletions_as_complete` | |
| S26 delete provable sessions before their tunnel | DEFECT | runtime.rs:799-808 (tunnels deleted first; their sessions dropped from `applied_session_specs` and never deleted); state.rs:1446-1466; shutdown runtime.rs:1975 | none | D5. This also applies to shutdown (P16). |
| S27 re-create a session deleted in the kernel by an operator | GAP | runtime.rs:1717-1736 (`InterfaceRemoved` handles bind devices only) | — | The spec itself calls this a known gap. |
| M1 reconciler | CONFORMS | runtime.rs:772-1129 | many | |
| M2 idempotent for converged entries; pending work retried on every reconcile | CONFORMS | runtime.rs:2582-2617, 941-948, 1100-1106 | `unchanged_reload_preserves_dns_changes_inflight_events_and_retries` | Converged sessions are untouched. |
| M3 keep partial progress | CONFORMS | runtime.rs:778-790, 979-982 | `reconcile_persists_partial_apply_on_failure` | |
| M4 entries independent; only a tunnel takes its sessions | DEFECT | runtime.rs:802, 811-815, 873-881, 907, 961-977, 1004-1009, 1048, 1063, 1107 (every non-conflict `Err` returns from `reconcile`) | `reconcile_persists_partial_apply_on_failure` asserts the abort | D3 (confirmed): one failing session stops every later session, tunnel failures stop unrelated tunnels, and a conflicting entry aborts the reconcile for its first 9 attempts. |
| M5 triggers: start, reload, 1 s retry, 30 s left-out retry; events run handlers only | CONFORMS | service.rs:170-198, 256-339; runtime.rs:1540-1576 | `refused_identifiers_are_retried_then_left_out_until_a_retry_succeeds` | |
| M6 ordering: child before parent; release before claim; independent ops independent | DEFECT | runtime.rs:799-808 vs 1057; 990-1021 vs 1057 | none | D1, D5. The code's order is: tunnel delete → tunnel add/update → temp renames → final renames → hwaddr → session delete → session add. Final renames come before the deletions that release names. |
| M7 degradation ladder | PARTIAL | — | — | Rung 4 (unmanageable skip) and rung 5 (left-out conflict) CONFORM. Rung 3 "temporary name while the configured name is held": unstaged sessions have no temporary name (D2), and staged ones block the reconcile (D3). Rung 2 (S13) is partial. Tunnel rungs are for the tunnels auditor. Rung 3 "disconnected" is implemented as a connect to a discard address (runtime.rs:1426, 2190), which is the retired design. |
| M8 moving down never changes identity; moving up in place without a reload | PARTIAL | — | — | A bind-device change re-creates (D4). Promotion when a foreign name holder leaves happens only by the 1 s full-reconcile poll, not by the DELLINK notification. |
| M9 never modify/delete/adopt foreign objects | PARTIAL | state.rs:1514-1520, 1906-1926 | — | Weakened by D7 (non-atomic check then delete) and by D2: unstaged sessions use the configured name as their creation-time name, which defeats the premise of S22 that matching needs "deliberate imitation". An operator re-creating a session by hand with the same ids and the natural name would be deleted. |
| M10 proof after the last event before each change; minimal interval | CONFORMS | state.rs:493, 560, 599, 1904 | — | |
| M11 session interface identity kept except by matrix operations | DEFECT | runtime.rs:2564-2565 | — | D4 (bind-device change). |
| M12 tunnel socket kept except by matrix operations | DEFECT | runtime.rs:2564-2565 | — | D4. The socket-family part is for the tunnels auditor. |
| M17 r1: remote_addr, ip_version, resolver_name, bind_interface, peer/source/connected → kept/kept | DEFECT + GAP | runtime.rs:2564-2576; config has no `resolver_name` and no `resolvers` map | `plan_tunnel_changes_detects_add_delete_update_and_recreate` | D4 for `bind_interface`. `resolver_name` and resolvers are not built (GAP). remote_addr and ip_version are in place: CONFORMS. |
| M17 r2: interface_name/hwaddr, or rename/address by another manager → kept | CONFORMS | runtime.rs:2602-2607; no re-assertion code | `plan_session_changes_…`, `renamed_session_link_events_…` | |
| M17 r3: tunnel_id/peer_tunnel_id → both re-created | CONFORMS | runtime.rs:2564, 807, 2610-2614 | `plan_tunnel_changes_…` | |
| M17 r4: session_id/peer_session_id/cookies/tunnel_name → session re-created, socket kept | CONFORMS | runtime.rs:2593-2600; keyed by (tunnel_id, session_id) at 2781 | `cookie_changes_recreate_the_session` | |
| M17 r5: a tunnel or session entry renamed in the configuration → re-created | DEFECT (low) | runtime.rs:2735, 2781 (keyed by ids, not by configuration name) | none | D9. Renaming a config entry with the same ids is a no-op. |
| M17 r6: removed entry / shutdown → removed | CONFORMS | runtime.rs:793-808, 1057-1066, 1975 | `reconcile_removes_resolver_for_deleted_tunnel` | The order is wrong (D5). |
| M17 r7: session deleted by an operator → re-created | GAP | — | — | Same as S27. |
| M17 r8: staged identity lost → re-created at most once per attempt | CONFORMS | state.rs:1642-1687 | none by name | |
| M17 r9: socket family change → kept until re-created for another reason | PARTIAL | state.rs:813-818, 929-935 (AF_INET fallback is global, existing sockets kept) | — | T26/bindv6only is not built. Tunnels auditor. |
| M17 r10: restart without hand-over → removed and re-created | CONFORMS | (kernel K17 on process exit) | — | |
| M17 r11: restart with descriptor hand-over → kept | GAP | no SCM_RIGHTS or LISTEN_FDS code | — | |
| M18 generations: proofs per generation; event-monitor loss ends none | CONFORMS | link_identity.rs:188-199, 343-363, 400-428; runtime.rs:2452 | `monitor_loss_invalidates_existing_and_uncaptured_watches` | The new generation opens lazily, at the next arm or finish (link_identity.rs:385-398). Validation while closed reports `Lost`, which is correct. |
| M19 configured / deferred / skipped / override; a config change clears; removing hwaddr restores the creation address under deferral | CONFORMS | state.rs:747-756, 1850-1887; runtime.rs:1016-1020, 1050-1054, 2602-2607 | `reconcile_applies_changes_and_removes_session_hwaddr`, `reconcile_retries_failed_hwaddr_change_without_repeating_rename` | Low-confidence edge: while a value is *deferred*, a manager-set address is overwritten when the device goes down, because there is no override detection during deferral. |
| M13 transient: retried 1 s; warned at most once per episode | DEFECT | service.rs:181, 278 (warn on every failed retry); runtime.rs:1703 | none | D6. |
| M13 lasting conflict: bounded retries, then left out, slow retry and on reload | PARTIAL | runtime.rs:1489-1512, 1567-1574 | `refused_identifiers_are_retried_then_left_out_until_a_retry_succeeds` | The bounded and slow retries CONFORM. During the first 9 refusals the whole reconcile aborts (D3). Name collisions are misclassified as conflicts (D2). |
| M13 unmanageable | CONFORMS | as S20 | as S20 | |
| M13 host defect: retried 1 s, reported once, readiness withheld; resolver-only withholds nothing | PARTIAL | service.rs:170-198 | — | Readiness is withheld (converge loops), but the defect is reported every second (D6). Resolver-only defects: GAP. |
| M13 configuration mistake at load time | n/a (config auditor) | — | — | |
| M13 defect of the daemon at error level | GAP | no `error!` in runtime.rs or state.rs | — | |
| M14 monotonic clock; fixed-delay timers | PARTIAL | service.rs:261-262 (`tokio::time::interval`, `Skip`) | — | Tokio uses CLOCK_MONOTONIC: CONFORMS. The retry is fixed-rate, not fixed-delay. The interval's first tick is immediate, so the first retry after a failed reload runs at once, and later retries are aligned to the interval, not 1 s after the previous attempt. |
| M14 table: reconcile retry 1 s / conflict 10 / left-out 30 s | CONFORMS | service.rs:25; runtime.rs:68, 72 | `refused_identifiers_…` | |
| M14 table: wait up to 2 s for a deleted tunnel to leave the kernel | GAP | state.rs:1446-1466 (only drops the socket) | — | Re-creating the same `tunnel_id` in the same reconcile then hits EEXIST (K17 workqueue), which is counted as a conflict and aborts the reconcile (D3). |
| M14 other rows (reconnect, resolver, tunables) | — | — | — | Tunnels, resolvers and process auditors. |
| M15 notify not poll; no tight loops; bounded timers | CONFORMS | runtime.rs:692, 712, 1516-1536 | — | There is an extra timer for the retired discard routes (runtime.rs:701, 1944-1958). |
| M16 cost per event bounded by entries concerned; unrelated events cost a comparison, no kernel query; lookup not scan; memory bounded by config | PARTIAL | runtime.rs:1583-1589, 1685-1713; state.rs:1034-1057; link_identity.rs:127-177, 243-247 | `address_and_vrf_notifications_do_nothing_without_bound_tunnels` | D8. |

#### Verdict counts (rows above)

There are 65 counted rows; the "M14 other rows" line is not counted. CONFORMS 29, PARTIAL 16, DEFECT 14, GAP 6. M17 r1 counts as both DEFECT and GAP. UNTESTABLE-STATICALLY appears twice, as a co-verdict on S9 and S15. n/a 1.

### Defects

1. **D1. A surviving session renamed to a removed session's name livelocks (high, confirmed).**
   - Code: runtime.rs:990-1021 do the final renames before runtime.rs:1057-1066 delete sessions. A rename failure goes through `try_apply!` and aborts the reconcile.
   - Scenario: session A is `l2tpa`, session B is `l2tpb`. A reload removes A and renames B to `l2tpa`, which S11 explicitly allows.
     - Phase 1 renames B to `rsl2tp-r000000`.
     - Phase 2 renames B to `l2tpa` and gets EEXIST, because A's device still exists.
     - The reconcile aborts before A is deleted. Every 1 s retry repeats this.
   - Outcome: A is never deleted, B never gets its name, and B is renamed to a fresh temp name every second (`rsl2tp-r000001`, `…02`, …). Managers that match on names see the device flap.
   - Confirmed with a mock probe in the scratch copy: 5 attempts all fail with `interface exists: l2tpa`, and B's name advances each time.
   - Fix: delete sessions (and send renames to temp names) before final renames and creations, as M6 says.

2. **D2. Sessions without `interface_hwaddr` are not staged, so a configured name held by a foreign device is misclassified as an identifier conflict (high).**
   - Code: state.rs:1647 and 1740-1757 create the session directly under the configured name. The kernel refuses with EEXIST (K20), and runtime.rs:2227-2240 counts any EEXIST as a conflict.
   - Scenario: a foreign `l2tp0` exists and the configured session `interface_name = "l2tp0"` has no hwaddr.
     - Attempts 1-9 abort the whole reconcile (D3).
     - At attempt 10 the session is left out with the false warning "another tunnel or session on this host holds [its identifiers]".
     - The reconcile returns Ok, so `converge` reports ready without the interface.
     - It is then retried only every 30 s.
   - Spec: S4 (every session staged, one creation path) and S7 (transient, retried every second, kept under a temp name).
   - Side effect: it also undermines the S22 premise (see M9).
   - The temporary name also comes from counter + pid rather than a random source, and is not checked before use (state.rs:338-345). That last part is minor.

3. **D3. Any non-conflict error aborts the whole reconcile (high, confirmed).**
   - Code: `try_apply!` at runtime.rs:802, 811-815, 877-880, 907, 961, 973, 1004, 1048, 1063, 1107. It also catches conflict errors while the count is below 10 (1100-1107).
   - Scenarios:
     - (a) The first session in key order fails staging or publication, for example because its configured name is held by a foreign device (S7, transient). Every later session is never created, for as long as the foreign device stays, and readiness is withheld for all of them. Confirmed with a mock probe: with session (10,100) failing, session (10,101) is never added.
     - (b) One tunnel's non-conflict add failure stops unrelated tunnels and their sessions.
     - (c) A failed deletion of a stale pending session (runtime.rs:811) stops everything, including tunnel additions.
   - Spec: M4. Also affects S10 (foreign-held rename target), S13 and S15.

4. **D4. A `bind_interface` change re-creates the tunnel socket and every session interface on it (high).**
   - Code: runtime.rs:2564-2565 sets `requires_recreate` when `bind_interface` differs.
   - Scenario: an operator changes `bind_interface` from `eth0` to `eth1` and reloads. All session devices on that tunnel are deleted and created again, with new indexes, so children and addresses on them are lost.
   - Spec: the matrix says kept/kept (M17 r1, M11, M12, S17, S18).
   - The test `plan_tunnel_changes_detects_add_delete_update_and_recreate` should be checked: it may assert this behaviour.

5. **D5. Tunnels are deleted before their sessions, and those sessions are never deleted explicitly, including at shutdown (medium).**
   - Code: runtime.rs:799-808 calls `delete_tunnel`, which only drops the socket (state.rs:1446-1466), then removes the tunnel's sessions from `applied_session_specs`. They never reach the session-delete step at 1057. Shutdown (runtime.rs:1975) takes the same path.
   - Effect: identifiers and names are released asynchronously by the kernel workqueue (K17), not deterministically (S26, M6 rule 1).
   - A re-creation in the same reconcile (peer_tunnel_id change, or D4) races the teardown. The tunnel id or session ids hit EEXIST and the configured names are still held by the dying devices, which leads to the conflict counting and abort of D3.
   - The 2 s deletion wait of M14 is also missing.

6. **D6. Transient and host-defect failures are warned every second (medium-high).**
   - Code: service.rs:181 and service.rs:278 `warn!` on every failed retry; runtime.rs:1703 warns on every link event while a hwaddr apply keeps failing.
   - Scenario: a foreign device holds a staged session's name. The log gets "configuration apply still pending; will retry" every second, forever.
   - Spec: M13 (once per episode at warning level; errno changes at debug). The S12 deferral info message is also repeated on every reconcile (runtime.rs:941-948, 1041).

7. **D7. Deletion after a notification loss checks by identifiers and deletes by identifiers in two operations, and a failed check leaks the session (medium).**
   - Code: state.rs:732-740 returns `false` on *any* `get` error. The callers then delete with `delete_session(ids)` (state.rs:1921-1926, 1517-1518, 1543-1544), not with `delete_session_by_ifname`, which l2tp 0.4 provides (handle.rs:634-642).
   - Scenarios:
     - (a) A transient genetlink error (ENOBUFS, EINTR) during the check, after a lifetime-monitor overflow, makes a removed session "forgotten without deleting". The kernel session keeps its ids and its configured-name device until the tunnel is torn down. A re-add then hits EEXIST and is left out as a conflict.
     - (b) There is a race window between the check and the delete.
   - Spec: S22 (check and deletion are one kernel operation by `L2TP_ATTR_IFNAME`).

8. **D8. Unrelated link events cause kernel work (medium).**
   - Code: every `InterfaceChanged` (any NEWLINK on the host) runs `handle_discard_route_change` (runtime.rs:1586-1588). Once a discard route was installed, that opens a netlink socket and re-installs routes (state.rs:1034-1057). It also runs `apply_pending_hwaddrs` (runtime.rs:1589, 1685-1713). For each session with a deferred address, that does a lifetime-socket GETLINK and opens a new rtnetlink socket (state.rs:1877, 237-243).
   - Bind-name matching scans `tunnel_specs` and `pending_bind_interfaces` instead of looking names up.
   - The lifetime ledger stores an entry for every link on the host (link_identity.rs:133-139, 155-177). That is memory bounded by the host, not by the configuration.
   - Spec: M16.

9. **D9. Renaming a configuration entry without changing its ids is a no-op (low).**
   - Code: runtime.rs:2735 and 2781 key entries by `tunnel_id` and `(tunnel_id, session_id)`.
   - Spec: the M17 r5 matrix says re-created (C14). This is harmless in practice, but it contradicts the normative matrix. Either the code or the matrix should change.

10. **D10. `%` in `interface_name` is passed to the kernel (medium).**
    - Code: config.rs:675-676 validates only through `L2tpIfName::from_name`, which accepts `%` (netlink-packet-l2tp 0.4 test.rs:661 lists `l2tpeth%d` as valid). There is no `%` check anywhere in `src/`.
    - Scenario: with `interface_name = "l2tp%d"`, the kernel expands the name at creation (unstaged) or at the publication rename (staged).
    - Follow-on: `rename_interface_with` compares the current name with `"l2tp%d"`, never matches, and renames again at every configured change.
    - Spec: S3, K32. The root cause is config validation, which is the config auditor's area too.

11. **D11. A proof lost after capture during staging skips re-identification (low).**
    - Code: state.rs:1712-1714. A pending session whose captured identity becomes `Lost` goes straight to delete and re-create. `recover_creation` (link_identity.rs:434-453) is used only when there was no capture.
    - S23 asks for re-identification at the broadcast index first. The impact is an unnecessary re-creation, which destroys children that a manager attached to the temp device.

## Audit 2: configuration (C), library (L), observability (O)

Scope: docs/spec/configuration.md, library.md, observability.md against
src/config.rs, src/lib.rs, src/error.rs, src/service.rs, src/blocking.rs,
src/bin/main.rs, Cargo.toml, logging in src/runtime.rs. Dependency
validation was read in the registry: iphost 0.3.3 (`IpHost::from_str`),
fqdn 0.5.2 (features `punycode`, `domain-name-without-special-chars`, ...),
netlink-packet-l2tp 0.4.0 `ifname.rs` (`L2tpIfName` rules), l2tp 0.4.0
(`Cookie`, `Error`).

Live evidence: `rs-l2tpd --check` built with `CONFIG_FILE_PATH`/`CONFIG_DIR_PATH`
pointing at scratchpad files (target dir `target-C`). Observed:

- `remote_addr = ""` (with `ip_version = "V4"`) accepted, rendered as `remote_addr = "."`; `"."` accepted too.
- `remote_addr = "bücher.example"` accepted, rendered `xn--bcher-kva.example`.
- `remote_addr = "::ffff:192.0.2.1"` without `ip_version` becomes `ip_version = "V6"`.
- `remote_addr = "fe80::1"` on an unbound tunnel accepted, no problem reported.
- `remote_addr = "fe80::1%eth0"` with `bind_interface` becomes a "no peer" warning, rendered `remote_addr = "100::"`.
- `interface_name = "l2tp%d"` accepted; `interface_hwaddr = "+2:00:5e:00:53:01"` accepted as `02:00:5e:00:53:01`.
- `tunnel_id = 4294967296` in a drop-in fails the whole drop-in (its other valid tunnel is lost too).
- `cookie = "00112233445566778"` gives `ERROR ... invalid cookie "00112233445566778"`, so the cookie is logged.
- `[host]`, `[resolvers]`, `resolver_name`, `remote_adr`, `bogus_key`, `cokie` produce no message at all; a file whose only problems are unknown keys gives `--check` exit 0, and a misspelt `cokie` silently runs the session **without a cookie**.
- A drop-in named `\377x.toml` (not UTF-8) was read and applied, with no warning.
- A dangling symlink `60-dangling.toml` was silently treated as absent.

`cargo test --lib config::` gives 27 passed.

### Rule-by-rule

| rule | verdict | evidence (file:line) | test | note |
|---|---|---|---|---|
| C1 main first, `.toml` case-insensitive, byte order, other files ignored | CONFORMS | main.rs:649-698 (`extension().eq_ignore_ascii_case`, `dropins.sort()`, main pushed first) | list_toml_files_at_sorts_and_filters, list_toml_files_at_keeps_main_precedence_over_lexicographic_order, list_toml_files_at_keeps_main_when_dropin_dir_missing | Case-insensitivity has no test |
| C1 non-UTF-8 file name ignored with a warning | DEFECT | main.rs:677-681 | none | `Path::extension()` of `\xff x.toml` is `"toml"`, so the file is read. Seen live. Defect 7 |
| C1 a file named exactly `.toml` | DEFECT (low) | main.rs:677-681 | none | `Path::extension(".toml")` is `None`, so the file is skipped although its name ends in `.toml` |
| C2 key-by-key recursive merge; later replaces; tables merged | CONFORMS | config.rs:496-505, 540-546, 653-661 | merge_overrides_fields, cookies_are_optional_and_peer_cookie_defaults_to_cookie, ip_version_is_optional_for_literal_addresses_only, later_documents_replace_invalid_interface_placeholders | Only for the tables that exist (see C5) |
| C3 absent main file or directory is not a problem | CONFORMS | main.rs:654, 687-689 | load_config_at_merges_main_and_dropins (absent.toml) | |
| C3 uninspectable, unreadable or unparsable file at start-up: named, left out, rest used | CONFORMS | main.rs:655, 670-674, 691, 701-705, 735-738 | load_config_at_merges_main_and_dropins, config_discovery_errors_keep_reload_state_and_usable_startup_files | |
| C3 file problem on reload: whole previous configuration kept | CONFORMS | main.rs:781-787 | same two tests | The level it is logged at is wrong (O2) |
| C3 present then absent is a removal | CONFORMS | main.rs:654 (NotFound is absent, no state kept) | none explicit | |
| C4 symlink followed; loop or permission error is an error | CONFORMS | main.rs:651-656 (`fs::metadata` follows) | config_discovery_errors_keep_reload_state_and_usable_startup_files (loop only) | Permission error has no test |
| C4 dangling link is an error, not a removal | DEFECT | main.rs:651-654 | none | `stat` on a dangling link gives ENOENT, which the code treats as absent. Seen live. Defect 6 |
| C4 file disappearing between listing and reading is treated as absent | DEFECT (low) | main.rs:701-704 | none | ENOENT from `read_to_string` becomes an error: a reload is refused, and at start-up it is logged as an error |
| C5 four optional tables | PARTIAL | config.rs:485-490 | empty_document_yields_empty_config | Only `tunnels` and `sessions` exist. `resolvers` and `host` are GAP and are silently ignored |
| C5 every field optional; textual values stay text until validated | CONFORMS | config.rs:530-536, 641-649 | later_documents_replace_invalid_interface_placeholders, invalid_values_reject_only_their_entry | |
| C6 wrong type fails the document | CONFORMS | serde derive, config.rs:484 | rejects_invalid_cookies (`cookie = 1234`) | |
| C6 unknown key: warning at start/reload, `--check` exit 1, strict conversion fails | DEFECT | config.rs:484, 529, 640, 719-723 (no `deny_unknown_fields`, no capture) | none | Ignored silently everywhere. Seen live. Defect 1 |
| C7 `tunnel_id` required, 1..2^32-1, unique | PARTIAL | config.rs:552-554, 1065-1067, 853-869 | rejects_zero_ids_and_unknown_tunnels, config_rejects_duplicate_ids_and_interface_names | Out-of-range fails the whole document instead of the entry. Defect 5 |
| C7 `peer_tunnel_id` 1..2^32-1, defaults to `tunnel_id` | CONFORMS | config.rs:568, 1068-1070 | optional_fields_may_be_omitted, builders_apply_defaults_and_validate | Out-of-range as for `tunnel_id` |
| C7 `remote_addr` literal must be unicast (not unspecified, multicast or broadcast); loopback allowed | CONFORMS | config.rs:292-297, 1091-1095 | remote_addr_must_be_unicast, rejects_non_unicast_literal_remote_addrs | |
| C7 `remote_addr` IPv4-mapped IPv6 literal is an IPv4 literal | DEFECT | config.rs:315-321, 1084-1090; iphost lib.rs:39-42 | literal_remote_addr_must_match_ip_version asserts the opposite | Defect 3 |
| C7 `remote_addr` IPv6 zone (`%ifname`, link-local only) | GAP | iphost `IpHost::V6Addr(Ipv6Addr)` has no zone | none | `fe80::1%eth0` becomes a tolerated "no peer" problem |
| C7 link-local literal without zone on an unbound tunnel is a hard mistake | DEFECT | config.rs:1076-1097 (no check) | remote_addr_must_be_unicast lists `fe80::1` as good on an unbound tunnel | Defect 2 |
| C7 `remote_addr` host-name grammar (1-253 bytes, ASCII LDH labels 1-63, no leading or trailing hyphen, trailing dot removed) | DEFECT | iphost lib.rs:43; fqdn punycode.rs:15-16, 20-36 | none | `""` and `"."` are accepted as the root name, and non-ASCII names are punycoded and accepted. Length, label and hyphen rules conform. Defect 4 |
| C7 `ip_version` V4/V6 either case; required for a host name; other-family literal is a mistake | CONFORMS | config.rs:331-344, 603-612 | ip_version_accepts_both_spellings_and_renders_upper_case, ip_version_is_optional_for_literal_addresses_only, rejects_literal_remote_addrs_of_the_other_family | |
| C7 `bind_interface` valid kernel name (no `%` among others); device need not exist | DEFECT | config.rs:555-558; netlink-packet-l2tp ifname.rs:109-136 | rejects_invalid_interface_name_after_merging (no `%` case) | `%` is not rejected. The other rules conform. Defect 8 |
| C7 `resolver_name` | GAP | absent from PartialTunnelConfig | none | Silently ignored as an unknown key |
| C8 `tunnel_name` required, names a tunnel | CONFORMS | config.rs:666-668, 883-888 | rejects_zero_ids_and_unknown_tunnels | |
| C8 `session_id` required, 1..2^32-1, unique host-wide | PARTIAL | config.rs:669-671, 899-904, 1223-1225 | config_rejects_duplicate_ids_and_interface_names | Out-of-range fails the document (Defect 5) |
| C8 `peer_session_id` defaults to `session_id` | CONFORMS | config.rs:688, 1226-1228 | optional_fields_may_be_omitted | |
| C8 `interface_name` required, valid name, unique | DEFECT | config.rs:672-676, 893-897 | rejects_invalid_interface_name_after_merging | `%` accepted (`l2tp%d` seen live). Uniqueness conforms. Defect 8 |
| C8 `interface_hwaddr` six hex octets, `:`/`-`, either case, unicast, not zero | DEFECT (low) | config.rs:137-153 | hwaddr_parsing_and_rendering | `u8::from_str_radix` accepts a leading `+`: `+2:00:...` is accepted. Defect 10 |
| C8 `cookie` 8 or 16 hex digits | CONFORMS | config.rs:253-269 | cookie_parsing_and_rendering, rejects_invalid_cookies | |
| C8 `peer_cookie` defaults to `cookie` | CONFORMS | config.rs:692 | cookies_are_optional_and_peer_cookie_defaults_to_cookie | |
| C16 resolver entries and their hard mistakes | GAP | none | none | |
| C17 `host.fix_bindv6only` | GAP | none | none | |
| C9 uniqueness in ascending byte order of names; later one at fault | CONFORMS | config.rs:793, 815 (BTreeMap<String> order), 853-908 | lenient_conversion_keeps_valid_entries_and_reports_the_rest | Separate resolver name space is GAP |
| C10 valid entry applied as configured | CONFORMS | config.rs:798-799 | lenient_conversion_keeps_valid_entries_and_reports_the_rest | |
| C10 unusable endpoint: applied without a peer, family rule, warning | PARTIAL | config.rs:559-564, 581-590, 619-624; main.rs:750-752, 1113-1115 | unusable_endpoints_keep_the_tunnel_without_a_peer, lenient_loading_keeps_everything_usable_and_sorts_the_problems | Tolerance, family rule and warning conform. "Without a peer" is the retired discard address (100::, 192.0.0.8), which is GAP. An empty host name is not caught (Defect 4) |
| C10 unusable `interface_hwaddr`: kernel address, warning | CONFORMS | config.rs:677-681, 833 | invalid_values_reject_only_their_entry, a_bad_hardware_address_alone_does_not_refuse_a_reload | |
| C10 `resolver_name` on a literal: applied, key ignored, warning | GAP | none | none | Ignored without a warning |
| C10 other mistakes left out, reported as error; a left-out tunnel takes its sessions | PARTIAL | config.rs:801-848; main.rs:1110-1112 | lenient_conversion_keeps_valid_entries_and_reports_the_rest | Conforms for zero, missing or duplicate ids, names, cookies and unknown tunnel. Out-of-range ids drop the file (D5), unzoned link-local is not caught (D2), resolver cases are GAP |
| C10 result may be empty; never refuses to start | CONFORMS | main.rs:1109-1130 | lenient_loading_keeps_everything_usable_and_sorts_the_problems | |
| C11 tolerated mistakes corrected in place on reload | UNTESTABLE-STATICALLY | runtime (other auditors) | none in my scope | Live test: start with a bad endpoint or MAC, reload with a fixed one, check the tunnel socket and session ifindex are unchanged |
| C12 file problem refuses the reload | CONFORMS | main.rs:781-787 | load_config_at_merges_main_and_dropins | Logged at warning, not error (O2) |
| C12 valid or tolerated entry as at start-up | CONFORMS | main.rs:801-804 | a_bad_hardware_address_alone_does_not_refuse_a_reload | |
| C12 existing entry with a hard mistake keeps its values, with a warning | CONFORMS | config.rs:801-811, 834-844; main.rs:801-802 | previous_values_replace_entries_that_would_be_rejected, lenient_loading_keeps_everything_usable_and_sorts_the_problems | |
| C12 new entry with a hard mistake left out, with a warning | CONFORMS | main.rs:798-800 | lenient_loading_keeps_everything_usable_and_sorts_the_problems | |
| C12 previous values no longer fit: reload refused naming the entry | PARTIAL | main.rs:796-814 | lenient_loading_keeps_everything_usable_and_sorts_the_problems | Refuses only when the retained entry sorts after the colliding new one (Defect 9) |
| C12 two-pass conversion, outcome independent of names | DEFECT | config.rs:790-849 (single pass in name order) | previous_values_replace_entries_that_would_be_rejected codifies the single pass | Defect 9 |
| C12 entry no longer present is removed from the kernel | UNTESTABLE-STATICALLY | runtime (other auditors) | none in my scope | Resolver part is GAP |
| C13 accepted configuration is the base of the next reload and is reported by the handle | CONFORMS | service.rs:315; main.rs:831-833 | none direct | |
| C14 change semantics and ordering | UNTESTABLE-STATICALLY | runtime (sessions/model auditors) | none in my scope | |
| C15 strict conversion fails on the first problem of any kind, unknown keys included | PARTIAL | config.rs:740-746, 922-928 | lenient_conversion_keeps_valid_entries_and_reports_the_rest | Unknown keys do not fail it (D1) |
| C15 lenient conversions return every problem with kind, name, field, effect, error; document problems name file and key path | PARTIAL | config.rs:393-449 | invalid_values_reject_only_their_entry | No field accessor (the field is only in the message text). No library document-problem type: file errors are binary strings, main.rs:731-741 |
| C15 strict conversion is what direct deserialisation does | CONFORMS | config.rs:719-723, 951-955, 1116-1120 | rendering_round_trips, standalone_tunnel_and_session_documents_get_the_same_defaults | |
| L1 library owns no file or terminal I/O, signals or tunables; serde optional; TOML, CLI and logger behind `bin` | CONFORMS | lib.rs:15-18; Cargo.toml:37-52; only `eprintln!` is test-only, netlink.rs:323 | none | |
| L2 unsafe denied; kernel through netlink and socket crates | CONFORMS | lib.rs:60; the only `allow(unsafe_code)` is the test module, state.rs:1941 | none | |
| L3 foreign types re-exported; private fields; enums non-exhaustive | PARTIAL | config.rs:40, 45; error.rs:8; runtime.rs:33 | none | `IpVersion` (config.rs:302-311) lacks `#[non_exhaustive]`. `ControlEvent` struct-variant fields are public, so adding one is breaking. `l2tp::TunnelId` (inside `L2tpError::DeletionPending`/`TunnelIdMismatch`) is not re-exported (low) |
| L4 a `Config` is always valid; insertion validates the same rules | PARTIAL | config.rs:853-908, 1064-1097, 1222-1230 | builders_apply_defaults_and_validate | Same validation everywhere, but the rules are missing (D2, D3, D4, D8) |
| L4 lenient conversions return kind, name, effect, error | CONFORMS | config.rs:411-429 | lenient_conversion_keeps_valid_entries_and_reports_the_rest | |
| L5 `Service::new` fails at once | CONFORMS | service.rs:136-148; state.rs:914-926 | none | |
| L5 `converge` retries 1 s, handles events, ignores reloads | CONFORMS | service.rs:170-198 | shutdown_survives_a_full_queue_before_converge | |
| L5 `converge` returns the list of entries left out for conflicts | PARTIAL | service.rs:28-36, 170 | none | Returns only `Startup` |
| L5 `run` without `converge` converges first | DEFECT | service.rs:256-283 | none | Defect 11 |
| L5 `run` removes everything at shutdown | CONFORMS | service.rs:341 | shutdown_wakes_an_idle_service | Not on the panic path (L7) |
| L6 `Control`: clone, any thread, `reload` non-blocking and fails when full, `reload_wait`, persistent `shutdown`, in order, `config` | CONFORMS | service.rs:69-117 | shutdown_survives_a_full_queue_before_run, reliable_reload_waits_for_queue_capacity | |
| L7 callback on a blocking-capable thread; error logged and previous kept | CONFORMS | service.rs:293-306 | none | |
| L7 callback panic ends the service with an error after cleanup | DEFECT | service.rs:309-312 | none | Defect 12 |
| L7 shutdown does not wait for a blocked callback | DEFECT | service.rs:293-297 | none | Defect 13 |
| L8 `blocking::Service` on its own runtime and thread | CONFORMS | blocking.rs:42-107 | none | |
| L8 dropping it, before or after `run`, performs the P16 shutdown | DEFECT | blocking.rs:84-86, 152-160 | none | Defect 14 |
| L9 `Runtime::new`, `reconcile`, `shutdown`, Drop | CONFORMS | runtime.rs:721-724, 772, 1966, 2161-2173 | many runtime tests | `reconcile` reports "unapplied" as `Err` |
| L9 `handle_event` | GAP | none, only per-kind `handle_*` | none | |
| L10 `handle_event` dispatches every variant, including future ones | GAP | none; service.rs:202-248 dispatches privately | none | With `ControlEvent` non-exhaustive, an embedder cannot forward unknown variants |
| L11 one non-exhaustive error enum; no panic on bad input | CONFORMS | error.rs:14-48 | none | No input-driven panic found in config, service or blocking |
| L12 runtime asks the program to write a tunable via an event | GAP | none | none | |
| O1 log facade; stderr, info, or debug with `--verbose` | CONFORMS | main.rs:1089-1097 | none | |
| O2 start-up: hard mistake at error, tolerated at warning | CONFORMS | main.rs:1110-1115 | none (strings checked, not levels) | |
| O2 unknown key at warning | DEFECT | none | none | Never logged (D1) |
| O2 reload: kept values or left out at warning | CONFORMS | main.rs:798-803 | none | |
| O2 reload: whole reload refused at error | DEFECT | service.rs:303-305 | none | Defect 15 |
| O2 host defect at error, once | DEFECT | service.rs:181, 278 | none | Warning, every second (D16) |
| O3 lasting condition reported once at start and once at end | DEFECT | service.rs:181, 278; runtime.rs:1284-1289 | none | Defect 16 |
| O4 entry messages carry ids and configuration name, plus field for configuration problems | PARTIAL | runtime.rs:801-1080 (ids, no name); config.rs:441 (name + field, no ids) | none | The runtime has no configuration names: DesiredTunnel and DesiredSession are keyed by id |
| O5 cookies never logged; `Debug` gives the length | DEFECT | config.rs:254-257; config.rs:640-649 | cookie_parsing_and_rendering (Debug only) | `Cookie` Debug (config.rs:242-246) and `describe_cookies` (runtime.rs:2514-2520) conform. Defect 17 |
| O6 kernel errors keep their errno names | PARTIAL | error.rs:29; l2tp error.rs:158 (`kernel error {code}: {message}`) | none | Numeric code and strerror text only; ENETUNREACH-style names never appear |
| O7 parent exits 0 when ready, 1 on failure or early shutdown | CONFORMS | main.rs:548-564, 1150-1161 | none | |
| O7 daemon 0 on clean shutdown, non-zero on a failed step or callback panic; callback error leaves 0 | CONFORMS | main.rs:1187-1195; service.rs:303-311 | none | |
| O7 `--check` exits 1 on any problem, unknown keys included | DEFECT | main.rs:1120-1125 | none | Unknown keys give exit 0. Seen live (D1) |
| O8 `--check` prints TOML with file keys, left-out entries absent, problems on stderr in start-up words, no kernel request | CONFORMS | main.rs:1109-1126 (returns before daemonize and Service::new) | none for the binary path | |
| O8 tolerated mistakes rendered corrected: no peer for an unusable endpoint | GAP | main.rs:1117 renders config.rs:563 discard | none | Rendered `remote_addr = "100::"`, the retired discard design |
| O9 PID file is PID plus newline | CONFORMS | main.rs:488 | write_pid_file_accepts_search_only_ancestors | |
| O9 tunnels and sessions recognisable in `ip l2tp show` | UNTESTABLE-STATICALLY | none | none | Live: compare `ip l2tp show tunnel` and `show session` with the config while connected and disconnected |
| O9 `rsl2tp-t` staged names, `rsl2tp-r` renames | PARTIAL | runtime.rs:2642 (`rsl2tp-r`) | runtime tests around 3663-3721 | No `rsl2tp-t` staging exists (sessions auditor) |
| O9 no other daemon object on the host | GAP | runtime.rs:2045-2080 (null devices and discard routes) | none | Retired discard design |

#### Counts

- CONFORMS: 44
- PARTIAL: 14
- GAP: 10
- DEFECT: 22 rows, 17 distinct defects below
- UNTESTABLE-STATICALLY: 4

### Defects

1. **Unknown keys are silently ignored everywhere** (high). config.rs:484, 529, 640, 719-723: the serde derives have no `deny_unknown_fields` and nothing collects unknown keys.
   - C6 and O2 want a warning naming the key path, O7 and O8 want `--check` to exit 1, and C15 wants the strict conversion to fail. None of the three happens.
   - Seen live: `cokie = "deadbeef"` on a session gives `--check` exit 0 and the session runs with no cookie. The operator believes injection protection is on, and it is off.
   - The same applies to `remote_adr` (the tunnel then gets a "remote_addr is missing" no-peer warning that does not mention the typo) and to `[host]`, `[resolvers]` and `resolver_name`.
2. **Unzoned link-local peer accepted on an unbound tunnel** (high). config.rs:1076-1097 never checks `is_unicast_link_local`, and test `remote_addr_must_be_unicast` asserts `fe80::1` is good. C7 and C10 call this a hard mistake (left out, error). Instead the tunnel is applied with a peer the kernel cannot connect to without a scope.
3. **IPv4-mapped literal treated as IPv6** (high). config.rs:315-321 and 1084-1090; iphost parses `::ffff:a.b.c.d` as `V6Addr`. With `ip_version = "V4"` the entry is a tolerated "no peer" mistake, although the spec says it is a valid IPv4 literal. Without `ip_version`, it creates an IPv6 tunnel. Test `literal_remote_addr_must_match_ip_version` encodes the opposite of C7.
4. **Empty or root host name and non-ASCII host names accepted** (high). The fqdn 0.5.2 `punyencode` (punycode.rs:15-16) returns the root FQDN for `""` and `"."`, and punycodes Unicode labels. So:
   - `remote_addr = ""` with `ip_version` is a valid configuration, with no problem, in both the strict and lenient conversions.
   - The tunnel resolves the root name forever, and `--check` renders it as `"."`.
   - C7 requires 1-253 bytes of ASCII letters, digits and hyphens. C10 says such a value is an unusable endpoint (warning).
5. **Out-of-range identifier fails the whole document** (high). An identifier above 2^32-1 or negative fails the document because the fields are `Option<u32>` (config.rs:531-532, 643-644). C10 lists "out-of-range identifier" as an entry-level mistake.
   - Seen live: `tunnel_id = 4294967296` in a drop-in removed the drop-in's other, valid tunnel at start-up.
   - On a reload it refuses the whole reload instead of keeping that one entry.
6. **Dangling symlink treated as an intentional removal** (high). main.rs:651-654: `fs::metadata` gives ENOENT for a dangling link and the code takes that as absent.
   - Scenario: `/etc/rs-l2tpd.toml` is a link to a file on a not-yet-mounted or replaced path, and SIGHUP arrives.
   - Result: every tunnel and session in that file is removed from the kernel. C4 requires an error, and C3/C12 require the reload to be refused.
   - The existing test covers only a symlink loop. A fix needs `symlink_metadata` to tell a dangling link from a missing file.
7. **Non-UTF-8 drop-in names are read** (high). main.rs:677-681: `Path::extension()` of `"\xffx.toml"` is the UTF-8 `"toml"`, so the file is merged with no warning (seen live). C1 says it is ignored with a warning. A related low one: a file named exactly `.toml` is skipped although its name ends in `.toml`.
8. **`%` accepted in interface names** (high). netlink-packet-l2tp ifname.rs:134-136 rejects NUL, `/`, `:`, whitespace and 0xa0, but not `%`. The spec (C7, C8, K32) forbids it because the kernel expands it as a format pattern.
   - Scenario: `interface_name = "l2tp%d"` is accepted (seen live), and the kernel creates `l2tp0` or the like.
   - The daemon then wants a device named `l2tp%d`, which never exists. It will rename or retry against a name the kernel will not honour, or collide with another `l2tpN`.
   - The same applies to `bind_interface`.
9. **Reload conversion is single-pass and depends on names** (high). config.rs:790-849 handles entries one by one in name order and inserts a retained (KeptPrevious) entry before later new entries are seen.
   - Scenario: accepted config has `a` with id 10. The reload gives `a` a hard mistake and adds a new valid `c` with id 10.
   - Code: `a` keeps id 10 and `c` is left out with a warning, so the reload is accepted.
   - Spec C12: refused, naming `a`.
   - If the new entry were named `0c`, the code would refuse. So the outcome depends on names, which C12 forbids.
   - The spec's own example (`a`=10 with a mistake, `b` moves to 10) is refused but names `b`, not `a`.
10. **Hardware address accepts a sign** (low). config.rs:143-146: `u8::from_str_radix("+2", 16)` is 2, so `+2:00:5e:00:53:01` is accepted (seen live). The cookie parser guards against this (config.rs:260); `HwAddr` does not.
11. **`Service::run` without `converge` never applies the initial configuration** (high). service.rs:256-283: `reconcile_pending` starts false and nothing reconciles `config` until a reload or a `ReconcileRequested`. L5 says `run` converges first. An embedder that calls `run` directly gets an idle service with nothing created.
12. **Reload-callback panic skips cleanup** (high). service.rs:309-311 `return Err(...)` before `self.runtime.shutdown()` at service.rs:341. The Runtime is only dropped, which closes sockets without order. L7 and P16 require the orderly shutdown first.
13. **Shutdown waits for a blocked reload callback** (high). service.rs:293-297 awaits `spawn_blocking` outside the `select!` on `shutdown_rx`. Scenario: the callback blocks (for example a hung read of a file on NFS), then SIGTERM arrives; the service does not shut down until the callback returns. L7 and P13 forbid this.
14. **`blocking::Service` dropped before `run` does not perform the P16 shutdown** (medium-high). blocking.rs:84-86 is just `drop(service)` inside the runtime: no `runtime.shutdown()`, so tunnels created by `converge` are torn down only by socket close, without order. L8 requires the P16 shutdown.
15. **Refused reload logged at warning, not error** (high). service.rs:304 `warn!("failed to load configuration: {}")` covers every refusal from main.rs:782-786 and 810-813. O2 requires error.
16. **Repeated warnings every second** (high). These break O3 (once per episode) and the O2 "host defect: error, once" rule:
    - converge's `warn!` on every failed reconcile (service.rs:181);
    - run's `warn!` on every pending retry tick (service.rs:278);
    - every failed unbound reconnect retry (runtime.rs:1284-1289, re-armed each second at 1293-1307).

    Scenario: a host without `l2tp_eth`, or a lasting EPERM, logs a warning every second forever.
17. **Cookie values reach logs and diagnostics** (high). This breaks O5.
    - config.rs:254-257 formats the rejected cookie text into the error (`invalid cookie "00112233445566778"`). The daemon logs it at error level at start-up (main.rs:1111) and at warning on reload (main.rs:799), and `--check` prints it to stderr. A one-digit typo leaks the whole intended cookie (seen live).
    - `PartialConfig`, which is public, derives `Debug` with `cookie: Option<String>` (config.rs:640-649), so `{:?}` of a merged document prints the cookies.

## Audit 2: events (E), resolvers (V), architecture (A)

Scope: docs/spec/events.md, docs/spec/resolvers.md, docs/spec/architecture.md against
src/runtime.rs, src/service.rs, src/netlink.rs, src/state.rs, src/state/link_identity.rs,
src/bin/main.rs (signals only), Cargo.toml, iphost 0.3.3 (registry copy, the version
Cargo.lock resolves), netlink-proto 0.13.0 / rtnetlink 0.23.0 (registry), l2tp-rs (sibling).
`cargo test --lib` (skipping `privileged`): 114 passed, 0 failed.

Overall: the code implements the previous design (discard addresses, null device, discard
routes, route-group subscription, system resolver only through iphost 0.3.3). The spec's
configured resolvers (iphost 0.4.0), the disconnected-socket state, restart, bindv6only,
and `Runtime::handle_event` do not exist yet. Inside what is built, there are real defects
(see "Defects").

### Events

| rule | verdict | evidence (file:line) | test | note |
|---|---|---|---|---|
| E1 device appears → bind + reconnect | PARTIAL | runtime.rs:1583-1679 (pending bind by name, bind, then `handle_local_address_change` reconnect at 1676-1678); event from runtime.rs:2420-2432 | removed_bind_interface_is_rebound_when_it_reappears, reconcile_defers_missing_bind_interface_until_it_appears, late_bind_retries_source_selection_until_interface_is_ready; docker address-changes.sh | Binding and reconnect on appearance work. But the spec premise "a tunnel that was disconnected because its device was absent" is not true: a tunnel created while its device is absent is created unbound and connected to its real peer (runtime.rs:1319-1329, 2089-2112). See Defect 8. Resolver half: N/A (no bound resolvers, GAP V9). |
| E2 rename: bound device renamed away → disconnect and wait | DEFECT | runtime.rs:1595-1597 skips every tunnel whose configured name differs from the event's new name; `InterfaceChanged` carries no index (runtime.rs:125-128, 2423-2431) | reconcile_rebinds_when_bound_device_was_renamed_away only drives `handle_interface_change(None)`; address-changes.sh:263-281 renames and creates the replacement at once | See Defect 2. |
| E2 rename: device takes configured name → bind by reconnect | CONFORMS | runtime.rs:1598-1619, 1655-1678 | reconcile_handles_interface_name_swap; address-changes.sh:263-300 | |
| E2 session device rename → nothing but pending hwaddr retry | CONFORMS | runtime.rs:1589, 1685-1713 | renamed_session_link_events_apply_pending_hwaddr_without_disturbing_up_siblings | S10 "acknowledged override" bookkeeping is sessions scope. |
| E3 device disappears → bound tunnels disconnected, wait | PARTIAL | runtime.rs:1717-1736 marks the binding invalid (state.rs:1436-1444) and queues a rebind; the socket is not disconnected (the kernel keeps `sk_bound_dev_if` of the dead index, so sends fail rather than leak) | removed_bind_interface_is_rebound_when_it_reappears; interface_resync_recovers_replacement_after_missed_removal | No explicit disconnect; VRF treated like any device: CONFORMS. |
| E3 session device disappears → observed removal, re-create when kernel lost session | PARTIAL | removal proof: link_identity.rs:179-186; no re-creation on DELLINK: runtime.rs:1717-1736 handles tunnels only, reconcile plans from specs (runtime.rs:2582-2617), not from kernel state | pending_session_is_resumed_and_parent_teardown_removes_it (staging only) | S27 re-creation is sessions scope; nothing in the event path does it. |
| E3 resolver bind device disappears | GAP | no bound resolvers | — | V9. |
| E4 session device down → deferred hwaddr applied | CONFORMS | runtime.rs:1589, 1685-1713 | hwaddr_change_on_an_up_device_is_deferred_until_it_is_down, failed_hwaddr_change_is_retried_on_link_events | |
| E4 VRF slave membership change → reconnect tunnels bound to VRF | CONFORMS | runtime.rs:2316-2332, 2388-2414, 1815-1824 | controller_change_refreshes_only_a_verified_current_vrf_after_slave_deletion, controller_cache_tracks_attachment_reparenting_and_detachment | |
| E4 bind device's own VRF membership change | PARTIAL | a tunnel bound to `eth1` when `eth1` is enslaved: `VrfChanged{vrf}` is ignored because the VRF is not a bound index (runtime.rs:1816), `InterfaceChanged{eth1}` sees the name unchanged (runtime.rs:1600) | none | See Defect 9 (low confidence, spec wording ambiguous). |
| E4 nothing looked up for unrelated devices | PARTIAL | every NEWLINK of any device runs `handle_discard_route_change` (kernel requests when discard routes are recorded, runtime.rs:1586-1588, state.rs:1034-1057) and re-validates every pending-hwaddr session (runtime.rs:1589) | address_and_vrf_notifications_do_nothing_without_bound_tunnels (address/VRF only) | Discard routes are retired design (D page). |
| E5 only AF_UNSPEC link events are lifetimes | CONFORMS | runtime.rs:2360, 2394, 2401, 2421, 2434; link_identity.rs:156-160, 180 | protocol_link_metadata_does_not_remove_devices_or_change_vrf_membership, protocol_specific_deletion_is_not_netdevice_deletion | |
| E6 address added → reconnect connected bound tunnels of that family on device or its VRF; no kernel query if nothing bound | CONFORMS | runtime.rs:2440-2442, 2462-2472, 1774-1798, 1829-1900 (family filter 1868-1877, discard skip 1856-1863) | address_changes_match_effective_family_and_current_bindings, address_and_vrf_notifications_do_nothing_without_bound_tunnels, local_address_change_reconnects_tunnels_bound_to_changed_interface; address-changes.sh | Bound tunnels whose last reconnect failed are also reconnected (only_disconnected=false); harmless. |
| E7 address removed → as E6 plus unbound tunnels whose own-socket source is the address | CONFORMS | runtime.rs:2443-2451, 2477-2487, 1235-1239, 1246-1309 (source from getsockname, state.rs:1159-1165) | removed_source_addresses_reconnect_the_unbound_tunnels_using_them, address_removals_carry_the_address_and_discard_route_removals_both_families; source-and-peers.sh | |
| E8 failed reconnect → one retry per device / one for unbound, 1 s; other family does not postpone; retry resolves name; stops on success | CONFORMS | runtime.rs:1840-1844, 1868-1876, 1888-1919, 1293-1308, 1803-1809; name re-resolved state.rs:1364-1368 | local_address_change_retries_failed_reconnect_after_one_second, vrf_retry_survives_other_family_events_and_slave_removal, reconnect_retries_follow_replacement_interfaces_resolved_by_name, reconnect_retry_continues_when_event_precedes_sender_completion | |
| E9 no route group subscribed | GAP | monitor subscribes `Ipv4Route`/`Ipv6Route` (runtime.rs:2260-2261) and acts on discard-route removals (runtime.rs:2453-2457, 1925-1961); filter keeps DELROUTE of discard routes (netlink.rs:221-271) | monitor_filter_keeps_link_address_and_discard_route_removals_only | Retired discard-route design still in place. Consequence: without the filter (attach failure is only a warning, netlink.rs:61-68) a full-table router floods the monitor. |
| E10 answer change → reconnect to selected address | CONFORMS (reachable case) | runtime.rs:520-565 (poll), 1156-1192 | dns_apply_failure_requeues_current_address, retargeting_resolver_does_not_reuse_the_previous_hosts_cached_address | |
| E10 unreachable answer → tunnel disconnected, address pending, retried 1 s | DEFECT | runtime.rs:1193-1201 keeps the old peer; state.rs:1308-1324 rolls back to / never leaves the previous peer; runtime.rs:1554-1560 only falls back when not connected | none for connected-A → unreachable-B (discard_address_falls_back_to_the_other_family covers discard → unreachable only) | See Defect 1. |
| E10 answers for names/families no longer configured discarded | CONFORMS | runtime.rs:580-597, 1162-1168, 614-617 | retargeting_resolver_does_not_reuse_the_previous_hosts_cached_address, dns_family_retarget_keeps_the_new_family_answer_observable | Resolver part: GAP. |
| E11 refresh 30 s after previous lookup returned | CONFORMS | iphost auto.rs:147 then 204 (resolve, then sleep); runtime.rs:496-499 | none | |
| E11 lookups bounded per kind | GAP | only the system resolver; bound is the libc's | — | V4. |
| E11 polled every second | CONFORMS | runtime.rs:520-523 | — | |
| E11 failed query keeps answer | CONFORMS | iphost lib.rs:286, 320-331 (`use_cached_on_error=true`, auto.rs:95) | none | |
| E11 negative answer keeps answer | DEFECT | iphost auto.rs:95 hardcodes `retain_stale_values=false`; lib.rs:306-315 clears the family | none | See Defect 6. |
| E11 replacing host name/family/resolver discards answers | PARTIAL | host name: runtime.rs:581-587 (new resolver). Family: same resolver kept, the other family's cached answer from the last lookup is used, no fresh query (runtime.rs:590-592, 2703-2706). Resolver: GAP | retargeting_resolver_does_not_reuse_the_previous_hosts_cached_address, dns_family_retarget_keeps_the_new_family_answer_observable | |
| E12 reconcile retry every second | CONFORMS | service.rs:261-281, 317-326; converge 172-196 | degraded-start.sh (indirect); no unit test of the loop | During converge every dispatched event also triggers a full reconcile (Defect 11). |
| E13 pending peer retry 1 s, applied in place, reported once | PARTIAL | runtime.rs:1516-1576, 1449-1478 | unroutable_literal_peer_gets_a_discard_address_and_is_retried, a_peer_update_to_an_unroutable_address_uses_a_discard_address_meanwhile | The timer and reporting conform. The meanwhile state is a discard address (or the old peer, Defect 1), not a disconnected socket (T15, A19). |
| E14 left-out retry every 30 s | CONFORMS | runtime.rs:1524-1528, 1567-1574; service.rs:332-336 | refused_identifiers_are_retried_then_left_out_until_a_retry_succeeds | `try_send` drop is retried 30 s later. |
| E15 / E16 | n/a (removed) | — | — | Code still has the discard-route grace and repair that E15/E16 removed (runtime.rs:58, 1997-2087, 1925-1961). |
| E17 reload; unchanged config changes nothing | CONFORMS | service.rs:291-327; runtime.rs:791 (empty plan), 920-935, 1126-1127 | unchanged_reload_preserves_dns_changes_inflight_events_and_retries | |
| E18 shutdown removes everything, also during slow start | CONFORMS | service.rs:173-176, 184-192, 266-269, 341; runtime.rs:1966-1986; main.rs:853-865 | shutdown_survives_a_full_queue_before_converge, shutdown_survives_a_full_queue_before_run, shutdown_wakes_an_idle_service | Shutdown is only noticed between reconciles (A14). |
| E19 reload during incomplete reload: last wins | CONFORMS | service.rs:315-326 (config replaced, pending retried with new config); reloads before readiness ignored per P9 (service.rs:193) | none | |
| E26 restart (SIGUSR2) | GAP | no SIGUSR2 handler (main.rs:837-868), no hand-over | — | Process scope. |
| E20 event monitor overflow/failure → reopen, seed, resync | PARTIAL | reopen: runtime.rs:2333-2345, 2266-2273; resync: runtime.rs:2290-2299, 1218-1229 (bindings by name 1220, all connected tunnels 1225-1228, hwaddr via 1589); seed is done on the monitor socket itself (runtime.rs:2279, 2373-2384), not the request socket | monitor_resync_refreshes_sources_without_interface_identity_changes, interface_resync_recovers_replacement_after_missed_removal; monitor-resync.sh, link-monitor-burst.sh | RA part N/A (GAP). Overrun sends two resyncs (Defect 10). |
| E20 lifetime subscription loss → generation ends, reopen, identities lost; no monitor resync | CONFORMS | link_identity.rs:188-215, 369-383, 501-507; reopened lazily at next command (343-355) | monitor_loss_invalidates_existing_and_uncaptured_watches; staging-loss.sh | Reopen is lazy (A7 note). |
| E20 first subscription causes no resync | CONFORMS | runtime.rs:2246, 2290-2299 | none | The first monitor is spawned concurrently with the first reconcile (runtime.rs:727), so "opened before anything exists" is not guaranteed; low risk. |
| E20 event channel overflow handled as monitor loss | DEFECT | monitor blocks on `send().await` (runtime.rs:2292, 2320, 2326); no drop+marker anywhere | none | See Defect 3. |
| E21 ENOBUFS → loss | CONFORMS | netlink-proto framed.rs:89-97 turns ENOBUFS into an Overrun from port 0; runtime.rs:2318, 2333-2337, 2452; link_identity.rs:208-211 | monitor_loss_invalidates_existing_and_uncaptured_watches; link-monitor-burst.sh | |
| E21 lookup timeout (2 s) → loss | PARTIAL | lifetime lookups time out after 5 s (link_identity.rs:263-268, 278-281) and count as loss (375-381); the monitor's seed dump has no timeout (runtime.rs:2373-2384) | staging-loss.sh | Value differs (5 s vs 2 s). |
| E21 socket error → loss | CONFORMS | stream end: runtime.rs:2301 loop exit → 2340-2345 reopen + resync; link_identity.rs:308-311, 505 | — | |
| E21 reopen before repeating a lookup on a lost socket | CONFORMS | link_identity.rs:388-397, 408-411 | — | |
| E21 NETLINK_NO_ENOBUFS not set | CONFORMS | not set anywhere (grep) | — | |
| E22 only port 0 acted on | CONFORMS | runtime.rs:2305-2315; link_identity.rs:301-303, 503 | none | |
| E23 RA with RDNSS on resolver's own socket | GAP | no RA resolver | — | |
| E24 monitor does not subscribe ND_USEROPT; filter never on request sockets | PARTIAL | groups at runtime.rs:2256-2262 (no ND_USEROPT: CONFORMS); the seed GETLINK dump is sent on the filtered monitor socket (runtime.rs:2279) | — | The filter accepts the dump replies (types 1-4, 16), so no observed failure. |
| E25 bindv6only flip | GAP | no V6ONLY check or `host.fix_bindv6only` | — | |

### Resolvers

| rule | verdict | evidence (file:line) | test | note |
|---|---|---|---|---|
| V1 `resolvers` table, `resolver_name`; literal uses no resolver | GAP | no such config (grep `resolver_name` empty); every tunnel, literal or not, gets an `AutoIpHostResolver` thread (runtime.rs:826-830, 496-499) | — | Literal tunnels hold a resolver thread (V15). |
| V2 four kinds, hard mistakes | GAP | Cargo.toml:29 pins `iphost = 0.3.3` (spec: 0.4.0) | — | |
| V3 system resolver = libc, daemon reads no files | CONFORMS | iphost lib.rs:278 (`to_socket_addrs` = getaddrinfo) | none | |
| V4 both families at once; `ip_version` picks | CONFORMS | AF_UNSPEC getaddrinfo, iphost lib.rs:278-304; runtime.rs:656-661 | — | |
| V4 every 30 s after previous lookup returned | CONFORMS | iphost auto.rs:147, 204 | — | |
| V4 at once on tunnel/resolver config change | PARTIAL | host name change: new resolver, immediate lookup (runtime.rs:581-587); `ip_version` change: no new lookup (runtime.rs:590-592); resolver config: GAP | dns_family_retarget_keeps_the_new_family_answer_observable | |
| V4 lookups on threads, never block the reconciler; change notification or 1 s poll | CONFORMS | iphost auto.rs:124 (thread); runtime.rs:520-565; only literals are resolved inline (runtime.rs:2666-2683) | — | |
| V4 one lookup at a time per host name | PARTIAL | one resolver per tunnel (runtime.rs:689), so two tunnels with the same host name look it up concurrently | — | |
| V4 per-kind bounds; address kind bypasses hosts file | GAP | system resolver only | — | |
| V5 usable = unicast, not unspecified/multicast/broadcast, V6 not IPv4-mapped | DEFECT | config.rs:292-296 canonicalises first, so `::ffff:a.b.c.d` is usable for a V6 tunnel | resolved_addresses_that_cannot_be_peers_are_ignored (no mapped case) | Defect 7. |
| V5 selected = previous while present, else first usable | PARTIAL | stability: iphost lib.rs:291-303; but iphost picks the first address of the family, usable or not, and the runtime then rejects the whole answer (runtime.rs:649-654, 1170-1182) instead of skipping to the next usable | resolved_addresses_that_cannot_be_peers_are_ignored | Defect 7. |
| V5 one warning per answer with unusable addresses | PARTIAL | runtime.rs:1171-1175 warns when a change is emitted; an unusable first answer for a never-answered tunnel emits no event and no warning (watcher compares filtered values, runtime.rs:530-541) | — | |
| V6 failed lookup keeps answer | CONFORMS | iphost lib.rs:286, 320-331 | — | |
| V6 negative answer keeps answer (`retain_stale_values` MUST) | DEFECT | iphost auto.rs:95 `new_with_config(ip_host, true, false)`; not configurable in 0.3.3 | none | Defect 6. |
| V6 one family fails, other succeeds → failed family kept | DEFECT | getaddrinfo returns the succeeding family only; lib.rs:311-315 clears the other | none | Defect 6. |
| V6 outage reported once at start and end | GAP | iphost logs nothing (tracing feature off); runtime logs nothing for failed lookups | — | |
| V6 never answered → no real peer, disconnected | PARTIAL | runtime.rs:2709-2711 connects to a discard address instead of leaving the socket disconnected | reconcile_uses_discard_addr_for_unresolved_fqdn | Retired design (A19). |
| V7 changed host name discards answers | CONFORMS | runtime.rs:581-587 | retargeting_resolver_does_not_reuse_the_previous_hosts_cached_address | |
| V7 changed `ip_version` discards and re-queries | PARTIAL | answers kept, no re-query (runtime.rs:590-592) | dns_family_retarget_keeps_the_new_family_answer_observable | |
| V7 "nothing else" discards answers | DEFECT | a re-creation (peer_tunnel_id or bind_interface change, runtime.rs:2564-2570) drops the resolver (runtime.rs:804) and creates a fresh one with `use_discard_until_dns=true` (runtime.rs:503-506, 826-830, 2709-2711) | reconcile_recreate_failure_cleans_stale_resolver (asserts removal) | Defect 5. |
| V7 other family's answer never used | CONFORMS | runtime.rs:656-661 | — | Except IPv4-mapped (Defect 7). |
| V8 readiness never waits for resolver | CONFORMS | runtime.rs:2709-2711; reconcile returns Ok | reconcile_uses_discard_addr_for_unresolved_fqdn | |
| V8 never-answering resolver reported once | GAP | no report | — | |
| V9 binding | GAP | — | — | |
| V10 RA | GAP | — | — | |
| V11 loss does not touch resolvers; no ND_USEROPT on monitor | CONFORMS | handle_network_resync never touches `self.resolvers` (runtime.rs:1218-1229); groups at runtime.rs:2256-2262 | — | RA servers: N/A. |
| V12 DHCPv6 | GAP | — | — | |
| V13 answer in force changes → reconnect | DEFECT | as E10 | — | Defect 1. |
| V13 resolver config change → discard and re-query | GAP | — | — | |
| V13 named resolver removed → reload refused | GAP | — | — | |
| V13 resolver bind device appears/disappears | GAP | — | — | |
| V13 RDNSS lifetime expires | GAP | — | — | |
| V13 notifications lost → nothing | CONFORMS | runtime.rs:1218-1229 | — | |
| V13 shutdown → queries abandoned, nothing removed | CONFORMS | runtime.rs:664-669 (watcher aborted); iphost thread exits at its next wake (auto.rs:132-137) | — | |
| V14 unified ipv6 | GAP | — | — | |
| V15 resources | PARTIAL | system resolver: one OS thread plus one Tokio task per tunnel, literal tunnels included (runtime.rs:496-565); a replaced resolver's thread lingers up to 30 s (auto.rs:204); other kinds GAP | — | |

### Architecture

| rule | verdict | evidence (file:line) | test | note |
|---|---|---|---|---|
| A1 binary owns process concerns | PARTIAL | signals main.rs:837-868; P25 tunable writing and P14 hand-over absent | — | Process scope. |
| A2 services converge/run/reload/shutdown; blocking variant on own thread | CONFORMS | service.rs:170-342; blocking.rs:40-80 | service tests | |
| A3 reconciler sole writer, owns policy | CONFORMS | runtime.rs:682-715 | — | |
| A4 state layer records, no policy | PARTIAL | tunnel record state.rs:1258-1265; resolver records live in runtime.rs:478-488, not the state layer; state holds policy (rollback to previous peer state.rs:1309-1318, null-device policy state.rs:1059-1111) | — | |
| A5 kernel interfaces table | PARTIAL | requests on own sockets (state.rs:42 `Rtnl::connect`); lifetime socket unfiltered (link_identity.rs:243-247); monitor subscribes route groups (runtime.rs:2260-2261) and receives its seed dump on itself (runtime.rs:2279); configured resolvers absent | — | |
| A6 one loop; producers never block; drop + resync marker; persistent shutdown flag | DEFECT | loop: service.rs:265-339 (CONFORMS); shutdown flag service.rs:112-116 (CONFORMS); producers block: runtime.rs:558, 1302, 1534, 1915, 1950, 2292, 2320, 2326 | shutdown_survives_a_full_queue_* | Defect 3. |
| A7 lifetime subscription own socket/task, ordered lookups, private request path | PARTIAL | link_identity.rs:242-260, 327-335, 492-518, 527-576 | link_identity tests; staging-loss.sh, session-identity.sh | After a loss the socket stays closed until the next command (link_identity.rs:343-355, 510-515), so it is not "read continuously". |
| A8 dependency order; MAY run concurrently | CONFORMS | runtime.rs:793-1112 (sequential) | plan_* tests | |
| A9 resolver never blocks loop | CONFORMS | runtime.rs:520-565; iphost auto.rs:124 | — | |
| A10 no disk state but PID file | CONFORMS | only main.rs touches `std::fs` | — | |
| A11 reconciler holdings | PARTIAL | tunnels/sessions/conflicts present (runtime.rs:682-715); per-resolver servers, subscription health/generations, bindv6only flag absent | — | |
| A12 records updated after kernel confirmation; resumable | CONFORMS | state.rs:1250-1267, 1327, 1353-1378; runtime.rs:774-790, 1114-1118 | reconcile_persists_partial_apply_on_failure | |
| A13 subscription failure reopens; op failure never aborts reconcile for others; resolver failure keeps answer; signal thread independent | DEFECT | reopen: runtime.rs:2266-2273, 2340-2345 (CONFORMS); abort: `try_apply!` returns on the first unclassified error (runtime.rs:778-790, 846, 873-881, 907, 961-1015, 1048, 1063, 1107); signals are Tokio tasks on the same multi-thread runtime (main.rs:843, 857, 1134) | reconcile_persists_partial_apply_on_failure (asserts the abort) | Defect 4. |
| A14 retries are messages/timers; shutdown within one iteration | PARTIAL | retries are timers (runtime.rs:1298-1307, 1532-1535, 1911-1918); but one reconcile is one iteration and can be long (lifetime barriers time out at 5 s, link_identity.rs:263-281); shutdown is checked only between reconciles (service.rs:173, 266) | — | |
| A15 sockets rather than unmanaged tunnels | CONFORMS | state.rs:1180-1212, 1250-1256 | tunnel-ownership.sh | |
| A16 indexes rather than names | CONFORMS | runtime.rs:1598-1619, state.rs:1423-1444 | session-identity.sh | |
| A17 kernel record rather than database | CONFORMS | link_identity.rs:434-453 (recovery by creation name) | staging-loss.sh | Sessions scope; not checked deeper. |
| A18 kernel filter is an optimisation | PARTIAL | filter netlink.rs:173-293 (byte-checked: header type at offset 4 compared in host order; `ld #nla` with X=RTA_DST, A=28; IPv6 4-word and IPv4 compare at nla+4; jump targets correct). It is not just an optimisation, because route groups are subscribed (runtime.rs:2260-2261) | monitor_filter_keeps_link_address_and_discard_route_removals_only; privileged_monitor_filter_passes_link_and_discard_route_removals_only (ignored) | |
| A19 disconnected socket rather than substitute peer | GAP | discard address and null device (runtime.rs:76-82, 1997-2087, 2190-2201) | — | |
| A20 reconciler rather than event-driven mutations | CONFORMS | runtime.rs:772-1129 | — | |
| A21 non-exhaustive events dispatched by `Runtime::handle_event` | GAP | `#[non_exhaustive]` CONFORMS (runtime.rs:112); there is no `handle_event` (grep); dispatch is private to `Service` (service.rs:202-248) | — | Embedders of `Runtime` cannot forward unknown variants. |

### Defects

1. **A DNS change to an unreachable address keeps sending to the old peer** (E10, T15, V13). Confidence: high.
   Code: runtime.rs:1184-1201, state.rs:1296-1325, runtime.rs:1547-1561.
   Scenario: a tunnel with FQDN `peer.example` is connected to A. The dynamic DNS record moves to B, and B has no route (or the bind VRF has no route to it). `modify_tunnel(B)` fails. On the fast path, `reconnect_ip` fails with the socket still connected to A. On the slow path, the rollback at state.rs:1311-1316 reconnects to A. `handle_dns_change` records B as pending and the tunnel stays on A. `handle_peer_retry` only falls back when the socket is not connected (runtime.rs:1554), so the tunnel keeps sending to A until B becomes reachable. A dynamic address that was given up is often reassigned, so L2 frames go to a third party. The spec requires the tunnel to be disconnected with B pending. No test covers connected-A to unreachable-B.

2. **A bound device renamed away is not detected on its own event** (E2, T11). Confidence: high.
   Code: runtime.rs:1595-1597; `InterfaceChanged` has a name but no index (runtime.rs:2423-2431).
   Scenario: tunnel `bind_interface = "underlay0"`, then `ip link set underlay0 name old0`. The NEWLINK carries the name `old0`, so every tunnel configured for `underlay0` is skipped. The socket stays bound to `old0` and keeps sending through it, so the configured name is no longer authoritative. It is caught only by a later full check (reload, resync) or when some device takes the name `underlay0`. Tests only cover `handle_interface_change(None)`, and address-changes.sh creates the replacement immediately.

3. **Producers block on the event channel, and the netlink queue in front of them is unbounded** (A6, E20 last sentence, R10, G23). Confidence: high on the mechanism, medium on the impact.
   Code: runtime.rs:2292, 2320, 2326 (also 558, 1302, 1534, 1915, 1950 for resolver and timer tasks). `rtnetlink::new_connection` uses netlink-proto's `UnboundedReceiver`, and its connection task drains the kernel socket continuously (netlink-proto lib.rs:229, connection.rs:159-180).
   Scenario: a burst of link or address notifications (many VLANs or PPP links flapping, IPv6 privacy-address churn) arrives while the reconciler is slow. The 256-slot channel fills and the monitor task blocks in `send().await`. The connection task keeps reading the 8 MiB kernel buffer into unbounded user memory. The kernel buffer never overflows, so no resync ever happens, memory grows without bound, and the events are processed with unbounded latency. The spec requires dropping the event and recording a resync marker.

4. **One entry's unclassified error aborts the whole reconcile** (A13, M13). Confidence: high on the mechanism, medium on how often it happens.
   Code: `try_apply!` at runtime.rs:778-790, used at 802, 811-815, 907, 961-1015, 1048, 1063, 1107; `Err` at 873-881; `prepare_discard_route` returns `Error::Other` during the 10 s grace (runtime.rs:2059-2067).
   Scenario: tunnel 1 has an unresolved FQDN on a host with no route to the discard address. The reconcile returns at tunnel 1 for 10 s, so tunnel 2 (literal, routable) and every session are not created. After the grace, if the null device cannot be created, `create_tunnel` returns an unreachable error that is not a conflict (runtime.rs:873-881). Every later entry is then blocked for as long as tunnel 1 fails. The same happens for a session whose `add_session` fails with any error other than EEXIST/EADDRINUSE.

5. **Re-creating an FQDN tunnel throws away its answer** (V7 "nothing else does", V6). Confidence: high.
   Code: runtime.rs:804 (resolver dropped in `to_delete`), 826-830 and 503-506 (fresh resolver with `use_discard_until_dns=true`), 2709-2711.
   Scenario: a reload changes `bind_interface` or `peer_tunnel_id` of a working FQDN tunnel. The tunnel is re-created on the discard address until a new lookup completes. If the resolver is down at that moment, the first lookup fails, there is no cached answer, and the tunnel stays without its peer for the whole outage. V6 says a resolver outage must never disconnect a working tunnel.

6. **`retain_stale_values` is not enabled; iphost 0.3.3 cannot enable it** (V6, E11). Confidence: high on the behaviour, medium on the impact.
   Code: Cargo.toml:29 (`iphost = 0.3.3`); iphost auto.rs:95 hardcodes `false`; lib.rs:306-315.
   Scenario: a transient NODATA for AAAA, or a lookup where AAAA times out while A succeeds (glibc returns the A records only), clears the cached IPv6 answer. The runtime keeps the current peer at that moment (runtime.rs:1170-1181). Two things then go wrong. First, the next answer `[B, A]`, with A the connected peer, selects B because iphost's previous value is gone: a needless reconnect that V5 forbids. Second, a family change on reload in that window (runtime.rs:2703-2711) falls back to the discard address.

7. **The usability rules are wrong in two ways** (V5). Confidence: medium (the code paths are certain, the DNS answers are rare).
   Code: config.rs:292-296; iphost lib.rs:291-303 with runtime.rs:649-654.
   (a) An AAAA answer of `::ffff:198.51.100.1` is canonicalised to IPv4 and accepted for a V6 tunnel, which then runs over IPv4. The spec says IPv4-mapped is unusable for V6.
   (b) An answer `[0.0.0.0, 192.0.2.1]` makes iphost select `0.0.0.0`. The runtime then rejects the whole answer ("keeping the current peer") instead of selecting `192.0.2.1`. A tunnel that never had an answer stays without a peer and gets no warning.

8. **A tunnel whose bind device is absent is connected unbound to its real peer** (cross-scope T13; E1/E3 premise). Confidence: high.
   Code: runtime.rs:1319-1329, 2089-2112, 1366-1380.
   Scenario: `bind_interface = "vrf-blue"` and the VRF is not yet created at boot. The socket is created unbound and connected to the peer, so frames go out through the main routing table, leaking outside the VRF, until the device appears. The spec requires the tunnel to stay disconnected until then.

9. **A bind device's own VRF enslavement does not reconnect the tunnels bound to it** (E4). Confidence: low, because the spec wording is ambiguous.
   Code: runtime.rs:1815-1824 (only a bound controller index is refreshed), 1598-1600.
   Scenario: a tunnel is bound to `eth1`, then `ip link set eth1 master vrf0`. Its routing context changes, but the only reconnect comes from incidental address events, so the source and route may stay stale.

10. **An overrun causes two full resyncs** (E20). Confidence: high, impact low.
    Code: runtime.rs:2452 (`Overrun` → `NetworkResyncRequested`) plus runtime.rs:2290-2299 after reopening.
    Each overrun reconnects every connected tunnel twice, and the first resync runs before the new socket is seeded.

11. **During `converge`, every event triggers a full reconcile** (E12). Confidence: high, impact low.
    Code: service.rs:172-196.
    After each dispatched event the loop goes straight back to `reconcile`. A burst of N address events during a slow start causes N back-to-back reconciles instead of one per second.

Not checked: how the kernel paces dump replies on a congested filtered socket (whether the unbounded seed dump at runtime.rs:2373 can ever hang), and the process, sessions and tunnels rules beyond where my rules reference them.


# Row-by-row cross-check of the first pass

Every first-pass row that is not plain "conforms", and every first-pass "conforms" row the second pass marks partial or defect, compared with the tables above; disagreements settled from the code. Summarised in the step 2 report, section "Row-by-row confirmation".

## Step 2 cross-check: first pass vs second pass (2026-10-28)

Scope: every first-pass row (R through L) that is not plain "conforms", plus every first-pass "conforms" row that the second pass marks PARTIAL, DEFECT or GAP. The already-settled items are left out (R4, R21/R22, G11, O5, A6, C1, C8, C10, T11, E2, V5, V6, V7, E20). Line numbers are at `741117b`.

Results: "D→2nd" means the second pass is right and "D→1st" means the first pass is right. "(dup X)" means the first pass already reports the same defect under rule X, so its verdict on this row is inconsistent, but nothing new was found.

| rule | first pass | second pass | result | evidence |
|---|---|---|---|---|
| R1 | partial (start-up exit) | PARTIAL (logs every second) | AGREE | service.rs:181, main.rs:1147 |
| R3 | conforms | PARTIAL | D→2nd (dup G13) | R3 = "host defect, as R1" = reported once; service.rs:181/278 warn every second |
| R5 | differs | DEFECT | AGREE | runtime.rs:2256-2262 |
| R7 | conforms | PARTIAL | D→2nd (dup P5) | A missing procfs is a host defect (retry, readiness withheld); `State::new` failure exits via service.rs:139 → main.rs:1147 |
| R9 | conforms | PARTIAL | D→2nd (dup G6) | EMFILE is retried but aborts the reconcile for every later entry (`try_apply!`, runtime.rs:778-790, 873-881) |
| R10 | conforms in effect (RCVBUF first, then FORCE) | CONFORMS ("FORCE then plain") | D→1st | netlink.rs:102 `set_rx_buf_sz` first, netlink.rs:106-116 `RcvBufForce` only when capped; the second pass's order is wrong, the outcome is the same |
| R14 | conforms | PARTIAL | D→2nd (dup P8) | Refusals 1-9 return from reconcile: runtime.rs:864-881, 1100-1107 |
| R16 | partial (system resolver only) | PARTIAL (discard, not disconnected) | AGREE | complementary reasons; runtime.rs:2709-2711, 496-499 |
| R18 | conforms (grouped with R17) | UNTESTABLE (scope) | SILENT → first pass wrong | R18's "when not met" is "the session is created again (S27)"; the first pass's own S27 row says this is missing; handle_interface_removed (runtime.rs:1717-1736) handles bind devices only |
| R26, R27 | conforms (grouped R24-R27) | PARTIAL | D→2nd | Both say "stays disconnected"; the code connects to a discard address: `AddressFamilyMismatch` counts as unreachable (runtime.rs:2220-2221), then connection_candidates (2190-2201); with no route, the discard grace also delays (2059-2067) |
| R35 | conforms (grouped R28-R36) | DEFECT | D→2nd (dup R5) | "Route changes are not subscribed to": runtime.rs:2260-2261 |
| R37-R42 | partial (L5, L8, L10) | R37/40/41/42 CONFORMS, R38 PARTIAL, R39 UNTESTABLE | AGREE | No `handle_event`, so R39 cannot be met (L10); the rest as L5/L8 |
| R44, R48 | missing | GAP | AGREE | |
| R46, R47 | missing | GAP / UNTESTABLE (C7 GAP) | AGREE | |
| G1 | differs | DEFECT | AGREE | The second pass adds SIGUSR2 (default action kills) and EPIPE on a dead parent (main.rs:1177-1183) |
| G3 | differs | UNTESTABLE (scope; sessions auditor) | SILENT → confirms first pass | Sessions auditor M11/M12/S17 DEFECT (runtime.rs:2564-2565 re-creates on `bind_interface`), M17 r5 (keyed by ids, runtime.rs:2735, 2781) |
| G5 | differs | DEFECT | AGREE | runtime.rs:2096-2104, 1367-1379, 2190-2201 |
| G6 | differs | DEFECT | AGREE | runtime.rs:864-881, 1100-1107 |
| G8 | differs | DEFECT | AGREE | |
| G10 | partial | PARTIAL | AGREE | |
| G12 | differs | DEFECT | AGREE | |
| G13 | differs | DEFECT | AGREE | |
| G14 | partial | PARTIAL | AGREE | |
| G15 | differs | DEFECT | AGREE | |
| G17 | conforms ("with the exceptions noted in E") | PARTIAL | D→2nd | Bounds row "bind device disappears: disconnected at once" fails (runtime.rs:1717-1736 only forgets the binding; state.rs:1432-1444); the bindv6only row is absent; conflicts block others for about 10 s |
| G19 | conforms | PARTIAL | D→2nd | The substitute for "disconnected" is a discard connection (runtime.rs:2190-2201); unstaged sessions have no temporary-name substitute (state.rs:1647) |
| G20 | differs | PARTIAL | AGREE | |
| G21 | partial | DEFECT | AGREE | |
| K4 | conforms | PARTIAL | D→2nd (dup T4) | AF_INET latch is sticky: state.rs:1206 |
| K5 | missing | GAP | AGREE | |
| K6 | missing (grouped with K5) | CONFORMS | D→2nd | K6's uses are peer changes and source reselection, and the code does connect/disconnect/reconnect: state.rs:1341-1380 (`socket.disconnect()` 1362) |
| K7 | differs | DEFECT | AGREE | |
| K8 | conforms | DEFECT | D→2nd (dup settled R4 and the "Not required" row) | In-place `SO_BINDTODEVICE` on a still-bound socket (runtime.rs:1655 → state.rs:1405-1421) needs CAP_NET_RAW; the null device needs `dummy` |
| K11, K13, K14, K39 | missing | GAP | AGREE | |
| K12 | conforms | PARTIAL (missing → exit) | D→1st | K12 states only the dependency; what happens when it is missing is R7/P5/H15, already counted there |
| "Not required" | differs | DEFECT | AGREE | |
| A1 | partial | PARTIAL | AGREE | |
| A4 | conforms | PARTIAL | D→2nd | The state layer holds policy: rollback to the previous peer (state.rs:1308-1318); resolver records live in runtime.rs:478-488 |
| A5 | partial | PARTIAL | AGREE | The second pass adds that the seed dump is sent on the filtered monitor socket (runtime.rs:2279) |
| A7 | conforms | PARTIAL (lazy reopen) | D→1st | Its own socket and task, an ordered lookup, a oneshot reply path (link_identity.rs:492-576); lazy reopen after a loss (343-355) breaks no A7 MUST, since the generation already ended |
| A8 | partial (order differs from M6) | CONFORMS | D→1st | Order: tunnel delete → … → final renames → session delete (runtime.rs:793-808, 990-1066); the second pass's own M6 row is DEFECT |
| A11 | conforms | PARTIAL | D→2nd (minor) | Per-resolver servers, subscription health and the P25 flag are not held; they follow from missing V/P25 |
| A13 | conforms | DEFECT | D→2nd (dup G6) | "never aborts the reconcile for other entries": `try_apply!` returns (runtime.rs:778-790) |
| A14 | conforms | PARTIAL | D→2nd | A nested wait shutdown cannot interrupt: `spawn_blocking(reload).await` outside the `select!` (service.rs:293-297) |
| A18 | partial | PARTIAL | AGREE | |
| A19 | missing | GAP | AGREE | |
| A21 | missing | GAP | AGREE | |
| M Terms | differs | (M7 rung 3 = discard) | AGREE | |
| M4 | differs | DEFECT | AGREE | |
| M6 | differs | DEFECT | AGREE | |
| M7 | conforms in shape | PARTIAL | D→2nd (dup S4/S7) | Rung 3 "temporary name while held": an unstaged session is created under the configured name (state.rs:1647); for a staged one, a publication failure aborts the reconcile (state.rs:600-606 → 1682) |
| M8 | conforms | PARTIAL | D→2nd (dup T22/M11) | M8: "the only identity changes are those of the matrix"; a `bind_interface` change re-creates (runtime.rs:2564-2565) |
| M9 | conforms | PARTIAL | D→2nd (dup S22/S4) | Check then delete in two operations (state.rs:732-740, 1921-1926); an unstaged creation-time name equals the configured name |
| M11, M12 | partial | DEFECT | AGREE | |
| M13 | partial | DEFECT/PARTIAL | AGREE | |
| M14 | partial | PARTIAL + GAP | AGREE | The second pass adds that the timer is fixed-rate, not fixed-delay (service.rs:261-262) |
| M16 | differs | PARTIAL | AGREE | |
| M17 | differs | DEFECT + GAP | AGREE | |
| P1 | partial | DEFECT | AGREE | |
| P2 | conforms (logging-order nit) | PARTIAL (same nit) | AGREE | Same finding, different label |
| P5 | differs | DEFECT | AGREE | |
| P6 | partial | DEFECT | AGREE | |
| P7 | differs | DEFECT | AGREE | |
| P8 | differs | DEFECT | AGREE | |
| P10 | conforms | PARTIAL | D→2nd | "The daemon remembers the inode it published": `write_pid_file` returns `Result<()>` (main.rs:185); the fallback runs only on `PermissionDenied` (main.rs:482) |
| P11 | differs | DEFECT | AGREE | |
| P12 | partial | PARTIAL | AGREE | The second pass adds that SIGHUP is not coalesced (main.rs:843-850) |
| P13 | partial ("reload semantics conform") | DEFECT | D→2nd | "a shutdown during a blocked callback proceeds without waiting": `spawn_blocking(...).await` is not raced with `shutdown_rx` (service.rs:293-297) |
| P14, P26 | missing | GAP | AGREE | |
| P15 | conforms | GAP | D→2nd (low) | No restart operation (P26); for a stop/start, the missing P17 wait can meet EEXIST, then the conflict retries (state.rs:1446-1466) |
| P16 | differs | PARTIAL | AGREE | |
| P17 | differs | DEFECT | AGREE | |
| P18 | conforms | DEFECT | D→2nd (= settled R22) | "Nothing else survives a crash": the null device and routes do (state.rs:1008-1111) |
| P21 | partial | DEFECT | AGREE | The second pass adds `ProtectSystem=full` |
| P22 | partial | PARTIAL | AGREE | |
| P25 | missing | GAP | AGREE | |
| C4 | differs | DEFECT | AGREE | |
| C5 | missing | PARTIAL/GAP | AGREE | |
| C6 | differs | DEFECT | AGREE | |
| C7 | partial | DEFECT ×4, GAP | AGREE | The second pass finds more: mapped literal, `""`/`"."`, out-of-range, unzoned link-local |
| C12 | differs | DEFECT | AGREE | |
| C14 | differs | UNTESTABLE (scope) | SILENT → confirms first pass | Final renames (runtime.rs:990-1021) run before session deletes (1057-1066); entries keyed by ids (2735, 2781); the second pass's S11/D1 probe reproduces this |
| C15 | partial | PARTIAL | AGREE | |
| C16, C17 | missing | GAP | AGREE | |
| T1, T2 | differs | GAP/DEFECT/PARTIAL | AGREE | |
| T4 | differs | PARTIAL | AGREE | |
| T6 | partial | GAP + CONFORMS | AGREE | |
| T8 | partial | CONFORMS + GAP | AGREE | |
| T10 | differs | PARTIAL + DEFECT | AGREE | |
| T12 | conforms | PARTIAL | D→2nd | "the tunnel is disconnected": handle_interface_removed only calls `forget_tunnel_binding` (runtime.rs:1717-1736; state.rs:1432-1444 "the kernel keeps the socket bound") |
| T13 | differs | DEFECT | AGREE | |
| T14 | conforms | PARTIAL | D→2nd (dup T1) | "until there is one … disconnected": FQDN gets a discard address (runtime.rs:2709-2711) |
| T15 | differs | CONFORMS + DEFECT | AGREE | |
| T16 | partial | PARTIAL | AGREE | |
| T17 | differs | DEFECT | AGREE | |
| T19 | conforms | PARTIAL | D→2nd | "when the bind device's VRF membership changes": VrfChanged carries controller indexes and is ignored unless the controller is bound (runtime.rs:1815-1818, 2388-2413); InterfaceChanged on an unchanged name continues (1600) |
| T20 | partial | PARTIAL | AGREE | |
| T21 | conforms | PARTIAL | D→2nd | Returns before the disconnect when the bound name is missing (state.rs:1353-1356, then disconnect at 1362); bare connect at state.rs:1320-1325 |
| T22 | differs | PARTIAL | AGREE | |
| T24 | conforms | PARTIAL | D→2nd (dup T8) | "waits for the kernel to release": delete_tunnel only drops the socket (state.rs:1446-1466) |
| T25 | partial (abort not mentioned) | DEFECT | D→2nd (dup P8) | "nothing else is affected" fails: runtime.rs:864-881; the test asserts it at runtime.rs:5830-5833 |
| T26, T27 | missing | GAP | AGREE | |
| T28 | differs | DEFECT | AGREE | |
| T29 | conforms | PARTIAL | D→1st | The daemon's own view exists (state.rs:1385-1390); "discard counted as connected" is the T1 design gap, already counted there |
| V1, V2, V9, V10, V12, V14 | missing | GAP | AGREE | |
| V4 | conforms | PARTIAL | D→2nd | "at once when the tunnel's configuration changes": an `ip_version` change only rewrites the family, with no lookup (runtime.rs:590-592); one resolver per tunnel, so a host name is looked up concurrently |
| V8 | conforms (grouped V7, V8) | CONFORMS + GAP | D→2nd | "a resolver that never answers … reported once": an unanswered FQDN silently gets a discard address (runtime.rs:2709-2711), with no report |
| V11 | missing | CONFORMS | D→2nd | Holds for the system resolver: resync never touches resolvers (runtime.rs:1218-1229); no ND_USEROPT group (2256-2262) |
| V13 | missing | DEFECT/GAP/CONFORMS | D→2nd | The system-resolver rows apply: answer change → reconnect is the T15/T28 defect; loss and shutdown conform |
| V15 | missing | PARTIAL | D→2nd | One iphost thread per tunnel, literal tunnels included (runtime.rs:496-499, 826-830), not per host name |
| S1 | conforms | PARTIAL | D→2nd (composite of S4/S7/S11/S27) | |
| S3 | partial | DEFECT | AGREE | |
| S4 | differs | DEFECT | AGREE | |
| S7 | differs | DEFECT | AGREE | |
| S10 | conforms | PARTIAL | D→2nd (dup G6) | A foreign-held rename target is an `Err` that aborts the reconcile (runtime.rs:1004-1009 via `try_apply!`) |
| S11 | partial | DEFECT | AGREE | |
| S12 | partial | PARTIAL | AGREE | |
| S13 | conforms | PARTIAL | D→1st | "Unusable" is the C8 grammar, which is caught at load (config.rs:85-97, C10 tolerated); a kernel refusal of a valid address (state.rs:565-569) is a transient failure, whose blocking is G6 |
| S15 | conforms | PARTIAL/UNTESTABLE | D→1st | S15 itself says "a refusal meanwhile is a transient conflict (T25)", and the code does exactly that; the abort is P8's |
| S17 | conforms | DEFECT | D→2nd (dup T22) | "anything about the tunnel that changes in place": a `bind_interface` change re-creates the tunnel and its sessions (runtime.rs:2564-2565) |
| S18 | conforms | PARTIAL | D→2nd (dup T22/S11) | The same re-creation removes children; the D1 livelock renames the survivor every second |
| S22 | differs | DEFECT | AGREE | |
| S23 | conforms | PARTIAL | D→2nd | A captured identity later `Invalidated` goes straight to discard and re-create (state.rs:1712-1713 → 1678-1680), with no re-identification at the broadcast index |
| S26 | differs | DEFECT | AGREE | |
| S27 | missing | GAP | AGREE | |
| E1 | conforms | PARTIAL | D→2nd | Binds in place with `bind_tunnel_interface` (runtime.rs:1655) before the reconnect, instead of binding through T21; this is EPERM without CAP_NET_RAW on a still-bound socket (settled R4); the "was disconnected" premise fails (T13) |
| E3 | partial ("bind device removal conforms") | PARTIAL (no disconnect) | D→2nd on the bind half | runtime.rs:1717-1736 does not disconnect; state.rs:1432-1435 says the kernel keeps the binding |
| E4 | conforms | PARTIAL | D→2nd | A bind device's own VRF membership change does not reconnect (see T19); every NEWLINK runs handle_discard_route_change and apply_pending_hwaddrs (runtime.rs:1586-1589) |
| E9 | differs | GAP | AGREE | |
| E10 | conforms | DEFECT | D→2nd (dup T15) | runtime.rs:1193-1201; state.rs:1308-1325 |
| E11 | conforms | DEFECT + PARTIAL | D→2nd (= settled V6/V7) | |
| E13 | conforms | PARTIAL | D→2nd | The retry uses `modify_tunnel` (runtime.rs:1547), which on a still-connected same-family socket is a bare `reconnect_ip` (state.rs:1320-1325), not the T21 reconnect E13 requires |
| E15, E16 | differs | n/a (code still has it) | AGREE | |
| E21 | partial | CONFORMS/PARTIAL | AGREE | |
| E23, E25, E26 | missing | GAP | AGREE | |
| E24 | missing (grouped E23-E26) | PARTIAL | D→2nd | No ND_USEROPT conforms; but the GETLINK seed dump is a request sent on the filtered monitor socket (runtime.rs:2279 with handle from 2255-2265; dump 2373-2384) |
| H1-H3 | conforms in shape | GAP / DEFECT / PARTIAL | D→2nd | H2 "its sessions exist": for a V6 tunnel, the 100:: candidate's `prepare_discard_route` returns Err during the 10 s grace and `?` aborts create_tunnel (runtime.rs:1324-1326, 2059-2067) before 192.0.0.8 is tried; H1 "nothing else exists": null device |
| H4 | partial | PARTIAL | AGREE | |
| H5 | partial | PARTIAL | AGREE | |
| H6 | partial | DEFECT | AGREE | |
| H7 | conforms | PARTIAL | D→2nd | Replacement VRF rebind is in place (settled R4); "unreachable default route leaves the tunnel disconnected" becomes a null device route in the VRF table (runtime.rs:2008-2012, 2069-2072) |
| H8 | differs | DEFECT | AGREE | |
| H11 | conforms | PARTIAL | D→2nd (minor) | The RA paragraph needs resolvers (missing); an unstaged session is not "a staged device published" (state.rs:1647) |
| H12 | partial | PARTIAL | AGREE | |
| H13 | conforms | PARTIAL | D→2nd (dup T12) | "unplugging disconnects": not done (runtime.rs:1717-1736) |
| H15 | differs | DEFECT | AGREE | |
| H17 | conforms | PARTIAL | D→2nd (dup M16) | runtime.rs:1586-1589, 1774-1798 |
| H18 | missing | GAP | AGREE | |
| O2 | partial | CONFORMS/DEFECT mix | AGREE | |
| O3 | differs | DEFECT | AGREE | |
| O4 | partial | PARTIAL | AGREE | |
| O6 | partial | PARTIAL | AGREE | |
| O7 | conforms | DEFECT | D→2nd (dup C6) | "`--check` exits … 1 with any, unknown keys included": unknown keys are ignored (no `deny_unknown_fields`, config.rs:484) |
| O8 | conforms | GAP | D→2nd | "no peer for an unusable endpoint": renders `remote_addr = "100::"` (main.rs:1117 renders config.rs:559-564 discard) |
| O9 | partial | PARTIAL/GAP | AGREE | |
| L3 | conforms | PARTIAL | D→2nd | "enums are non-exhaustive": `pub enum IpVersion` has no `#[non_exhaustive]` (config.rs:302-311) |
| L4 | conforms | PARTIAL | D→2nd (dup C7) | Validation is shared, but the rules it checks are incomplete (`%`, mapped, unzoned link-local, `""`) |
| L5 | partial | PARTIAL + DEFECT | AGREE | |
| L7 | partial (panic only) | DEFECT ×2 | D→2nd | The first pass missed "shutdown does not wait for a blocked callback": service.rs:293-297 |
| L8 | partial | DEFECT | AGREE | |
| L9 | conforms | GAP | D→2nd (dup L10) | L9 lists `handle_event`; none exists (service.rs:202-248 dispatches privately) |
| L10, L12 | missing | GAP | AGREE | |

### Counts

- AGREE: 105
- DISAGREE: 63. The second pass is right in 56; the first pass is right in 7 (R10, K12, A7, A8, T29, S13, S15).
- SECOND-PASS-SILENT: 3. G3 and C14 confirm the first pass; R18 shows the first pass is wrong.

Of the 56 where the second pass is right, about 30 add nothing new: the first pass reports the same defect under another rule but marked this row "conforms". The ones that add something new are R10 (reversed), P13/L7/A14 (shutdown blocked by a hung reload callback), P10 (inode not remembered), T12/E3/H13/G17 (no disconnect on bind-device removal), T19/E4 (a bind device's own VRF enslavement is ignored), T21 (early return before the disconnect), E13 (the peer retry uses a bare connect), E1 (in-place bind), E24 (seed dump on the filtered socket), H1-H3 (the grace period aborts before the other family's discard address is tried), S23, V4, V8, V11/V13/V15, K6, L3, O8, A4.
