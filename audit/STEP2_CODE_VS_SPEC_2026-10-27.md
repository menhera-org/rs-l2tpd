# Roadmap step 2: the code's behaviour against the specification — 2026-10-27

| Detail | Value |
|---|---|
| Code | `main` at `6dfa2a9` (`src/` last changed before the specification work; 16,400 lines in `src/`, plus `build.rs`) |
| Specification | `docs/spec/` as committed in `6dfa2a9` ("docs(spec): finish the specs"), with the resolver-page and link fixes made the same day |
| Method | Every source file was read in full (`lib.rs`, `error.rs`, `config.rs`, `service.rs`, `blocking.rs`, `runtime.rs`, `state.rs`, `state/link_identity.rs`, `netlink.rs`, `bin/main.rs` without its tests, `build.rs`) and compared with every numbered rule of every page. The `l2tp` 0.4.0 and `iphost` 0.3.3 sources in the cargo registry were read where a rule depends on them. `cargo test --all-features` was run (114 library tests, 18 binary tests, 1 doctest pass; 21 privileged tests ignored). Two throwaway unit tests were added, run and reverted: one confirms the name-takeover deadlock below, the other that `%` passes interface-name validation. Every Docker suite of `tests/docker/README.md` was then re-run on this tree with freshly built x86_64 musl binaries (current 0.2.0, baseline 0.1.5, the privileged test binary): the 21 privileged kernel tests, the 18-case interoperability matrix plain, with `MAC_RELOAD=1` and with `COOKIES=1`, address-changes (4 cases), discard-recovery (4), networkd-routes (2), networkd-sessions (3), session-children, session-identity (3), tunnel-ownership, monitor-resync, link-monitor-burst normal and `MODE=overflow`, degraded-start (10), source-and-peers (3), ipv6-disabled (4) and staging-loss (2). All passed on Linux 6.8.0-147. They test the current design, so they corroborate rather than contradict the rows below: degraded-start asserts that readiness waits for a route to `100::` and that the null device appears after the grace period (P7, G8); source-and-peers asserts the ten conflict retries (P8); link-monitor-burst and staging-loss show the identity rules of S19–S24 holding. |
| Verdicts | **conforms**: the code does what the rule says. **differs**: it does something else. **missing**: the rule's mechanism does not exist. **partial**: the rule holds in some cases. A verdict says what the code does, not whether the code or the rule should change; step 3 decides that. |

## Summary

The code implements the design the first audit described: tunnels are always connected, to a discard address (`100::`, `192.0.0.8`) when they have no peer, with a `dummy` null device and routes as the sink of last resort; the event monitor subscribes to the route groups to repair those routes; there are no configured resolvers, no descriptor hand-over, no restart operation and no `bindv6only` handling. Those four areas are **missing** and account for most of the rows below. They were expected.

Beyond them, the comparison found defects in the current code that the specification's unconditional promises forbid, independent of the design change:

1. **A removed session whose name a surviving session takes never converges** (C14, M6, S11). Final renames run before deletions in `reconcile`, so the rename to the taken name fails with `EEXIST` on every reconcile and the removed session is never deleted. Confirmed with a unit probe: three consecutive reconciles failed with "interface exists: l2tp1", the survivor stayed on `rsl2tp-r000002`, the removed session stayed. The daemon retries every second forever and the reload never completes.
2. **One failing entry blocks every entry ordered after it** (M4, G6). The first error other than an identifier conflict returns from `reconcile`; entries later in identifier order are not attempted until the next reconcile, and never while the error persists. Identifier conflicts have the same effect for their first nine refusals (P8).
3. **Readiness waits for things it must not wait for** (P6–P8, G8, G15): a session's publication under its configured name when a foreign device holds the name (the staging failure aborts the reconcile, so `converge` never returns), and a route to a discard address (a ten-second grace period, then the null device).
4. **A tunnel can stay connected to a peer the configuration or the resolver no longer names** (G5, T15, T17): a resolver answer that cannot be reached leaves the previous peer connected; a reload to an unreachable peer whose discard addresses cannot be reached either keeps the old peer; a bind device renamed away is not disconnected until the next reconnect, so frames keep leaving through the renamed device (T11).
5. **A session without a configured hardware address is not staged** (S4): it is created directly under its configured name, and a foreign device holding that name makes the kernel refuse the creation, which the code counts as an identifier conflict (ten retries, then left out with a wrong diagnosis) instead of a transient publication failure (S7).
6. **A kernel-interface failure at start-up exits the daemon** (P5, H15, M13, G1) instead of withholding readiness and retrying.
7. **The PID file is removed unconditionally at shutdown** (P11), and a PID-file publication failure makes the parent exit 1 and the daemon shut down (P11 says it keeps running and the parent exits 0).
8. **An interface name containing `%` passes validation** (C7, S3, K32). The probe shows `L2tpIfName::from_name("l2tp%d")` succeeding (non-ASCII bytes pass too, which the kernel allows). The kernel expands such a name at creation, so the creation watch armed for the literal name never captures the device, the kernel's stored name differs from the handle's, the session is reported as "no longer this daemon's session" and forgotten while it exists in the kernel, and the second attempt is refused as an identifier conflict. Nothing in the suites configures such a name, so this is a reading result confirmed only at the validation step.

The rest are smaller: logging on every retry instead of once per episode (G13, O3), per-event kernel lookups on unrelated address events (M16), the `AF_INET` latch never re-probed (T4), bare `connect` for same-family peer changes (T28), a session deletion by identifiers rather than by creation-time name (S22), deterministic temporary names (S4), a lookup timeout of five seconds rather than two (E21), and a few library-contract gaps (L5, L8, L10).

Two places where the code is stricter or safer than the rule, for step 3 to decide which way to go:

- **A configuration entry renamed with unchanged identifiers keeps its kernel objects.** The reconciler keys entries by identifier, not by configuration name (`build_desired_maps`), so a rename of `[tunnels.a]` to `[tunnels.b]` changes nothing in the kernel. C14 and M17 say it is a removal and an addition. The code's behaviour preserves interface identity, which is the hard rule's direction.
- **A tunnel's `bind_interface` change re-creates the tunnel** (the known gap of T22) because of the previous rule set; the specification's in-place reconnect is strictly better and already decided.

## Requirements (R)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| R1 | partial | Operations fail and are retried every second with readiness withheld; but a failure to open the kernel interfaces at start-up exits the daemon (see P5). | `src/bin/main.rs:1147`, `src/service.rs:136-148` |
| R3 | conforms | `CAP_NET_ADMIN` is needed for the netlink operations; no other capability is used. | — |
| R4 | conforms | `SO_BINDTODEVICE` is only ever applied to a socket without a binding: at creation, after a disconnect, or on a socket created unbound. The crate doc and `src/lib.rs:27-28` still say `CAP_NET_RAW` is needed; that is a documentation error. | `src/state.rs:652-669`, `1341-1370`, `1405-1421` |
| R5 | differs | The monitor subscribes to the link, both address and **both route** groups; the kernel filter keeps only link and address messages and the removal of a discard route. No `RTNLGRP_ND_USEROPT`. | `src/runtime.rs:2255-2262`, `src/netlink.rs:157-171` |
| R6 | conforms | The classic BPF filter is attached; a failure is a warning and the monitor runs unfiltered. | `src/netlink.rs:61-68` |
| R7 | conforms | Through the `l2tp` crate's namespace handling. | — |
| R9 | conforms | One L2TP/IP socket per tunnel; short-lived rtnetlink connections per operation. | `src/state.rs:42-47` |
| R10 | conforms in effect | `SO_RCVBUF` is tried first and `SO_RCVBUFFORCE` only when it was capped; the specification names the order the other way round, the result is the same. The default is kept when it is larger. | `src/netlink.rs:90-125` |
| R11, R12 | conforms | — | `src/bin/main.rs:119-173` |
| R13 | conforms | Start-up leaves an unreadable file out; a reload keeps the previous configuration. | `src/bin/main.rs:745-815` |
| R14 | conforms | Identifiers and names unique within the configuration (session identifiers across tunnels); kernel refusals handled as conflicts. | `src/config.rs:853-908`, `src/runtime.rs:1489-1505` |
| R15 | conforms | — | `src/state.rs:1613-1626` |
| R16 | partial | Only the system resolver (libc through `iphost` 0.3.3). | `src/runtime.rs:496-499` |
| R17, R18 | conforms | Foreign replacements are never deleted; see S21/S22. | `src/state.rs:1446-1466`, `1889-1937` |
| R19 | conforms | `rsl2tp-t…` and `rsl2tp-r…` names are the daemon's; a foreign device under one is skipped. | `src/state.rs:338-345`, `src/runtime.rs:2619-2651` |
| R21, R22 | conforms | PID file path is an argument; a kill leaves nothing behind. | `src/bin/main.rs:40-42` |
| R23 | conforms | — | `src/state.rs:103-115` (S12) |
| R24–R27 | conforms | `AF_INET` sockets refuse IPv6 peers before any socket call. | `src/state.rs:702-717` |
| R28–R31, R34–R36 | conforms | See the S and T rows. | — |
| R37–R42 | partial | See L5, L8, L10. | — |
| R43 | conforms | Nothing under `/sys` is read; `/proc/self/exe` is read by `--setup` only. | `src/bin/main.rs:1007` |
| R44, R48 | missing | No `IPV6_V6ONLY` read-back, no tunable write, no `host` table. | — |
| R45 | conforms | — | `src/state.rs:296-326` |
| R46, R47 | missing | No resolvers; no zone in `remote_addr` (see T27). | — |

## Promises (G)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| G1 | differs | The daemon exits when the kernel interfaces cannot be opened at start-up, and when the PID file cannot be written (P11). No panic on input was found. | `src/bin/main.rs:1147`, `1163-1176` |
| G2 | conforms | Ownership is proved before every change: link identities, the kernel's creation-time name, the socket for tunnels. | `src/state/link_identity.rs`, `src/state.rs:732-740` |
| G3 | differs | `bind_interface` changes re-create the tunnel and its sessions (known gap). A configuration-entry rename keeps everything (see the summary). | `src/runtime.rs:2564-2569`, `2724-2785` |
| G4 | conforms | Never lowers a device; defers the hardware address instead. | `src/state.rs:548-580` |
| G5 | differs | Tunnels are connected to a discard address; a tunnel whose bind device is absent at creation is created unbound and connected through the main table; a renamed-away device keeps carrying frames until a reconnect; an unreachable resolver answer leaves the old peer connected. | `src/runtime.rs:2089-2113`, `1367-1380`, `1193-1201`, `1413-1421`; `src/state.rs:1436-1444` |
| G6 | differs | The first error of any kind except a counted conflict returns from `reconcile`; entries after it in identifier order wait for the next reconcile. | `src/runtime.rs:778-790`, `1086-1108` |
| G7 | conforms | At the configuration layer. | `src/config.rs:790-849`, `src/bin/main.rs:780-815` |
| G8 | differs | Readiness waits for a session's publication under its configured name (a staging failure returns an error, so `converge` loops) and for a route to a discard address. | `src/service.rs:170-198`, `src/runtime.rs:1997-2087`, `src/state.rs:586-608` |
| G9 | conforms, no exception | No hand-over exists, so every restart tears down and re-creates. | — |
| G10 | partial | `CAP_NET_ADMIN` only; no `bpf()`; no tunable is written. But the null device needs the `dummy` driver and the daemon installs routes, which the kernel page lists as not required. | `src/state.rs:1061-1111` |
| G11 | conforms | Cookie `Debug` gives the length; logs print "set"/"none". | `src/config.rs:242-246`, `src/runtime.rs:2515-2522` |
| G12 | differs | Route groups are subscribed to (filtered to discard route removals); an address event on a device no tunnel is bound to still costs a VRF-master lookup when any tunnel is bound; every link event re-installs the recorded discard routes. | `src/runtime.rs:1774-1798`, `1586-1588` |
| G13 | differs | Failed reconnects are logged at warning level on every retry; so is an incomplete reconcile ("will retry") every second. | `src/runtime.rs:1894-1897`, `1286-1290`; `src/service.rs:181`, `278` |
| G14 | partial | See L5, L8, L10. | — |
| G15 | differs | See G8. | — |
| G16 | conforms | — | — |
| G17 | conforms | Within the bounds below, with the exceptions noted in E. | — |
| G18 | conforms | An unchanged reload changes nothing; pending work is retried. | `src/runtime.rs:3786-3855` (test) |
| G19 | conforms | Overrides acknowledged; configured changes applied by index. | `src/state.rs:1803-1831`, `1850-1887` |
| G20 | differs | Shutdown deletes tunnels first by closing their sockets; sessions are not deleted first; no wait for the kernel to finish (P16, P17). The exit code reports failures. | `src/runtime.rs:1966-1986`, `793-808`; `src/state.rs:1446-1466` |
| G21 | partial | Readiness without routes to peers, but not without a route to a discard address (grace period, null device). | `src/runtime.rs:55-58`, `1997-2087` |
| G22 | conforms | — | — |
| G23 | conforms | Bounded by the configuration; one resolver watcher task per tunnel. | — |

## Kernel page (K)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| K1–K4, K8, K9, K12 | conforms | — | — |
| K5, K6 | missing | Tunnels are never left disconnected; the no-peer state is a connection to a discard address. | `src/runtime.rs:2190-2201`, `src/state.rs:1177-1212` |
| K7 | differs | Route groups subscribed to. | `src/runtime.rs:2259-2261` |
| K10 | conforms | Classic BPF only; no `bpf()`. | `src/netlink.rs:173-293` |
| K11, K13, K14, K39 | missing | No `bindv6only` handling, no resolvers. | — |
| "Not required" list | differs | The `dummy` driver, routes and the route groups are required by the current code. | `src/state.rs:328-334` |

## Architecture (A)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| A1 | partial | The binary owns files, logging, daemonisation, the readiness pipe, the PID file and signals; no tunable write, no hand-over. | `src/bin/main.rs` |
| A2–A4 | conforms | — | `src/service.rs`, `src/runtime.rs`, `src/state.rs` |
| A5 | partial | Requests on sockets of their own, never on the monitor: conforms. The lifetime subscription is a dedicated unfiltered `RTNLGRP_LINK` socket read by its own task: conforms. The monitor subscribes to route groups: differs. Resolvers: system only. | `src/state/link_identity.rs:242-260`, `src/runtime.rs:2255-2262` |
| A6 | differs | The channel is bounded (256) but the monitor task awaits `send` when it is full instead of dropping the event and marking a resync; loss then shows up as a kernel-side overflow. Shutdown has its own persistent flag: conforms. | `src/runtime.rs:2320`, `src/service.rs:24`, `112-116` |
| A7 | conforms | Own socket, own task, request-reply through a oneshot, proofs kept in the worker. | `src/state/link_identity.rs:521-577` |
| A8 | partial | Operations are sequential; ordering differs from M6 (see M6). | — |
| A9 | conforms | 30 s refresh, 1 s poll, nothing blocks the loop. | `src/runtime.rs:53-54`, `520-565` |
| A10–A12 | conforms | — | — |
| A13 | conforms | Monitors reopen themselves; a resolver failure keeps the last answer. | `src/runtime.rs:2242-2348` |
| A14 | conforms | — | — |
| A18 | partial | The filter is an optimisation: conforms; route events are subscribed to: differs. | — |
| A19 | missing | Substitute peer design. | — |
| A21 | missing | No `handle_event`; see L10. | — |

## Model (M)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| Terms | differs | "Disconnected" does not exist as a state; a tunnel without a peer is connected to a discard address. | `src/runtime.rs:74-82` |
| M1 | conforms | — | `src/runtime.rs:772-1129` |
| M2 | conforms | — | tests at `src/runtime.rs:3786-3855` |
| M3 | conforms | Partial progress is recorded on every error. | `src/runtime.rs:778-790` |
| M4 | differs | The first non-conflict error stops the reconcile; later entries wait. The first nine refusals of an identifier also stop it (see P8): the existing test asserts that the session ordered after the refused one is not created during those nine attempts. | `src/runtime.rs:864-882`, `1100-1108`; test at `src/runtime.rs:5830-5833` |
| M5 | conforms | Start-up, reload, 1 s retry, 30 s conflict retry. | `src/runtime.rs:1516-1576` |
| M6 | differs | Tunnels are deleted before their sessions; final renames run before session deletions, so a name released by a removed session cannot be claimed (the deadlock in the summary). | `src/runtime.rs:793-808`, `990-1066` |
| M7 | conforms in shape | The ladder exists with the discard address in the "substitute" rung. | — |
| M8 | conforms | Promotion in place: pending peers retried, bind devices bound when they appear. | `src/runtime.rs:1540-1576`, `1583-1679` |
| M9, M10 | conforms | — | `src/state/link_identity.rs:400-428` |
| M11, M12 | partial | Identity kept for everything except `bind_interface` (re-created, known gap). | `src/runtime.rs:2564-2569` |
| M13 | partial | Transient failures retried every second; conflicts bounded; unmanageable devices skipped and reported once; host defect at start-up exits (G1); the defect class (`EAFNOSUPPORT`, `EPERM`) is not told apart. | `src/runtime.rs:2206-2240` |
| M14 | partial | Intervals match (1 s, 10 conflict attempts, 30 s left-out retry, 30 s refresh, 1 s poll); a ten-second discard-route grace period exists that the specification has removed; no wait for a deleted tunnel to leave the kernel (its conflicts are absorbed by the retries). | `src/runtime.rs:53-72` |
| M15 | conforms | One retry per bound device, one for unbound tunnels, one peer timer, one route-repair timer, one watcher per tunnel. | `src/runtime.rs:692-712` |
| M16 | differs | See G12. | — |
| M17 | differs | `bind_interface`: re-creates. Configuration rename: keeps. Hand-over rows: not applicable. | — |
| M18 | conforms | Generations end on the lifetime socket's loss only; the event monitor's loss causes a resync. | `src/state/link_identity.rs:188-199`, `src/runtime.rs:1218-1229` |
| M19 | conforms | Skipped changes recorded as applied and reported once; deferred changes retried on link events; the creation-time address restored when the key is removed. | `src/state.rs:742-759`, `1850-1887` |

## Process (P)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| P1 | partial | Starts before the network, except the discard-route wait. | — |
| P2 | conforms | Order: chdir, arguments, logging, load, report, daemonise, apply. The specification lists logging before the command line; the verbosity flag needs the command line first (a nit for step 4). | `src/bin/main.rs:1083-1140` |
| P3 | conforms | — | `src/bin/main.rs:1116-1126` |
| P4 | conforms | Double fork, readiness pipe, umask 022, only the PID file and its directories created. | `src/bin/main.rs:119-173` |
| P5 | differs | A failure to open the kernel interfaces exits the daemon (parent exits 1). | `src/bin/main.rs:1147`, `src/service.rs:139` |
| P6 | partial | Readiness is `converge` returning: every entry applied except left-out conflicts; temporary names qualify; a deferred hardware address qualifies. But see G8. | `src/service.rs:170-198` |
| P7 | differs | Readiness waits for publication under the configured name and for a discard route. | see G8 |
| P8 | differs | Conflict retries stop the reconcile for their first nine attempts, so the other entries are applied only at the tenth (about ten seconds), not concurrently. | `src/runtime.rs:864-882` |
| P9 | conforms | Reloads ignored before readiness; kernel and resolver events handled. | `src/service.rs:187-195` |
| P10 | conforms | Fresh inode, atomic replacement, guarded in-place update, directory checks, symlinks refused. | `src/bin/main.rs:185-538` |
| P11 | differs | The PID file is removed unconditionally at shutdown; a publication failure makes the parent exit 1 and shuts the daemon down. | `src/bin/main.rs:540-546`, `1163-1176` |
| P12 | partial | `SIGHUP` reload, `SIGTERM`/`SIGINT` shutdown, shutdown wins over queued reloads, reloads serialised. No `SIGUSR2`. | `src/bin/main.rs:837-868` |
| P13 | partial | Reload semantics conform; a callback panic ends the service with an error but without an ordered cleanup (the sockets close with the process; the null device survives). | `src/service.rs:291-327` |
| P14, P26 | missing | — | — |
| P15 | conforms | — | — |
| P16 | differs | Tunnels deleted first by closing sockets; sessions go with them; the PID file is removed afterwards. | `src/runtime.rs:1966-1986`, `src/bin/main.rs:1193` |
| P17 | differs | No wait for a tunnel to leave the kernel; the crate's waiting `delete_tunnel` is not used (the socket is dropped, as T8 wants). The comment at `src/runtime.rs:1963-1965` claims a wait that does not happen. Exit code conforms. | `src/state.rs:1446-1466` |
| P18, P19 | conforms | — | — |
| P20 | conforms | — | — |
| P21 | partial | Ordering, `Type=forking`, PID file, `TimeoutStartSec=infinity`, `Restart=on-failure`, address families including `AF_UNIX`, no capability restriction: conform. `ProtectKernelTunables=yes` forbids the `bindv6only` write; no `NotifyAccess`/`FileDescriptorStoreMax`. | `src/bin/main.rs:965-1001` |
| P22 | partial | Without `SIGUSR2`. | — |
| P23 | conforms | No systemd, D-Bus or layout dependency; `--setup` is an installer only. | — |
| P24 | conforms | musl builds exist. | `build-release.sh` |
| P25 | missing | — | — |

## Configuration (C)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| C1 | partial | Main file first, drop-ins by byte order, `.toml` case-insensitively. A non-UTF-8 name is skipped silently, not with a warning. | `src/bin/main.rs:649-699` |
| C2, C3 | conforms | — | `src/config.rs:496-505`, `src/bin/main.rs:745-815` |
| C4 | differs | A dangling symbolic link is treated as an absent file (`fs::metadata` reports it as not found), not as an error; a loop is an error. | `src/bin/main.rs:650-657` |
| C5 | missing | Only `tunnels` and `sessions`; no `resolvers`, no `host`. | `src/config.rs:483-490` |
| C6 | differs | Unknown keys are ignored silently (no `deny_unknown_fields`, no reporting); `--check` cannot report them. | `src/config.rs:483-490` |
| C7 | partial | `tunnel_id`, `peer_tunnel_id`, `ip_version` conform. `remote_addr`: no zone syntax (a zoned literal is an unusable endpoint), no link-local rule; `resolver_name` absent. Interface names: `%` and non-ASCII bytes are accepted (probe), against the rule's "no `%`". | `src/config.rs:593-614`, `1076-1097`; `l2tp-0.4.0/src/types.rs` |
| C8 | conforms | — | `src/config.rs:132-152`, `253-269`, `876-908` |
| C16, C17 | missing | — | — |
| C9 | conforms | Name order, the later entry loses. | `src/config.rs:790-849` |
| C10 | conforms | An unusable endpoint gets the discard address of the family chosen as C10 says; the rest matches. | `src/config.rs:551-590`, `src/bin/main.rs:745-770` |
| C11 | conforms | — | `src/runtime.rs:885-918` |
| C12 | differs | One pass in name order: a retained entry inserted early blocks a later new valid entry, which is then retained or rejected itself; the specification's two passes would refuse the reload naming the retained entry. The other rows conform (file problem refuses; new broken entry left out; previous values that no longer fit refuse). | `src/config.rs:790-849`, `src/bin/main.rs:780-815` |
| C13 | conforms | — | `src/service.rs:77-81` |
| C14 | differs | Entry rename keeps the objects; swaps conform; name takeover from a removed session never converges. | `src/runtime.rs:2724-2785`, `960-1066` |
| C15 | partial | Strict conversion fails on the first problem; unknown keys cannot be reported. | `src/config.rs:737-746` |

## Tunnels (T)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| T1, T2 | differs | No disconnected state; binding by name. | — |
| T3 | conforms | — | `src/state.rs:696-717` |
| T4 | differs | The first refusal latches every later tunnel to `AF_INET`; never probed again. The `AF_INET` forms conform. | `src/state.rs:816-818`, `1180-1212` |
| T5 | conforms | No option but the binding (the crate sets `SOCK_CLOEXEC` and, for UDP only, checksum options). | `l2tp-0.4.0/src/socket.rs:900` |
| T6 | partial | Close-on-exec: conforms. Created disconnected: differs (connected at creation). | `src/state.rs:1214-1270` |
| T7 | conforms | — | `src/runtime.rs:2227-2240` |
| T8 | partial | Deleted by closing the socket, never by identifier: conforms. The two-second wait: not done. | `src/state.rs:1446-1466` |
| T9 | conforms | — | — |
| T10 | differs | `SO_BINDTODEVICE` by name with an index check before and after (known gap). | `src/state.rs:652-669` |
| T11 | differs | A renamed-away device is noticed and the binding marked invalid, but the socket is not disconnected until the next reconnect. | `src/runtime.rs:1598-1608`, `src/state.rs:1436-1444` |
| T12 | conforms | — | `src/runtime.rs:1717-1736` |
| T13 | differs | Created unbound and connected when the device is absent (known gap). | `src/runtime.rs:2089-2113` |
| T14 | conforms | — | `src/runtime.rs:649-661` |
| T15 | differs | A new answer that cannot be reached leaves the tunnel on the previous peer (DNS path). | `src/runtime.rs:1193-1201`, `1473-1477` |
| T16 | partial | The unreachable set matches the table; `EAFNOSUPPORT`/`EPERM` are not classified as defects; link-local without a scope is treated as unreachable rather than a configuration mistake. | `src/runtime.rs:2206-2224` |
| T17 | differs | See T15; also a reload to an unreachable peer keeps the old peer when the discard addresses are unreachable too. | `src/runtime.rs:1413-1421` |
| T18 | conforms | — | `src/runtime.rs:1856-1863`, `1262-1265` |
| T19 | conforms | Bound: address events on the device or VRF members, membership changes; unbound: own source removed; resync. | `src/runtime.rs:1774-1798`, `1235-1239`, `1218-1229` |
| T20 | partial | Retries per device and shared for unbound, resolving the name again: conform. A connect that leaves the socket with an unspecified source is treated as failed in the daemon's view, but the kernel socket stays connected with that source. | `src/state.rs:837-862`, `1372-1377` |
| T21 | conforms | Disconnect, rebind by configured name, connect. | `src/state.rs:1341-1380` |
| T22 | differs | `bind_interface` re-creates (known gap). | `src/runtime.rs:2564-2569` |
| T23, T24 | conforms | — | — |
| T25 | partial | Ten attempts, then left out, 30 s and reload retries, sessions taken along: conform. No information message when the entry is finally created. | `src/runtime.rs:1489-1512`, `856`, `1109-1110` |
| T26 | missing | — | — |
| T27 | missing | No zone syntax; a link-local peer without a scope is `ScopeRequired`, treated as unreachable, so the tunnel stays on the discard address for good. | `src/runtime.rs:2218-2221` |
| T28 | differs | A same-family peer change on a connected, validly bound socket is a bare `connect` (keeps the previous source); other cases are full reconnects. | `src/state.rs:1297-1325` |
| T29 | conforms | — | `src/state.rs:1385-1390` |

## Resolvers (V)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| V1, V2, V9–V15 | missing | System resolver only. | — |
| V3 | conforms | `iphost` 0.3.3 resolves through the libc. | — |
| V4 | conforms | 30 s refresh, 1 s poll, lookups on a thread of the resolver. | `src/runtime.rs:53-54` |
| V5 | conforms | `iphost` 0.3.3 keeps the previously selected address while the answer still contains it and takes the first one otherwise (its "stable resolution" loop); unusable addresses are skipped with a warning. | `src/runtime.rs:644-654`, `1170-1182`; `iphost-0.3.3/src/lib.rs` |
| V6 | conforms in effect | `retain_stale_values` is not enabled (the 0.3.3 default is off), so a negative answer clears the cached family address; the daemon then ignores the empty answer and keeps the peer, so the tunnel's state matches the rule. The MUST on the option is not met. | `src/runtime.rs:496-499`, `1170-1182` |
| V7, V8 | conforms | A changed host name gets a new resolver; a changed family re-targets; readiness never waits. | `src/runtime.rs:580-597` |

## Sessions (S)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| S1, S2 | conforms | — | — |
| S3 | partial | Explicit name, no sequencing, no sublayer: conform. A configured name with `%` is not refused, so the kernel picks the name from its own pool and the daemon cannot identify the device it created (summary item 8). | `src/state.rs:1613-1626`, `1735-1757` |
| S4 | differs | Only sessions with a configured hardware address are staged; temporary names come from a counter plus the PID, not a random source. | `src/state.rs:338-345`, `1647`, `1735-1757` |
| S5, S6 | conforms | — | `src/state.rs:586-608`, `1628-1638` |
| S7 | differs | For an unstaged session, a foreign device holding the configured name makes the kernel refuse the creation; the refusal is counted as an identifier conflict (ten retries, left out, "another tunnel or session holds them"). For a staged session the publication failure aborts the reconcile (G6, G8). | `src/runtime.rs:1100-1108`, `src/state.rs:1724-1731` |
| S8, S9 | conforms | Index from the registration broadcast; ordered lookup barrier on the same socket. | `src/state/link_identity.rs:385-398`, `455-490` |
| S10 | conforms | — | — |
| S11 | partial | Swaps through temporary names conform; takeover from a removed session deadlocks. | `src/runtime.rs:960-1066` |
| S12 | partial | Deferral and restoration conform; the deferral is logged at information level on every reconcile that carries it. | `src/runtime.rs:1041`, `2524-2532` |
| S13–S18 | conforms | — | — |
| S19–S21, S23, S24 | conforms | — | `src/state/link_identity.rs`, `src/state.rs:1527-1551` |
| S22 | differs | The ownership check (`get` and compare the creation-time name) and the deletion (by identifiers) are two kernel operations; the crate offers `delete_session_by_ifname`, which the daemon does not use. | `src/state.rs:732-740`, `1921-1926` |
| S25 | conforms | — | — |
| S26 | differs | Deleting a tunnel does not delete its provable sessions first. | `src/runtime.rs:793-808` |
| S27 | missing | An externally deleted session is not re-created until its configuration changes or the daemon restarts (known gap). | — |

## Events (E)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| E1 | conforms | — | `src/runtime.rs:1583-1679` |
| E2 | partial | Follows the name; does not disconnect at once (T11). | — |
| E3 | partial | Bind device removal conforms; session device removal ends the proof but does not re-create (S27). | `src/runtime.rs:1717-1736` |
| E4, E5 | conforms | — | `src/runtime.rs:1685-1713`, `2416-2460` |
| E6, E7 | conforms | — | `src/runtime.rs:1774-1798`, `1235-1239` |
| E8 | conforms | — | `src/runtime.rs:1902-1919` |
| E9 | differs | Route removals of discard routes are subscribed to and repaired. | `src/runtime.rs:1925-1961` |
| E10, E11 | conforms | — | — |
| E12–E14 | conforms | — | `src/service.rs:272-281`, `src/runtime.rs:1540-1576` |
| E15, E16 | differs | A grace period and route repair exist. | `src/runtime.rs:55-58`, `1925-1961` |
| E17–E19 | conforms | — | `src/service.rs:291-327` |
| E20 | conforms | Monitor loss reopens, seeds, resyncs bindings and connected tunnels and re-checks deferred addresses; lifetime loss ends the generation only. The channel overflow row does not apply (A6). | `src/runtime.rs:2242-2348`, `1218-1229` |
| E21 | partial | `ENOBUFS`/stream end, missing reply and socket error are each a loss; `NETLINK_NO_ENOBUFS` unset. The lookup timeout is five seconds, not two. | `src/state/link_identity.rs:262-281` |
| E22 | conforms | — | `src/runtime.rs:2309-2315` |
| E23–E26 | missing | — | — |

## Hosts (H)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| H1–H3 | conforms in shape | With a discard address instead of a disconnected state. | — |
| H4 | partial | `AF_INET` sockets: conforms; never re-probed (T4). | — |
| H5 | partial | See T20. | — |
| H6 | partial | Readiness waits for a route to a discard address (grace, null device). | — |
| H7 | conforms | — | — |
| H8 | differs | Route events are subscribed to; the kernel filter drops all but discard-route removals, so the cost is small but not zero. | — |
| H9, H10, H11, H13, H14, H16, H17 | conforms | — | — |
| H12 | partial | See S7. | — |
| H15 | differs | Exits at start-up (P5). | — |
| H18 | missing | — | — |
| H19 | conforms | — | — |

## Observability (O)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| O1 | conforms | `env_logger` to standard error; `--verbose` is debug. | `src/bin/main.rs:1089-1097` |
| O2 | partial | Start-up left-out: error; tolerated: warning; reload kept/left out: warning; whole reload refused: logged at warning, not error. | `src/service.rs:304` |
| O3 | differs | Reconnect retries and incomplete-reconcile retries are logged at warning level every second. | see G13 |
| O4 | partial | Messages carry identifiers; configuration names appear only in configuration problems, not in runtime messages. | — |
| O5 | conforms | — | — |
| O6 | partial | Errors are passed through with their text ("File exists (os error 17)"), not with errno names. | — |
| O7 | conforms | — | `src/bin/main.rs:1142-1196` |
| O8 | conforms | — | `src/bin/main.rs:1116-1126` |
| O9 | partial | The null device `rsl2tpnull…` is an object of the daemon's that the rule says does not exist. | `src/state.rs:334` |

## Library (L)

| Rule | Verdict | The code | Evidence |
|---|---|---|---|
| L1 | conforms | — | `src/lib.rs:15-18` |
| L2 | conforms | `#![deny(unsafe_code)]`; the test module opts out. | `src/lib.rs:60` |
| L3, L4 | conforms | — | — |
| L5 | partial | `new` fails at once; `converge` retries; `run` without `converge` does **not** converge first: nothing is applied until a reload. | `src/service.rs:256-342` |
| L6 | conforms | — | `src/service.rs:62-117` |
| L7 | partial | Error keeps the previous configuration; panic ends the service with an error, without the ordered cleanup. | `src/service.rs:309-312` |
| L8 | partial | Dropping the blocking service without `run` drops the runtime: sockets close, no ordered shutdown, the null device survives. | `src/blocking.rs:84-86`, `152-160` |
| L9 | conforms | — | `src/runtime.rs:717-764` |
| L10 | missing | No `handle_event`; per-kind methods only (known gap). | `src/service.rs:202-248` |
| L11 | conforms | — | `src/error.rs` |
| L12 | missing | — | — |

## Decisions for step 3

Each of these is a case where the code and the rule disagree and the rule could reasonably go either way; everything else above is a defect of the code against a rule already decided.

1. A configuration entry renamed with unchanged identifiers: the code keeps the kernel objects; C14/M17 say re-create. Keeping them serves the hard rule on interface identity.
2. Logging a session's deferred hardware address on every reconcile (S12 says once).
3. The lifetime lookup timeout: five seconds in the code, two in E21.
4. `SO_RCVBUF` before `SO_RCVBUFFORCE` (R10 names the other order; same result).
5. P2's start-up order: logging cannot precede the command line that sets its level.

## Not checked

The exact kernel behaviour of a socket left connected with an unspecified source (T20), which the specification's disconnected state makes moot; a `%` name end to end on a live kernel (its validation step is confirmed, the rest follows from the code); the suites were run on this host's kernel 6.8.0-147 only, as their guide says.
