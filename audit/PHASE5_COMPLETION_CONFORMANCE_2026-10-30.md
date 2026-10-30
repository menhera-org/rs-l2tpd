# Phase 5 completion conformance check, 2026-10-30

Review of the whole tree at commit `0cf9252` (main) against `docs/spec`,
with three questions: does the specs-based build regress a running 0.1.5
installation (VRF, bind-device and systemd-networkd race setups, and the
reconnection paths in particular), does it have security problems, and
where does it deviate from the specification. The earlier
[phase 5 review](PHASE5_CONFORMANCE_REVIEW_2026-10-29.md) covered the
phase 5 diff; this one covers the tree, and verified claims by running
the suites and by live experiments, not by reading alone.

Verdict: the build conforms to the specification in substance and is
strictly better than 0.1.5 on every reconnection path exercised live
(bind device appearing late or renamed, VRF membership, address churn,
peer without a route, FQDN changes, reloads in place). It is not
release-ready: one spec-level design choice (staging every session under
a temporary name, S4) regresses every 0.1.5 installation that relies on
udev's persistent MAC policy, one reconnect path disconnects for good,
and a handful of robustness defects in the binary and reconciler need
fixing. Nothing found gives an unprivileged party control of the daemon.

Everything below is a fix list entry. Tick it when the fix lands and cite
the number in the commit message.

## Decisions, 2026-10-30

Taken by the maintainer the same day; the specification was amended in
the same commit where a decision changes a rule.

Fix status, 2026-10-30: A1–A6, B1–B11, C1–C6, D1–D12 and E1–E4
are complete (including the decisions resolved by specification changes).
Verification evidence is in [phase5-completion/fixes/](phase5-completion/fixes/):
the current CI gates, musl and glibc live suites on Ubuntu 6.8.0-147,
QEMU 6.12.114, 6.18.59 and vanilla 7.3, the actual user-systemd store,
scoped-device replacement, and systemd 255/259 MAC and networkd checks
pass. The ignored V10/V14 adapter tests ran on the host and in QEMU.
Only this status and the checklist were updated; no specification or
other documentation changed in the code-fix work.

E5 remains Phase 6 work: strict rule mapping reports 101 uncited rules;
strict source linking reports the same five uncited kernel facts and
zero functions without source citations. Full path coverage, the full
required Ubuntu/vanilla kernel matrix, real Incus/LXD and the root
system-unit sandbox remain open; these runs do not mark them complete.

| Item | Decision | Specification |
|---|---|---|
| A1 | Staging under a temporary name happens only when strictly necessary: a configured `interface_hwaddr`, or the configured name held by a foreign device. Otherwise the session is created directly under its configured name, as 0.1.5 did. | S4 and S7 rewritten; H11 limitation scoped to staged sessions |
| A2–A6 | Fix all. | no change |
| B1–B11 | Fix all. B6: the installer's unit goes to `/usr/local/lib/systemd/system`, where 0.1.5 wrote it; `/etc` copies shadow it by precedence. B9: `-v`, `-c`, `-p`/`--pidfile` accepted as aliases. | P27 aliases, installer path and modes (B6, B7), `--restart` file checks (B5); P2 closed descriptors (B1); P14 unusable `NOTIFY_SOCKET` (B3); C7 all-digit last label (B11); `docs/packaging.md` path and `--restart --pid-file` |
| A4, A6 | Spec text the fixes rely on. | C3 non-regular files and the 16 MiB bound (A4); S10 creation-time notification is not an override (A6) |
| C1 | The safer behaviour, which the code has: a new entry colliding with another new entry keeps its values in force when the accepted configuration holds its name. | C12 first-pass sentence |
| C2 | Fix the code: tolerate `resolver_name` only when the configured text was a literal. | no change |
| C3 | More buffer memory is fine; the spec follows the code. | R10 and E20: three subscriptions, 8 MiB requested, 16 MiB effective |
| C4 | The spec follows the code: retries per tunnel. | T20 and E8 |
| C5 | Fix the code: the hard mistake is found first. | C10 precedence paragraph |
| C6 | Noted. | K31 nuance and citation |
| D1–D11 | Fix. D10 with a manual `Debug` implementation that prints no cookie bytes. | no change |
| D12 | Docs fixed. | `tests/kernel/README.md`: `-m 2048` with the reason |
| E1–E5 | Strengthen the tests as a whole, not item by item. | no change |

## F. Follow-up after the fix commit 6075fde

The fix commit was verified twice on 2026-10-30. A fresh run of every
gate and suite ([record](phase5-completion/fixes-verification/test-run-2.md),
logs beside it): formatting, Clippy, the feature builds and the docs
clean; 196 ordinary tests plus the rules, service and conformance
suites green three times; the privileged container suites on musl and
glibc (kernel 9/13/5, process 18, fixtures 3), procfs hidden, the real
user systemd store and the notify filter all pass; the eight live
reconnection scenarios and the zoned link-local replacement that A2 had
failed pass with the new binary, with results identical to the
pre-fix run except for the fixed case; every session without a
hardware address was created directly under its configured name (61
of 61) and one with an address was staged and published. An
independent review of the diff against every item
([review record](phase5-completion/review-fixes.md)) found all items
fixed with tests the pre-fix code would fail, except the following. F1
and F2 are to be fixed before Phase 6 starts; the rest within Phase 6.
Phase 6 can begin.

- [ ] **F1. D9 regressed (medium).** `src/kernel/linux/rtnl.rs:93-97`
  returns `None` for an address record of any family other than
  `AF_INET` or `AF_INET6`, and `dump_addrs` (`:228`) and `dump_links`
  (`:210`) now turn one undecodable record into `EPROTO` for the whole
  dump, where the previous code skipped it. The daemon dumps with
  `AF_UNSPEC`, which also walks the MCTP and Phonet address tables when
  those families have addresses. On such a host the resync never
  completes: `monitor_pending` stays set, the "lost notifications"
  episode never ends, `address_devices` stays empty and every
  `AddrNew` is ignored (`src/reconciler/events.rs:277-286`), so bound
  tunnels no longer reconnect when their device gets an address. Fix:
  skip records of other families and keep `EPROTO` for a truncated
  inet record only; add a dump-level test with a foreign-family record.
- [ ] **F2. A1 partly (low to medium).** Re-creation through the event
  path (`recreate_session` after an observed removal or a failed
  verification) always stages, because the configured name is still in
  `reserved` and only `release_departed` drops it, which runs inside
  `reconcile` only (`src/reconciler/mod.rs:232`). The S27 re-created
  device therefore gets a temporary-name-derived MAC under udev's
  persistent policy, the A1 symptom again. Fix: release the reservation
  (absence was just confirmed) before `create_wanted_sessions` in
  `recreate_session`; assert the re-created session's name is the
  configured one in `direct_creation_and_recreation_preserve_publication_rules`.
- [ ] F3. `remember_device` (`events.rs:518-526` via `ladder.rs:56`)
  performs a `link_by_index(master)` round trip on every converge of a
  tunnel whose bind device has a master, even when cached (D4, M16).
- [ ] F4. `close_from` failure now ends start-up (`fdstore.rs:184-201`,
  D7); a host that filters `close_range` and sets a hard descriptor limit
  in the millions previously started slowly and now does not. One
  sentence on the hosts page.
- [ ] F5. The E1 test forces synchronous deletion; the asynchronous K18
  case (the survivor's rename hits the dying device, `EEXIST`, retried)
  is untested.
- [ ] F6. B5's checks refuse a 0.1.5 PID file (mode `0666`), so
  `rs-l2tpd --restart` cannot hand over from a running 0.1.5; the
  installer says `systemctl restart` is needed once. Say so in
  `docs/packaging.md`.
- [ ] F7. `tests/service.rs:1012-1021` was given a hardware address so
  that staging still blocks the reload during convergence; the direct
  creation path has no equivalent service test.

## A. Must fix before 0.2.0

- [x] **A1. Staging every session under a temporary name changes the MAC
  of every 0.1.5 session interface at every start (G22, S4, H11).**
  0.1.5 created the `l2tpeth` device directly as `l2tp0`; the rewrite
  creates it as `rsl2tp-tXXXXXX` and renames it (`src/reconciler/sessions.rs:205-277`,
  `:431`). On a host with udev and the stock `99-default.link`
  (`MACAddressPolicy=persistent`), udev handles the `add` uevent under the
  temporary name, assigns `hash(machine-id, temporary name)` and marks the
  address set by userspace; on the later `move` uevent it skips the
  policy. The device therefore gets a different MAC at every daemon
  start, where 0.1.5 got the same `l2tp0`-derived MAC every time. With it
  change the EUI-64 link-local address and everything keyed on the MAC
  (static routes via a link-local next hop, neighbour entries, DHCP
  leases). Confirmed live on systemd 249, 252, 255 and 259 with `dummy`
  and real `l2tpeth` devices: with a one-second gap udev always won; with
  an immediate rename udev still processed `add` first in 8 of 9 runs
  ([networkd report](phase5-completion/review-networkd.md), `phase5-completion/networkd/out-*-native.txt`).
  A configured `interface_hwaddr` avoids it (the daemon sets the address
  first, udev then skips), but G22 says a 0.1.5 configuration must not
  need to change. Fix (decided, spec amended): create a session directly
  under its configured name when no `interface_hwaddr` is configured and
  the name is free, and stage only when an address is configured (S4's
  stated reason) or the name is occupied. The creation name is then the
  configured name, which S22's deletion-by-creation-name still handles.

- [x] **A2. A failed connect to a zoned link-local peer leaves a kernel
  binding the daemon does not know about; every later reconnect skips the
  disconnect and fails `EINVAL` for good (T21, T27, G17).**
  `src/reconciler/tunnels.rs:412-418` (`reconnect`) and `:383-393`
  (`disconnect_to`) disconnect only when the record says connected, bound
  or stale. The kernel sets `sk_bound_dev_if` from the scope before the
  route lookup and does not restore it when the connect fails
  (`net/ipv6/datagram.c:221-227`, failure path `:255-263`); a later connect
  with another scope is refused (`include/net/sock.h:3023-3035`).
  Reproduced live: unbound tunnel to `fe80::1%vB`, `vB` down
  (`ENETUNREACH`), `vB` deleted and re-created with a new index: `pending:
  EINVAL` every second, forever, at debug level only because the warning
  episode is already open (`phase5-completion/reconnect/ll2-replace`).
  Fix: disconnect unconditionally in `reconnect`, and before binding in
  `disconnect_to`; `__udp_disconnect` on a connection-id-bound L2TP/IP
  socket is harmless.

- [x] **A3. A tunnel re-creation drops the resolver answer in force (V6,
  V7, G19).** `src/reconciler/tunnels.rs:169` forgets the resolver watch
  for every unwanted tunnel, including one re-created for a
  `peer_tunnel_id` change. Reproduced on the fake kernel: an FQDN tunnel
  connected to its answer, reload with a new `peer_tunnel_id`, the new
  socket is registered but not connected until the resolver answers again,
  which with DNS down is never. The spec's historical known-gaps table
  lists exactly this as a defect the rewrite removes. Fix: keep the watch
  across a same-`tunnel_id` re-creation; drop it only when the entry
  leaves the configuration or its key changes. No test covers answer
  retention across a re-creation.

- [x] **A4. Configuration files are read with no regular-file check and no
  size bound (C3, P2, P13).** `src/bin/rs-l2tpd/files.rs:84` after
  `present()` at `:14`, which calls `metadata` only. A FIFO named `x.toml`
  in the drop-in directory blocks `open` forever: at start-up before
  `daemon::start`, so the parent never exits and the supplied unit's
  `TimeoutStartSec=infinity` never fires; on reload it hangs the reload
  thread and every later reload is lost. A multi-gigabyte file is read
  whole. Fix: refuse non-regular files in `present()` as a C3 problem that
  names the file, and cap the read.

- [x] **A5. A session whose device left the namespace blocks its own
  re-creation silently, for ever (S21, T25, G13).**
  `src/reconciler/sessions.rs:177-180` refuses to create a session whose
  identifier has a creation-name reservation; `src/reconciler/tunnels.rs:185-195`
  releases a reservation only when the kernel no longer has the session.
  After an observed removal with the kernel session still present (a move
  to another namespace), a re-creating change (cookie, `peer_session_id`)
  is never attempted: `incomplete` every second, no kernel operation, no
  report, "reload completed" never logged. Reproduced on the fake kernel.
  Fix: apply the gate only to deletions the daemon commanded (the K18
  window), not to forgotten sessions; S21 wants the attempt and `EEXIST`
  counted as a conflict.

- [x] **A6. Every published session is recorded as renamed by another
  manager (S10).** `src/reconciler/sessions.rs:572-583` compares the
  creation-time `RTM_NEWLINK`, which still carries the temporary name and
  is delivered after the daemon's own rename, with `current_name` and
  records an override. Seen for every session in every live run. A real
  rename by udev or networkd later becomes indistinguishable from this
  bogus one. Fix: ignore link messages older than the rename, or compare
  against the name the message was sent for.

## B. Should fix

- [x] **B1. Log output goes to whatever holds descriptor 2 (O1).**
  `src/bin/rs-l2tpd/logger.rs:12` writes to standard error unconditionally
  and nothing ensures descriptors 0 to 2 are open; `fdstore::inherit`
  closes from 3 up only. Started with standard error closed, the first
  socket takes descriptor 2 and every log line becomes a write on it: on
  a tunnel socket an L2TP frame to the peer carrying log text. Fix: open
  `/dev/null` on every closed descriptor in 0 to 2 at the top of `run()`.

- [x] **B2. A stat error on the handed-over PID file kills the re-exec'd
  image (P26).** `src/bin/rs-l2tpd/restart.rs:83` propagates every error
  of `PidFile::matches` except `NotFound` (`pidfile.rs:230-236`); the new
  image exits 1, the inherited sockets close and every tunnel is deleted.
  P26 says a non-matching identity drops the removal authority with a
  report. Fix: treat an error like a mismatch, with a warning.

- [x] **B3. An unusable `NOTIFY_SOCKET` aborts start-up (P14, P5).**
  `src/bin/rs-l2tpd/main.rs:90-94`: a path over 107 bytes or an `AF_UNIX`
  refusal exits 1 before the kernel interfaces are opened, a three-second
  crash loop under `Restart=on-failure`. Fix: report and continue without
  a store.

- [x] **B4. An inherited descriptor that is a socket but not a datagram
  socket is retried every second, for ever (P14, L13).**
  `src/reconciler/store.rs:221-231` lists the definitive rejections;
  `l2tp 0.5.0`'s `from_fd` returns `ESOCKTNOSUPPORT` for a non-`SOCK_DGRAM`
  socket, which is missing from the list, so the descriptor is never
  retired or withdrawn and `incomplete` never clears. Fix: add it.

- [x] **B5. `--restart` trusts the PID file's location and content.**
  `src/bin/rs-l2tpd/restart.rs:248-259` reads the file unbounded (a FIFO
  hangs), parses any PID above 1 and sends `SIGUSR2` as root, whose default
  action is termination: a stale file after a crash names a recycled PID;
  a `--pid-file` in a world-writable directory lets a local user pick the
  target. Fix: `O_NOFOLLOW`, a regular file owned by the caller with no
  group or other write bit, at most a few dozen bytes. The docs also show
  `rs-l2tpd --restart` without `--pid-file` (`docs/packaging.md:28`, `:113`)
  while the unit uses `/run/rs-l2tpd/rs-l2tpd.pid`.

- [x] **B6. The installer's unit path and the 0.1.5 upgrade.**
  `src/bin/rs-l2tpd/setup.rs:46-61` writes the unit to
  `/etc/systemd/system`, which systemd.unit(5) reserves for units the
  administrator *created*; units the administrator *installed* belong in
  `/usr/local/lib/systemd/system`, next to the binary in `/usr/local/sbin`,
  and that is where 0.1.5's `--setup` wrote its unit. Installing there
  replaces the legacy unit in place instead of shadowing it, lets any
  `/etc` copy or `systemctl edit --full` win by precedence, and makes the
  byte-exact edit detection against one legacy text unnecessary. Also:
  the old binary stays at `/usr/local/bin/rs-l2tpd` and the running 0.1.5
  daemon re-execs its own `argv[0]`, so `rs-l2tpd --restart` after the
  install runs the old binary; the installer must say that
  `systemctl restart` is needed once. Fix the path in the installer and in
  `docs/packaging.md:26`; the spec's P27 names no directory.

- [x] **B7. Installer directories follow the caller's umask.**
  `src/bin/rs-l2tpd/setup.rs:15`, `:64`: `create_dir_all` under umask 000
  or 002 leaves `/etc/rs-l2tpd.toml.d` group- or world-writable, and the
  root daemon reads it at every reload. Files are chmod'ed, directories
  are not. Fix: `DirBuilder` with mode `0755`.

- [x] **B8. The monitor-resync warning repeats every second while the
  link dump fails (G13).** `src/reconciler/events.rs:355` warns
  unconditionally and `timers.rs:84-86` re-enters each tick. Reproduced:
  one loss plus five failing dumps, six warnings. Route it through
  `Report`; same for `disconnect failed` at `tunnels.rs:388` and `:415`.

- [x] **B9. The command line dropped 0.1.5's spellings (G22, P27).**
  0.1.5 accepted `-v`, `-c`, `-p`/`--pidfile PATH`; `src/bin/rs-l2tpd/args.rs`
  exits 2 on each. 0.1.5's installed unit passed no options, so installer
  upgrades survive, but a hand-written unit or script with `-p` breaks.
  Fix: accept the three old spellings as aliases and say so in P27.

- [x] **B10. `getrandom` failure panics the reconciler (G1).**
  `src/kernel/linux/mod.rs:81-85` uses `expect`; `getrandom(2)` fails with
  `ENOSYS` or `EPERM` under a filtering seccomp policy in a container. Fix:
  return an error from the trait method or fall back.

- [x] **B11. All-numeric last labels are host names (C7, C10).**
  `src/config/text.rs:56-67` classifies `300.1.1.1`, `1.2.3` and `01.2.3.4`
  as host names, so a mistyped literal becomes a DNS lookup and the warning
  points at `ip_version`. Reject a name whose last label is all digits and
  say so in C7. Not a regression: 0.1.5's `IpHost` fell through to FQDN too.

## C. Spec and code disagree; decide, then fix one side

- [x] **C1. C12 first pass versus `partial.rs:293-313`.** A new valid entry
  that collides with an earlier new entry and exists in the accepted
  configuration is retained with its old values (`KeptPrevious`); C12 says
  it is left out. The code's behaviour is the safer one. The test at
  `src/config/tests.rs:900` does not cover the branch.
- [x] **C2. A host-name tunnel without `ip_version` loses its
  `resolver_name`** (`partial.rs:399-407`, `mod.rs:369-405`): the
  peerless correction turns the key into a second tolerated mistake and
  `--check` no longer shows it. Tolerate the key only when the configured
  text was a literal.
- [x] **C3. R10 and E20 say two monitors with 8 MiB buffers;** the code has
  three subscriptions (`monitor.rs:146`, `lifetime.rs:151`, `l2tp.rs:396`)
  and the kernel doubles the requested size (K36), so 16 MiB each.
- [x] **C4. T20 and E8 say retries are per bound device;** the code
  retries per tunnel (`tunnels.rs:479-483`, `timers.rs:62-71`). A superset;
  amend the spec or the code.
- [x] **C5. C10 precedence:** `fe80::1` with `ip_version = "V4"` and no
  bind device is tolerated (family mismatch, checked first) instead of
  hard (link-local without a zone). Add a precedence sentence to C10.
- [x] **C6. K31 nuance:** `dev_set_mac_address` accepts an unchanged
  address while the device is up (`net/core/dev.c:9020-9044`); the code is
  consistent, K31 could say so.

## D. Lower-severity robustness items

- [x] D1. `src/reconciler/sessions.rs:186-197`: the session "create" episode
  is never ended (G13).
- [x] D2. `src/reconciler/events.rs:214-219`: an error from the kernel query
  on a link removal sets no retry (E3); the E27 path at `:338-341` does it
  right.
- [x] D3. Same-identifier re-creation leaves a one-second `session()` poll
  running for the entry's life (`events.rs:119-126`, `timers.rs:72-80`).
- [x] D4. `events.rs:151-159`: the VRF and master caches grow with every
  link on the host (G23); `timers.rs:99-110` is linear in the entries per
  event.
- [x] D5. `src/reconciler/tunnels.rs:57`, `:77`: adoption aborts the whole
  tunnel on one undeletable unmatched session (M4).
- [x] D6. `events.rs:359`: dead `dump_addrs()` call in the resync.
- [x] D7. `src/bin/rs-l2tpd/fdstore.rs:173-186`: when `close_range` is
  refused the fallback loops to the hard descriptor limit.
- [x] D8. `src/bin/rs-l2tpd/main.rs:24`, `:78`: a failed `getcwd` exits 1
  although only a relative `argv[0]` needs it.
- [x] D9. `src/kernel/linux/rtnl.rs:196`, `:214`: undecodable links and
  addresses are dropped from dumps silently.
- [x] D10. `src/kernel/linux/request.rs:146`, `:175`: a `Debug` bound on
  payloads that carry cookie bytes; nothing formats them today (O5).
- [x] D11. A rename of a device with IPv4 addresses reconnects twice: the
  kernel sends one `RTM_NEWADDR` per address for the label change
  (`net/ipv4/devinet.c:1516-1540`) and `events.rs:252-306` takes it as E6.
- [x] D12. `tests/kernel/README.md` said `-m 512` for QEMU; the current
  initramfs needs 2048 (the 512 run panics on unpacking). Docs fixed.

## E. Missing or weak tests

- [x] E1. C14, M6, S11: a removed session's name taken by a survivor has no
  test at all.
- [x] E2. V7 across a re-creation (A3); S21 re-creation after a namespace
  move (A5); G13 log counting (B8); S27 publication and hardware address
  after re-creation; T25's "eventual creation" message; session-level and
  adoption cases for G6.
- [x] E3. C7 host names: no non-ASCII, all-numeric or 253-plus-dot case;
  C7 literals: no `::ffff:192.0.2.1` with `ip_version = "V6"`; C2: no
  explicit empty-table "cannot remove a key" case; C12: see C1.
- [x] E4. V10 and V14 adapter tests are `#[ignore]` and did not run in the
  default suite; they need capabilities.
- [ ] E5. The strict traceability gates are phase 6 work and are reported
  here for the record: 106 of 330 active rules have no test citation (all
  of H and most of R, G and A, plus E26, O2, O4, O9, K1, K3, K6, K8, K13,
  K21, K33, K36, K38); K13, K14, K33, K38 and K40 are never cited by a
  `kernel::linux` function (`phase5-completion/gates/strict.log`,
  `strict-srclink.log`).

## Documented limitations (no fix planned)

- **systemd-networkd before v253 without udev.** In a container whose
  `/sys` is read-only (Docker; not a stock Incus system container, which
  mounts `/sys` read-write and runs udev, verified on Incus 6.0 on
  2026-10-30) udev does not run, and networkd matches a new link at its
  first netlink message. networkd v249 (Ubuntu 22.04) and
  v252 (Debian 12) do not re-match `.network` files on a rename, so a
  `[Match] Name=l2tp0` file never applies to a device the daemon created
  under a temporary name; v253 and later re-match after the rename.
  Confirmed live on 249, 252, 255 and 259 in both environments
  (`phase5-completion/networkd/out-*-container.txt`). With udev running,
  every version re-matches via the `move` uevent. Fixing A1 as proposed
  removes the limitation for sessions without a configured hardware
  address; it stays for staged ones. All current deployments run Ubuntu
  24.04 or later, where it does not apply. Written into `docs/spec/hosts.md`
  (H11) and `docs/interface.md`.
- **`.link` files need udev.** In a container without udev no `.link` file
  applies to any device, in 0.1.5 and now alike.

## What 0.1.5 did on the same events

Live, two daemons across a veth pair in two namespaces on the host's
6.8.0-147 kernel, the 0.1.5 binary built from the tag
(`phase5-completion/reconnect/old-*`, new build in `new-*`; scenario
script `reconnect/scenario.sh`). The report with log excerpts is
[the reconnection review](phase5-completion/review-reconnect.md).

| Event | 0.1.5 | This tree |
|---|---|---|
| Bind device absent, appears later under another name, renamed | Connected unbound through any route; readiness waited for a route; bound later without a reconnect | Disconnected until the name exists; bound by index and connected 0.2 s after the rename; ready before any route |
| Bind device renamed away or deleted | Kept sending through the renamed device; stayed on the dead index | Disconnected at once; reconnected on name-back and on re-creation |
| Address added or removed | Reacted to IPv6 addresses only, reconnecting every tunnel | One reconnect per same-family change on the bound device; unbound tunnels only when their source goes |
| Peer without a route, route added later | Retry loop, no session device, no readiness | Created disconnected, ready at once, connected within a second of the route |
| FQDN answer changes or disappears | Connected to `100::` first; never came up without an IPv6 default route | New answer applied at the next refresh; a disappeared answer keeps the previous one |
| VRF without members, member joins, `nomaster`, VRF re-created | Bound to the empty VRF without a reconnect (traffic left outside the VRF); never rebound after re-creation | Source `::` treated as a failure; connected on join; disconnected on `nomaster`; re-created VRF rebound |
| Reload changing bind, peer, family | Tunnel deleted and re-created, interface index changed; family change failed `EAFNOSUPPORT` for good | All in place, interface index unchanged throughout |
| `bindv6only=1`, fix off | Not handled | `AF_INET` socket for IPv4 peers, same reconnect semantics |

Nothing 0.1.5 reacted to is lost: it subscribed to link messages and
IPv6 address messages only; this tree subscribes to link, both address
families and the `l2tp` group.

Other visible changes from 0.1.5, all intended: umask 077 and PID file
mode 0644 (were 0 and 0666), dot-file drop-ins ignored, non-ASCII host
names and `""`/`"."` refused, log lines `LEVEL target: message` without a
timestamp, `--check` output gains `host` and `resolvers` tables and omits
defaults, the installer's binary path moved to `/usr/local/sbin`.

## Gates and suites, run fresh

[Test run record](phase5-completion/test-run.md), logs in
`phase5-completion/gates/`. Formatting, Clippy with all features and
`-D warnings`, the no-default and `serde` builds and the warning-denied
docs are clean. Native `cargo test --all-features`: 196 passed, 49
ignored. The fake-kernel suites three times: no flake. Privileged
container suites on the host kernel, musl and glibc: kernel 9/12/5
cases, process 17, fixtures 3, all passed; procfs hidden, the real user
systemd store, the notify address-family check and QEMU 6.12.114 passed.
Only the strict rule-map and source-link gates fail (E5).

## Security summary

No finding lets an unprivileged party control the daemon. The PID file
code works relative to a directory descriptor with `O_EXCL|O_NOFOLLOW`
and re-verifies the opened inode; the descriptor hand-over checks
`LISTEN_PID`, bounds `LISTEN_FDS`, validates names and closes everything
unannounced before anything is opened; the re-exec probes the target in a
private file table and preserves `SIGPIPE` ignore; netlink parsing is
bounds-checked and only port 0 is accepted as a sender; the BPF program
was verified instruction by instruction; cookies never reach a log line;
the library has no `unsafe`. The items with a security flavour are B1
(log text leaving through a socket when standard error is closed), B5
(`--restart` killing a recycled PID or a chosen one through a
world-writable PID directory), B7 (installer directory modes) and A4 (a
planted FIFO stalling start-up).

## Method and limits

Five independent readers each took a slice with the rule list for it
(binary, kernel boundary and configuration, reconciler and services,
reconnection paths, networkd and udev interaction), read the spec pages
first, then the code and the tests, and cited `file:line` for every
claim; a sixth ran every suite. The reconciler findings A3, A5 and B8
were reproduced on the fake kernel; A2 and all reconnection verdicts in
privileged containers against the live kernel with both binaries; A1 and
the networkd limitation in containers running systemd 249, 252, 255 and
259 with udevd started by hand. Not done: a real Incus or LXD container
(Docker with a read-only `/sys` and no udev stood in), the monitor
overflow path, real DNS, RA and DHCPv6 resolvers, the kernel matrix
beyond 6.8 and 6.12, the restart hand-over under load, and the root
system-unit mount sandbox, which stays the open item of the previous
review.
