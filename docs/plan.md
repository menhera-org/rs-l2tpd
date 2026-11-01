# The rewrite plan

[Documentation index](README.md)

Roadmap steps 5 and 6 of `CONTRIBUTING.md`, made concrete. Step 5 replaces
the whole codebase with the smallest one that satisfies every rule of the
[specification](spec/README.md); step 6 proves it: 100 % path coverage,
one test per claim, deterministic tests, kernel-facing code source-linked
to the kernel, and every kernel-relevant unit exercised against a live
kernel. The two steps interleave, because a module is finished only when
its tests exist; the phases below are ordered by what each one needs
from the previous.

The specification is authoritative; where a page here and the
specification differ, the specification is right and this page is wrong.

## Rules of the rewrite

- **Nothing is kept for its own sake.** The pre-rewrite baseline `741117b` (17,000 lines,
  of which `runtime.rs` 6,600 and `state.rs` 4,200) is read for the
  kernel facts it learned, not for its structure; the target is under
  7,000 lines of library and 1,500 of binary, excluding tests.
- **One boundary makes everything testable.** The reconciler talks to the
  host only through the `Kernel` trait of the [architecture](architecture.md#the-kernel-boundary).
  A fake implementation encodes the kernel facts K5–K42; the real one
  wraps the sockets. Every behavioural rule is tested against the fake,
  deterministically; every kernel fact and every real implementation is
  tested against the live kernel.
- **Every rule has a number, every test names one.** A test that guards
  rule T21 carries `/// spec: T21` immediately before its test declaration.
  The rule map lists identifiable test locations; it is traceability,
  not proof of execution or coverage. Required suite results and explicit
  per-clause cases establish that evidence ([testing](testing.md#gates)).
- **Stop at the upstream boundary.** When a step needs something of the
  `l2tp` or `iphost` crate that they do not provide, the step stops, the
  need is written down in [dependencies](dependencies.md#upstream-needs),
  and the fix goes upstream first (`CONTRIBUTING.md`, step 5).
- **Minimal supply chain.** A dependency is kept only when it replaces
  more code than it adds risk; the target list is in
  [dependencies](dependencies.md).
- **Ponytail.** Each change is the smallest complete one; abstractions
  exist only where two implementations exist (the `Kernel` trait, the two
  services).

## Phases

| Phase | Deliverable | Depends on |
|---|---|---|
| 0 | Upstream check, version plan, empty crate skeleton with features and CI gates | — |
| 1 | Configuration: types, validation, lenient conversions, serde, in-memory document merging | 0 |
| 2 | Kernel boundary: the `Kernel` trait, the fake kernel, the real kernel with its live tests | 0 |
| 3 | Reconciler: records, planner, tunnel and session operations, the degradation ladder, timers, event handlers, resolvers | 1, 2 |
| 4 | Runtime, services, control handle, library API and documentation | 3 |
| 5 | Binary: command line, files, logging, daemonisation, PID file, signals, descriptor store, restart | 4 |
| 6 | Proof: container suite, QEMU kernel matrix, coverage gate, source-link check, rule map | 2–5 |
| 7 | Release: documentation, changelog, 0.2.0 | 6 |

### Phase 0 — ground

1. Confirm the upstream crates provide what the specification needs
   (table in [dependencies](dependencies.md#upstream-needs)); file issues
   or patches for what they do not. Known at the start: `l2tp` 0.4.0
   provides sockets from and into descriptors, `disconnect`, session
   lookup and deletion by interface name, cookies in `SessionInfo` and
   the `l2tp` multicast events; 0.4.1 (published 2026-10-28, pinned in
   the manifest) needs no `/proc`. `iphost` 0.4.0 (read in `../iphost`) provides the four
   resolver kinds, the DUID choices, the raw and netlink RA sources and
   the shared DHCPv6 socket; answer selection, retention, the refresh
   thread and zone parsing are the daemon's ([dependencies](dependencies.md#upstream-needs)).
   The one item that was missing upstream, a constructor for a bound,
   unconnected tunnel socket (the disconnected state of T1), is
   in `l2tp` 0.4.2, published and pinned on 2026-10-28; 0.4.3 (same day,
   pinned) fixed the sender validation of E22 and added the bounded event
   subscription `events_bounded` as a bounded alternative; the production
   path now uses the daemon's raw adapter. 0.5.0 (2026-10-29,
   pinned, with breaking changes the daemon does not meet, since it uses
   no handle) added the socket identifiers of P14, the lenient reply
   parser for foreign cookies of K35 and the runtime-free `EventSocket`.
   What remains daemon-side is the request deadline: the generic-netlink
   request adapter of phase 2 ([dependencies](dependencies.md#upstream-needs)).
2. The version stays **0.2.0**: it was never released, so the API
   changes of L5, L6 and L13 break nothing published; the configuration
   format of 0.1.5, the last release, keeps working (G22).
3. Create the crate skeleton: `src/lib.rs` with the module tree of the
   [architecture](architecture.md#module-map), the `serde` and `bin`
   features, `#![deny(unsafe_code)]` and `#![warn(missing_docs)]` in the
   library, the `tests/` layout of [testing](testing.md#layout), and CI
   jobs that fail on warnings, on `cargo doc` warnings, on a build
   without default features, and on a rule without a test.
4. Delete `src/runtime.rs`, `src/state.rs`, `src/state/`, `src/netlink.rs`,
   `src/service.rs`, `src/blocking.rs`, `src/config.rs`, `src/bin/main.rs`
   and `tests/docker/*.sh`; keep `tests/docker/README.md` as the seed of
   the new one, and `build.rs` with a third path (`PID_FILE_PATH`, P10).

Exit: the empty crate builds with and without features, CI is green, the
rule map tool exists and reports every rule as untested.

**Status: done on 2026-10-28.** The old tree and the shell scenarios are
deleted; the skeleton of the [architecture](architecture.md#module-map)
is in place with empty modules; `Cargo.toml` carries the
[dependency list](dependencies.md) and the `serde`, `bin` and
`fake-kernel` features; `build.rs` has the three paths; the rule-map and
source-link tools run as `cargo test --test rulemap --test srclink`,
lenient until phase 6; CI runs every gate. The binary builds and exits 2
with a message until phase 5. Next: phase 1.

### Phase 1 — configuration

Implements the static [configuration](spec/configuration.md) rules C2,
C5–C17 and library types L3–L4. File handling (C1, C3, C4) is designed
here and implemented in Phase 5.

1. `config::Config`, `TunnelConfig`, `SessionConfig`, `ResolverConfig`,
   `HostConfig`: private fields, builders, getters; every constructor and
   insertion validates (C7, C8, C16, C17, C9); `Config` cannot hold an
   invalid entry (L4). Kernel-identity keys (`TunnelIdentity`,
   `SessionIdentity`, C14) derived from the entries.
2. `config::PartialConfig`: the merged-but-unvalidated form with every
   field optional and textual (C5); `merge` (C2); the strict conversion
   (`TryFrom`, C15); `into_config_lenient` (C10) and
   `into_config_with_previous` (C12, two passes); `Problem` with kind,
   entry, field, effect and error (C15).
3. The `serde` feature: `Deserialize` for `PartialConfig` with
   `deny_unknown_fields` off and unknown keys collected (C6), `Serialize`
   for the check-mode rendering in the fixed order of O8.
4. The binary's file layer (in phase 5, but designed here): reading the
   main file and the drop-ins in byte order, `.toml` compared without
   case, dot-files ignored, symlink rules (C1, C3, C4), merging documents
   before validation.

Tests: one unit test per row of C7, C8, C16, C17, C10 and C12, the
merging examples of C2 and C12, the name rules of C5 and K32, the host
name and literal rules of C7 including the IPv4-mapped and zone cases,
unknown keys at every depth. No kernel is involved.

Exit: C2, C5–C17 and L3–L4 have passing static configuration tests,
including each field/table case. C1, C3 and C4 file discovery/read errors
are explicitly Phase 5 exit requirements; runtime device checks from
C16/T27 belong to Phases 2–3. `cargo doc` is clean.

**Status: done on 2026-10-28.** Items 1–3 are in `src/config/`, with
35 unit tests citing every C rule except C1, C3 and C4, the file layer of
phase 5. On the library side, item 4 is `PartialConfig::set_source`
(names the file in its unknown-key problems) and `merge`. The phase
distinguishes static validation from runtime device conditions
(C16, T27) and includes the C16 ignored-field tolerance in C10; runtime
enforcement is required before Phases 2–3 close. L3's re-export check
is phase 4's.

### Phase 2 — the kernel boundary

Implements the kernel interfaces of A5 and the facts of
[kernel](spec/kernel.md) as code that cites them.

1. The `Kernel` trait ([architecture](architecture.md#the-kernel-boundary)):
   tunnel sockets (create with family, bind with connection id, bind to
   index, connect, disconnect, local address, `IPV6_V6ONLY` read,
   descriptor in and out), L2TP generic netlink (create session with
   name, delete by identifiers or by name, get session, list sessions of
   a tunnel, get tunnel), rtnetlink requests (link by name, rename by
   index, hardware address by index, link dump, address dump, Ethernet
   address of a device), and the three subscriptions as streams (event
   monitor, link lifetime with ordered lookups, `l2tp` group).
2. `kernel::fake`: an in-memory kernel that implements the trait and the
   facts the reconciler relies on, each fact a method or a rule in the
   fake with its K number: K5 (unconnected sockets drop frames: the fake
   counts drops), K15, K16 (name copied once), K17 (close deletes
   sessions asynchronously, with a configurable delay), K18, K19
   (identifier refusals), K20, K22 (bind semantics and the `CAP_NET_RAW`
   rule), K23–K26 (connect outcomes by a routing table the test sets),
   K27, K31 (`EBUSY` while up, random address), K32 (name rules), K34,
   K37, K41. The fake also delivers notifications in kernel order and
   can be told to overflow a subscription (E20, E21) or to drop
   notifications.
3. `kernel::linux`: the real implementation over `l2tp::TunnelSocket`
   (`ip_unconnected`, 0.4.2), a bounded generic-netlink request/event
   adapter meeting the upstream-needs table (the trait is synchronous
   and runs on the reconciler's own thread,
   [architecture](architecture.md#the-kernel-boundary)), and `netlink-sys` sockets with
   `netlink-packet-route` for the rtnetlink requests and the two
   subscriptions; the event monitor attaches the classic BPF program of
   A5 through `socket2`; `SO_RCVBUFFORCE` then `SO_RCVBUF` (R10); the
   lifetime socket answers ordered lookups (A7); `ENOBUFS` is surfaced as
   a loss (E21); only port 0 is accepted (E22). Every function cites the
   kernel source lines of the fact it relies on, in the form the
   source-link check reads (`// kernel: net/l2tp/l2tp_ip.c:333-334 (K22)`).
4. Live tests (`tests/kernel/`) cover each applicable K fact with the
   production operations plus test-only fixture controls; operation
   cases share their body between real and fake implementations (the conformance suite of [testing](testing.md#the-conformance-suite)).

Exit: each K fact has an explicit evidence row: shared operation test,
live-only host test or source/requirement assertion. Applicable operation
cases pass on the fake and running kernel, including index reuse within
a generation, ambiguous creation names, foreign-namespace events,
event loss scans, sender validation, and missing-reply deadlines with
uncertain mutations. A source assertion does not count as a passing live
test. The fake is the only kernel the Phase 3 behavioral tests use.

**Status: done on 2026-10-29.** The [kernel evidence map](kernel-evidence.md)
classifies every K fact, including delegated resolver facts and source-only
requirements. Fifteen shared operation cases pass on the fake and real
implementations. The production adapter's live tests force lifetime queue
overflow, a missing mutation acknowledgement, a foreign sender and index/name
reuse in the same generation; they also read every foreign cookie length.
The suites pass on 6.8.0-147 (container), 6.12.114, 6.18.59 and 7.3 (TCG QEMU).
The QEMU runs found and fixed the newer kernel's namespace-wide session-ID
lookup: replies are checked against the requested tunnel, and deletion verifies
the pair within the same absolute deadline. No function in `kernel::linux`
lacks a source citation, including `pub(super)` functions. The complete release
matrix and strict global coverage/source gates remain Phase 6 requirements;
these selected live runs do not claim them. Commands, results and limits are
in the verification record (repository file `audit/PHASE23_VERIFICATION_2026-10-29.md`).

### Phase 3 — the reconciler

**Status: done on 2026-10-29 for reconciler policy.** The fake-kernel suite
includes the corrected S23 safe recovery, the five-second coalesced L12
handshake, exact-name L13 retirement and separate process-wide V15 budgets.
Blocked obsolete calls retain permits, current jobs/results coalesce, namespace
ownership is preserved, and unused discovery resources are released. The
released `iphost` 0.4.1 adapter is exercised with controlled RA, DHCPv6 and DNS
peers; its own parser/transport regressions run separately. A real systemd
manager holds a live tunnel reference until acknowledged withdrawal. Seeded
reload sequences assert convergence, identity preservation, peer selection and
the fixed point; ten fake-suite runs pass. See the
case/evidence record (repository file `audit/PHASE23_VERIFICATION_2026-10-29.md`).
The service callback/wakeup portions of E19/E26 and L12/L13, process re-exec,
shutdown orchestration and whole-daemon resource/timing promises still belong
to Phases 4–6; the reconciler tests do not claim those implementations.

Implements [model](spec/model.md), [tunnels](spec/tunnels.md),
[sessions](spec/sessions.md), [resolvers](spec/resolvers.md) and
[events](spec/events.md) over the `Kernel` trait.

1. Records (A11): `TunnelRecord`, `SessionRecord` with the identity
   states of S19–S23 and the enforced fields of M19, `ResolverRecord`,
   and the global counters and deadlines.
2. The planner (M1, M6): from the accepted configuration and the records,
   derive the right state of every entry (T1, S1, V1–V2) and the list of
   operations, ordered by the three rules of M6: deletions, renames to
   temporary names, creations, final renames; matched by kernel identity
   (C14).
3. Tunnel operations (T3–T29): family selection and the `bindv6only`
   read-back (T4, T26, E25), creation disconnected, the reconnect as the
   one three-step operation (T21, T28), bind by index (T10–T13),
   link-local zones (T27), the connect outcome table (T16), identifier
   conflicts with the counters (T25), re-creation with the deletion wait
   (T8, T24).
4. Session operations (S3–S29): staging under random names (S4, X2),
   publication and its retries (S6, S7, the eight draws), the rename
   batch with temporary names only for swaps (S11), deferred hardware
   addresses (S12), identity proofs through the lifetime subscription
   (S8, S9), loss handling (S19–S24), removal (S25–S26), external
   deletion through the `l2tp` group and the kernel query (S27, S29),
   adopted tunnels (S28).
5. Resolvers (V1–V15): adapters over `iphost` for the four kinds,
   selection and retention (V5–V7), binding (V9), the DUID read with its
   retry (V12), answers polled once a second (V4). Use separate process-wide system
   and configured lookup budgets (V15), retain permits through obsolete
   calls, coalesce jobs/results, and release unused discovery state.
   V10 uses incremental RDNSS updates; V14 enables bounded per-family
   fallback through the upstream API, not daemon-owned DNS protocol code.
6. The degradation ladder (M7–M8) as the single place that decides which
   substitute an entry gets, so that promotion is one function.
7. Event handlers (E1–E27) and timers (M14–M15): one tick, per-device
   retries, the left-out retry, the resolver refresh.
8. Reporting (O2–O6): episodes keyed by entry and condition, once at
   start and end, the S12 exception, errno names, cookies never
   formatted (O5, with a `Debug` that prints the length).

Tests: against the fake kernel, one test per rule of M, T, S, V and E,
and one per row of the identity matrix M17, the connect outcome table
T16, the ladder M7, the timing table M14 and the convergence bounds of
G15–G23, with the fake's clock advanced deterministically. Property
tests for the planner: any sequence of reloads converges, no operation
is issued on a converged entry (M2, G18), and a session's index never
changes except by a matrix row (G3).

Exit: M, T, S, V and E policy cases pass deterministically, as do G3,
G5–G7 and G18 planner properties. Include cross-tunnel name swaps and
session-ID reuse delayed by deletion, resolver config generations and
non-VRF validation, and dual zone/bind dependencies. G14 library behavior
and actual channel/wakeup concurrency are covered by Phase 4; Phase 5
adds actual-process acceptance. Remaining G15–G23 timing and resource
promises require Phase 6 end-to-end tests. A planner test alone does not
establish service or process behavior.
The [contract correction cases](testing.md#contract-correction-acceptance-cases)
are mandatory: staged replacement after loss, tunable completion before
registration, obsolete lookup accounting, and both upstream resolver
corrections. A documentation rewrite does not close these gates.

### Phase 4 — runtime and services

Implements [library](spec/library.md) L5–L13 and the concurrency of
A6–A7, A13–A14.

1. `Runtime`: owns the reconciler, the bounded channel, the subscription
   tasks and the timers; `new` opens the kernel (failing at once, L9);
   `reconcile`, `handle_event`, `shutdown`; the monitor drops events and
   marks a resync when the channel is full (A6); the lifetime task
   answers proofs over its own request-reply path (A7).
2. `ControlEvent`, non-exhaustive, with the variants the specification
   names: kernel events, resolver answers, ticks, reload, shutdown,
   `WriteTunable` (L12), `StoreSocket`, `ForgetSocket` (L13), restart
   (L6).
3. `Service` (Tokio) and `blocking::Service`; `Control` with `reload`,
   `reload_wait`, `shutdown`, `restart`, `config`; the reload callback on
   a thread that may block (L7); the restart callback (L6); adopted
   descriptors into the constructors (L5).
4. Library documentation: the crate-level example, one example per
   service, `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps`.

Tests: the service tests of L5–L13 against the fake kernel (converge
with a conflict, run then reload, a full queue, a callback panic, drop
without shutdown, adopted descriptors verified and refused); doc tests;
a `#[non_exhaustive]` and re-export check (L3).

Exit: every L rule tested; the library builds with no default features,
with `serde`, and under `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps`.

**Status: done on 2026-10-29 within this phase's scope.** The runtime,
Tokio service, blocking service and control handle are implemented. The
1,024-entry input queue has persistent loss and shutdown paths; reload
callbacks run off-thread, and shutdown does not wait for them. Named
adoption, tunable/store handshakes and restart descriptors are exposed
without process I/O in the library. Shutdown verifies kernel absence and
keeps withdrawal and kernel deletion windows separate. Public boundary
records now have constructors/getters and private fields; enums are
non-exhaustive and dependency types are re-exported.

The verification record (repository file `audit/PHASE4_VERIFICATION_2026-10-29.md`)
maps the L rules to executed cases: 12 runtime tests, 14 service tests,
six doc tests, ten seeded fake-suite repetitions, the warnings/feature
build gates, and 26 live Linux tests including the two services and
unordered runtime drop. That record predates the binary implementation
in Phase 5 below. Coverage, the full required kernel matrix and strict
global gates remain Phase 6.

The Phase 4 audit follow-up (repository file `audit/PHASE4_REMEDIATION_2026-10-29.md`)
corrects F1–F7 and verifies the amended L7/L8 blocking contracts: reload
completions return as events, queued requests survive the converge/run gap,
failed store delivery releases capacity, blocking completions work inside
`spawn_blocking`, and Tokio drop does not join the owner. Kernel/resolver
callbacks, including subscription initialization and clock reads, stay
outside the service's asynchronous wait. The follow-up records 64 ordinary
library tests, 22 service tests, ten seeded repetitions and live host results.

### Phase 5 — the binary

Implements [process](spec/process.md) P1–P27 and
[observability](spec/observability.md) O1, O7, O8.

1. Command line (P27) by hand, no `clap`: the documented options, exclusive
   modes, exit 2 on misuse.
2. Files (C1–C4) and `--check` (P3, O8) with its fixed rendering.
3. Logging (O1): a `log::Log` to standard error, `LEVEL target: message`.
4. Daemonisation (P2, P4): double fork, `setsid`, `/dev/null` on standard
   input, umask, the readiness pipe, `--foreground`.
5. PID file (P10–P11): fresh inode, ownership and permission rules,
   remembered inode, conditional removal.
6. Signals (P12): a thread on `sigwait` for `SIGHUP`, `SIGTERM`, `SIGINT`,
   `SIGUSR2`; `SIGPIPE` ignored; merged reloads; the persistent shutdown
   flag.
7. Host tunable (P25): the `/proc/sys/net/ipv6/bindv6only` write on the
   runtime's event.
8. Descriptor store (P14): `NOTIFY_SOCKET` datagrams with `SCM_RIGHTS`
   (`FDSTORE=1`, `FDNAME=t<id>`, `FDSTOREREMOVE=1`), `LISTEN_FDS` with the
   original parent's PID through the double fork, unannounced
   descriptors closed. Retain exact announced names through adoption,
   retry uncertain verification, and retire definite rejections through
   L13's bounded withdrawal/close/absence path. Verify manager processing
   where possible, serialize removal before replacement storage, and
   report failed cleanup without hanging shutdown.
9. Restart (P26, E26): the `--adopt-version` probe, close-on-exec cleared
   on the handed sockets only, `execve` of the path the daemon was started
   with. Requests stay blocked across exec until the new instance prepares
   its signal collector; a pre-exec hook retains `SIGPIPE` ignore even if
   exec fails.
10. Capability report (R49): `capget(2)` for the effective set, no
    `/proc`; report each missing one once.
11. The systemd unit (P21), rendered from `contrib/rs-l2tpd.service.in`
    per installation path (packaging), with a
    test that parses it for every required key and a live notification
    test under its actual address-family restrictions.
12. `--setup-systemd` behind the `setup-systemd` feature
    ([packaging](packaging.md#--setup-systemd-feature-setup-systemd)):
    atomic copy of the binary, the unit unless edited, the configuration
    paths unless present, `daemon-reload`, `enable --now` once, never a
    restart; `--prefix` for the tests.

Tests: unit tests for the command line, the merging, the rendering, the
PID-file rules (on a temporary directory), the signal merging (with the
service on the fake kernel); container tests for daemonisation,
readiness, the PID file, the store protocol against a tiny notify-socket
listener, the restart exec, and the capability report.

Exit: every P and O rule and the deferred C1, C3, C4 file cases tested; the binary runs on glibc and musl
targets (P24).

**Status: implemented on 2026-10-29, conformance follow-up verified on
2026-10-30 within this phase's scope.** The binary now
loads and checks files, logs, double-forks with readiness, publishes and
removes its PID file by inode, and forwards coalesced signals to the
existing service. The native descriptor-store transport uses processing
barriers; adoption preserves exact names through both forks. Re-exec
preserves the executable path, options, PID-file authority and interfaces,
including with zero tunnels. Descriptor remapping uses a private Linux
file table so a failed exec cannot disturb live threads.

The unit template and optional installer are implemented, including
preserved edits and first-enable-only behavior. The unit selects a
dedicated writable PID directory; standalone PID defaults are unchanged.
No dependency was added.

The latest conformance record is repository file
`audit/PHASE5_CONFORMANCE_FIXES_2026-10-30.md`. It records 27 ordinary
binary cases, seven ordinary process cases, 17 privileged process cases
and three file/ownership fixtures on both musl and glibc. Fresh QEMU runs
on 6.12.114, 6.18.59 and 7.3 execute all 24 process cases; the real user
systemd manager and procfs-hidden installer/daemon checks also pass.
The follow-up fixes the confirmed audit findings, tests full-queue signal
forwarding and preserves SIGUSR1's default action. Rust's exec preserves
the signal mask; the reproduced failed-exec SIGPIPE reset is fixed.
The initial record, `audit/PHASE5_VERIFICATION_2026-10-29.md`, retains its
dated test counts and repetition evidence. Reproduction commands are in
repository file `tests/process/README.md`.

A whole-tree check on 2026-10-30 (repository file
`audit/PHASE5_COMPLETION_CONFORMANCE_2026-10-30.md`) ran every suite,
compared the reconnection paths live against the 0.1.5 binary, and found
them conforming and better than 0.1.5 throughout. Every item was decided
the same day (the report's decisions section) and the specification was
amended where a decision changed a rule: sessions are created directly
under their configured name and staged only when strictly necessary (S4,
S7, H11), C10 precedence, the safer C12 collision outcome, three
subscriptions with 16 MiB effective buffers (R10, E20), retries per
tunnel (T20, E8), the K31 nuance, the 0.1.5 option aliases (P27), the
installer's unit under `/usr/local/lib/systemd/system`. The code fixes and
the strengthened tests are the next step.

The required Ubuntu/vanilla kernel matrix, Incus/LXD, combined coverage,
strict global gates and whole-daemon resource/timing promises, including
comparative P15 timing, remain Phase 6. The full root system-unit mount
sandbox, especially the bindv6only write exception, is still unverified.
The binary still exceeds the rewrite's under-1,500-line target before
inline tests; that size target remains open.

### Phase 6 — proof

The detailed instructions for this phase, with work packages, commands
and acceptance criteria, are on the [Phase 6 page](phase6.md).

1. The container suite (`tests/docker/`), rewritten as Rust integration
   tests driven by one runner script, one scenario per H rule and per
   G promise, against the real kernel: the dual-stack and IPv4-only
   hosts, `disable_ipv6`, `ipv6.disable` (QEMU only), VRFs, routers with
   no default route, containers, networkd and udev renames, hot-plugged
   devices, address churn, missing modules and capabilities, clock jumps
   (QEMU only: a container shares the wall clock with the host),
   hundreds of sessions, `bindv6only`, session MTUs at or above the
   underlay's (H20, an acceptance condition), the non-systemd contract, and the
   unprivileged Incus/LXD system container that `CONTRIBUTING.md`
   requires ([testing](testing.md#the-scenario-suite)).
2. The QEMU kernel matrix over the [kernel targets](testing.md#kernel-targets)
   of `CONTRIBUTING.md`: required are the stock kernels of the two latest
   Ubuntu LTS releases, their vanilla equivalents and mainline, as a
   rule that follows Ubuntu and kernel.org (24.04's 6.8.0 and 26.04's
   7.0.0 today; the table in testing.md MUST be updated and re-run when
   they move); desired are every release from v6.8 to the newest, Debian
   and RHEL-ish stock kernels. Each boots with TCG
   and runs the conformance suite and the K5 sweep; a kernel built
   without IPv6 serves H4 and T4.
3. Coverage: `cargo llvm-cov` over unit, fake-kernel and container tests
   combined, gate at 100 % of production lines and branches of `src/`.
   Test-only `#[cfg(test)]` bodies/helpers are excluded from instrumentation,
   but all required tests still execute. The only allowed production
   exclusions are `kernel::linux` branches that no kernel of the verified
   range reaches, each marked and justified. Test execution and rule
   traceability remain separate requirements.
4. The source-link check: every function of `kernel::linux` carries a
   `// kernel:` citation that names a K fact. Every linux-scoped K fact
   is cited by a function; delegated/source-only facts require explicit
   classification in the evidence map and a test declaration citation
   (maintainer decision, 2026-10-30).
5. The rule map: every numbered rule of every page appears in at least
   one test declaration; the report lists locations per rule. This is
   traceability only: required feature/ignored/live suites must separately
   execute successfully, and multi-clause rules retain explicit case lists.
6. Determinism: the fake-kernel suite runs with a seeded random source
   and a virtual clock; the container suite waits on events, never on
   sleeps of fixed length; each suite is run ten times in CI without a
   flake before the gate is enabled.

Exit: all five gates green on the running kernel and on every required
kernel target; the Incus/LXD scenario run, not skipped.

**Status: in progress on 2026-11-01.** Production source `584062d`
passes all thirteen required matrix profiles: five normal suites of 27
scenarios, five clock profiles, both IPv6-absent boots and missing-driver
recovery. Strict rule/source maps, unprivileged Incus and the root sandbox
have passing records. The checked libc exception is applied; no nix
contribution or release is required.

Released iphost 0.4.4 fixes V12's anonymous Reply validation defect. Three
live witnesses fail with 0.4.3 and pass with the registry release. Local
and required-kernel integration checks pass; the specification remains unchanged.

The current E27 correction fixes verification stopping while a session's
announced deletion is still queued. A delayed-work model witness fails on
the preceding implementation and passes with the correction. Repeated models,
GNU/musl live suites, three musl Incus runs and the root sandbox pass.
The required matrix passes all thirteen profiles on `584062d`, including
the E27 correction and released iphost 0.4.4.
The iphost 0.4.4 integration and standard-library boundary changes pass
common checks, ten native and instrumented seeds, three musl model runs,
GNU live/Incus, manager, task limits and the root sandbox. Three musl
scenario/Incus repetitions pass. The required matrix also passes all
thirteen profiles on frozen signed commit `584062d`. Later test-only
additions retain their separate execution records.

Earlier test-only additions have passing common checks and repeated
GNU/musl qualification. Fresh coverage for iphost 0.4.4 and the boundary changes is **97.21% of
lines and 90.59% of branches**, leaving **242 lines and 174 branches**. The 100% gate and complete
clause/history/resource/event-cost proof remain open. Repository file
`audit/PHASE6_VERIFICATION_2026-11-01.md` identifies each result's exact scope.
The following entries retain the history of earlier measurements.

**Initial status, 2026-10-31.** The strict source-link check
passes locally. The partial host scenarios, unprivileged Incus case and
root system-unit sandbox have passing records. The required matrix driver
passes all five currently implemented profiles and both scoped H4
boots, with unchanged published versions and tested sources. The
maintainer approved documenting vanilla 6.8.12's K26/K34 errno distinction.
Controlled boots traced the Ubuntu 26.04 initramfs OOM
to default-enabled kexec-handover scratch reservation; the cold-boot helper
disables that unused feature when the supplied config enables it.
A readiness/signal-order race found
by that guest is fixed and retested. Initial merged coverage is 91.03%
lines / 77.02% branches, before the readiness/H15 fixes. H15 now has four
capability/netlink scenarios and a scoped missing-driver guest pass; the
host subset now passes 26 scenarios, including the 300-tunnel scale case. H16 clock steps and monitored pause/resume
pass on all five required kernels, and the low-port-range DHCPv6 positive
case passes. H17 exercises every session, bounds descriptors across shrink
cycles and observes zero requests for unrelated links; a fresh mainline
normal profile passes the expanded 23-scenario suite. Two retained map
allocations are fixed. The lifetime subscriber now indexes deletion work
by interface and incarnation, with passing native/live/host cases. There
are no uncited active rules: the map links all 333. Deadline selection now uses ordered indexes, with
ten seeded rule runs, all host/process cases and a fresh mainline clock
case passing. Obsolete conflict history is released on removal/shutdown.
Relevant link/address cache maintenance now updates changed dependencies
instead of scanning all bindings. Regressions fix stale addresses after
resync and unbound VRF sibling records retained from notifications; five
focused cases, all host scenarios and ten seeded rule runs pass. The
rule-suite logger no longer forks across other fake socket owners.
R6/R9 now have live filter-refusal and descriptor-exhaustion/recovery
cases; the host suite passes 25 scenarios. Tunnel/session creation share
severity classification, and kernel EAGAIN is distinguished from the
internal tunable wait.
Library requirement tests now cover missing runtime/capability/logging,
lost caller-forwarded events, overlapping owners and active/retiring drop.
They fix sockets retained by a shared backend on drop and replace a missing
Tokio timer panic with a forwarded error. Ten seeded library/rule/service runs,
19 live kernel cases, 26 process cases and all 25 host scenarios pass.
Operator/peer/manager requirement assertions now link another 23 rules;
invalid UTF-8, occupied staging/rename candidates, raw frame admission and
empty `/proc` plus `/sys` have stronger executable checks. The real user-manager
descriptor-store check also passes separately from the container profile.
R35 now has a bounded burst/lost-source recovery case; a separate R45 guest
profile proves ordinary-device operation with the VRF driver unavailable.
All active R rules have test-declaration citations, with clause coverage still
subject to the complete proof and coverage gates.
O4 now has exact entry-label and configuration-diagnostic assertions. A
reproduced diagnostic defect is fixed: valid IDs survive left-out entries,
sessions include both IDs, and unknown-key diagnostics retain their context.
The planner now compares session fields, bindings and selected sources with
accepted configuration after each transition. Staging retries check no second
creation, and restart checks exact PID formatting and fixture disk contents.
Architecture/event/observability assertions link another 15 rules, with
module-map checks kept distinct from behavioral execution evidence.
A live G15–G20 scenario now checks early readiness with three disconnected
entries, measured connection, in-place stability/fidelity and ordered cleanup
with a successful process exit. The conflict process case enforces ten-second
readiness. Local traceability is complete. The required ten seeded fake/live
CI repetitions passed on their first attempt, and the common CI script now
enforces both strict map flags. The updated strict workflow passes both its
build and full live guest jobs; declaration traceability does not imply
complete clause proof.
Complete event-cost/resource/history proof, remaining clauses and
final matrix/coverage refreshes are still open. No global gate is declared
complete. The latest record is repository file
`audit/PHASE6_VERIFICATION_2026-10-31.md`; the approved H11 MAC limitations
remain in [H11](spec/hosts.md#other-network-managers).
[Required-kernel behavior](kernel-behavior.md) records all five targets'
observations, proof scope and limitations.

The earlier coverage refresh on Rust source `0f5292e` included inline test
code and measured 92.26% lines / 78.16% branches. Under the maintainer's
approved production-code scope, the latest merged report is 95.03% lines /
84.97% branches: 424 missing lines and 272 missing branches, with no
production exclusions. It includes all 26 normal scenarios, real user
manager and full Incus manager profiles. The unmodified musl
Incus runner has passing records and the later H11 failure described below.
The required-kernel refresh found a vanilla 7.0.14
fixture failure: asynchronous shutdown checks made total netlink counts vary.
Comparing drained startup/reload work fixes that measurement; three focused
repetitions and the full normal/clock profiles now pass on that kernel.
A later full required matrix passes all five normal and clock profiles,
both IPv6-absent boots and the missing-Ethernet-driver case. Published targets
match before and after. Its exact I/O source and earlier fixture set are in
`audit/phase6/matrix-20261031T213935Z-567802/README.md`. Later test additions
still need final consistent-source qualification, and full coverage remains
open. The ten-run CI evidence is
in repository file `audit/phase6/strict-gates-20261031/README.md`.
Resource-history tests now verify record/index/watch cleanup across repeated
300-entry configurations and fix retained DNS/outgoing queue capacity. Fresh
normal GNU, musl Incus and unmodified root-systemd profiles pass; repository
file `audit/phase6/resource-history-20261031/README.md` records their scope.
The subsequent shared-resolver fix makes recovered DHCPv6 discovery reach
the actual lookup job and indexes job cancellation and answer delivery.
Its fresh live, Incus and root-systemd checks pass; repository file
`audit/phase6/resolver-cost-20261031/README.md` records the regression,
cost comparison and remaining limits.
The next test-only batch covers abandoned service replies, resolver thread
creation failures and configuration conversions. Its common checks and ten
seeds pass. Repository file `audit/phase6/coverage-errors-20261031/README.md`
records the unchanged production source and incremental profiles. The
preceding resolver commit's CI live guest exposes upstream DHCPv6 listener
sharing across equally named interfaces in different namespaces. Released
`iphost` 0.4.2 fixes that cache and dead listener records; fresh full normal
guest, GNU coverage, Incus and root-systemd profiles pass. Repository record
`audit/phase6/upstream-netns-20261031/README.md` identifies the release and
source. Released `iphost` 0.4.3 now also fixes subscriber cleanup and bounds
pending datagrams; nine live upstream probes pass three times. Fresh daemon
profiles and a deterministic no-waiter readiness test retain 93.32% line /
80.95% branch coverage. Repository record
`audit/phase6/upstream-dhcp-queues-20261031/` gives exact scope. Complete
resource/event-cost proof, remaining clauses and the final matrix stay open.

Desired identifiers now index configuration names without repeated full scans;
complete identity checks still decide ownership. The rename planner uses
ordered holder/waiter indexes, and a session deletion retries only that entry.
Both changes pass ten seeds and fresh live, Incus and root-systemd profiles.
Repository records `audit/phase6/reconcile-lookups-20261031/` and
`audit/phase6/rename-cost-20261031/` retain comparisons and exact scope.
The standalone documentation check also passes after removing 36 links to
files outside `docs/`; its record is `audit/phase6/standalone-docs-20261031/`.

The latest validation/control simplification and error cases pass common
checks and ten seeds, with fresh GNU live and manager profiles. The coverage
record `audit/phase6/coverage-simplify-20261031/` excludes two profiling
experiments with invalid inferred counts. A new unmodified Incus failure
shows udev replacing a staged configured MAC; the preceding committed daemon
reproduces it. H11 precedence wording and its proposed explicit-authority
test await a maintainer decision. The evidence and unapplied correction are
in `audit/phase6/staged-mac-override-20261031/`; later individual passing
manager runs do not establish P5 determinism.

Descriptor retirement now indexes withdrawal tokens, blocked identifiers and
due work. Named host requests coalesce by name while preserving delivery order.
Five regression/resource cases, ten seeds and fresh GNU live, manager, Incus
and unmodified root-systemd profiles pass. The complete resource proof remains
open; `audit/phase6/store-cost-20261031/` records this batch's scope.

The fake backend now rejects closed local socket handles while external
descriptors retain their tunnels, matching the Linux backend. Strengthened
shared adoption assertions and four fake observation cases pass ten seeds
and fresh GNU profiles. `audit/phase6/fake-handles-20261031/` records the two
baseline failures and current proof scope.

The shared identifier case now verifies unregistered external ownership and
adoption refusal in both families. The fake matches the Linux backend's
observed behavior. Socket-backed proof failures, executable search/probe bounds
and mismatched inherited metadata have additional assertions, passing common
checks, ten seeds and fresh GNU profiles. Repository record
`audit/phase6/ownership-proof-20261031/` gives exact scope and limitations.

File and descriptor faults now have additional ownership, cleanup and reload
assertions. Their coverage helper retains exit profiles when opens are denied;
musl syscall spellings and probe-fixture fork isolation are verified. A one-use
peerless target conversion is removed. Common checks, ten seeds and fresh
GNU/Incus/root-systemd profiles pass; `audit/phase6/io-faults-20261031/` retains
the failed fixtures and final collection. A required matrix is running in an
isolated checkout of that source; it has no final result yet.

Monitor registration/receive errors, reactor shutdown and lifetime-reader
failure now have socket-backed assertions. The forking fault fixtures run
serially and pass three GNU and three musl repetitions. ARM64, RISC-V64 and
PowerPC64LE all-target test builds pass after fixing syscall assumptions.
Common checks, ten seeds and compatible GNU profiles pass; the repository
record is `audit/phase6/monitor-faults-20261031/`. No shipping logic changes.

Daemon setup faults now verify original errors, bounded parent exit and an
untouched PID file before kernel startup. Both service APIs return final
cleanup-query errors while releasing local descriptors. Common checks, ten
seeds, three GNU and three musl fault repetitions and fresh GNU profiles pass;
`audit/phase6/process-errors-20261031/` records the results. Shipping logic
and dependencies are unchanged.

Linux inheritance now has precise refusal/ownership assertions for Unix,
non-socket, UDP and TCP descriptors. Incomplete session identities and
truncated deletion notices have parser assertions. Three GNU, three musl
and three instrumented repetitions, ten seeds and common checks pass;
`audit/phase6/inheritance-validation-20261031/` records compatible production
coverage mappings and the remaining cross-kernel qualification.

Descriptor-store barrier tests now cover refused pipe/send/poll/read operations
and persistent interrupts, checking original errors, deadline bounds and local
descriptor release. Ten seeded binary runs, three musl repetitions, cross-target
builds and common checks pass. Repository record
`audit/phase6/barrier-faults-20261031/` gives compatible coverage mappings and
the remaining proof limits; shipping code is unchanged.

A new signal-fault probe finds an upstream nix error-handling defect: a
positive pthread error is treated as success. Upstream PR #2852 has a
GNU/musl-tested fix that also preserves musl's -1/errno convention. Integration
and the proposed daemon signal cases wait for a compatible upstream release;
there is no daemon workaround. Repository record
`audit/phase6/upstream-signal-errors-20261031/` gives the pinned reproduction,
upstream patch and remaining scope.

A redundant tolerant resolver correction is removed: literal processing
already handles it. The regression checks both corrected fields and their
order. Ten seeds, common checks and fresh GNU/live/manager/Incus and unmodified
musl root-systemd profiles pass. Repository record
`audit/phase6/config-correction-20261031/` gives the fresh coverage totals and
remaining qualification and resource limits.

Two isolated G23 witnesses keep one configured tunnel while increasing current
addresses or VRF members from 100 to 10,000. Retained daemon collections grow
with that host state. This differs from the completed-history checks and does
not establish the written configuration-only bound. Repository record
`audit/phase6/resource-cache-bounds-20261031/` gives exact counts and source;
the specification remains unchanged and G23 remains open.
An unapplied proposal would count current dependency state while requiring
streamed temporary inventories and prompt cleanup. That contract choice awaits
the maintainer; it does not make the existing full-namespace dumps compliant.

The fake backend now shares binding/peer/source state across adopted socket
aliases, matching the strengthened live conformance case. Final shared suites
pass three times on GNU and musl with CAP_NET_RAW present and absent. Ten
seeds, common checks and compatible GNU profiles pass; the fake reaches 100%
line coverage. Repository record `audit/phase6/alias-state-20261031/` gives
the baseline failure, production mapping checks and remaining scope.

The new upstream signal regression passes all four native Linux jobs, whose
full suites fail an unchanged receive-overflow test. Independent PR #2853
replaces its fixed packet-capacity assumption with measured loss. All 30
returned upstream CI jobs pass for that proposal. Repository record
`audit/phase6/upstream-overflow-fixture-20261031/` retains the controls;
both upstream fixes still await integration and the signal release.

The shared suite now checks repeated scoped link-local connects and renames
to the current name. GNU and musl cases pass three times with CAP_NET_RAW
present and three times absent, alongside ten seeded suites and compatible
coverage profiles. Repository record
`audit/phase6/repeated-operations-20261101/` gives the results and the initial
driver timeout. Production coverage reaches 95.03% lines / 85.03% branches;
final qualification and the remaining Phase 6 requirements stay open.

A closed host-request receiver now has a public-API regression: the tunable
deadline permits family fallback and readiness, while an unacknowledged
withdrawal still reports incomplete cleanup and releases local descriptors.
Ten GNU and three musl service suites and common checks pass. Repository
record `audit/phase6/closed-host-receiver-20261101/` gives compatible coverage
mappings and the remaining scope. Production coverage reaches 95.05% lines /
85.03% branches; the 100% gate remains open.

The fake no longer duplicates the generation in each tracked registration:
generation changes clear that map. Stronger fake/Linux index-reuse checks
preserve a foreign replacement through deletion and invalidate old lifetime
registrations. Ten seeded suites, GNU/musl live repetitions, fresh GNU/live/
manager/Incus profiles, an unmodified musl root-systemd guest, cross-target
compiles and common checks pass. Repository record
`audit/phase6/tracked-lifetime-20261101/` gives the fresh totals: 95.05% lines /
85.07% branches, with the remaining global requirements open.

Uncertain session creation now has eight result/publication/deletion cases.
A failed fresh scan must retain the record and reservation; an isolated
discard-without-verification control fails. Public sibling/publication and
failed event-scan cases also pass. Ten seeded suites, three musl library/rules
repetitions and common checks pass, with unchanged production mappings.
Repository record `audit/phase6/uncertain-sessions-20261101/` gives the
95.20% line / 85.56% branch report and its remaining proof limits.

A dual-family VRF event case checks address removals, member loss and
one-second recovery while preserving sessions and an unrelated tunnel.
Ten seeded suites, three musl rule repetitions and common checks pass.
Repository record `audit/phase6/vrf-address-events-20261101/` gives the
95.27% line / 86.01% branch report, compatible mappings, the corrected
source-preference assumption and the current implementation's passing CI.
The new required matrix now passes in its frozen bdf81b5 checkout; it
predates the later socket-state and approved fixture changes.

Required socket-operation failures now report unapplied work. Unspecified-
source cleanup restores the configured binding, and simultaneous full/
per-tunnel deadlines attempt each tunnel once. Ten seeded suites, three
musl library/fake/rule runs, fresh live/manager profiles and the root
sandbox pass. Repository record
`audit/phase6/tunnel-application-status-20261101/` gives the fresh
95.46% line / 86.11% branch report: 387 lines and 252 branches remain.

The maintainer approved explicit staged-MAC authority, G23's current
dependency-state bound with streamed inventories, and H6's retry-deadline/
observed-completion distinction. The specifications and MAC/timing fixtures
are updated. Three fresh Incus cases, the unmodified root-systemd guest,
three normal suites and common checks pass. Repository record
`audit/phase6/maintainer-decisions-20261101/` retains exact sources and
earlier failures. That approval alone did not pass G23; implementation and resource
verification follow below.

The November 1 required matrix re-resolves the same five published targets
and passes all normal/clock and scoped degradation profiles on bdf81b5.
Repository record `audit/phase6/matrix-20261101T003757Z-933582/` retains the
frozen source and publication checks. Final source qualification, the nix
release, full clause/resource/event-cost proof and 100% coverage remain
open. The production eeec257 workflow passes both CI jobs in about fourteen
minutes without timeout.

The daemon now streams link/address inventories and retains only current
dependencies. Two-pass monitor resync handles members before their VRF;
completed-dump staging rejects partial evidence. Resource cases cover
1–10,000 entries and release of all tracked state after the final
dependency; an early-commit negative control fails. Ten seeded suites,
three musl suites, common/cross checks, fresh GNU/live/manager profiles,
Incus, root sandbox and three serial normal suites pass. Repository record
`audit/phase6/streamed-inventories-20261101/` gives the current 95.51% line /
86.17% branch report: 385 lines and 253 branches remain.

An isolated QEMU control reproduces simultaneous scale workloads exhausting
the shared ARP budget: two packet failures coincide with two table-overflow
increments; the same traffic passes alone with no overflow. Host-kernel
scale qualification is now serial, with unchanged packet assertions.
Repository record `audit/phase6/neighbour-pressure-20261101/` retains the
source and diagnostic-only scope. Final kernel qualification, the nix
release, complete clause/resource/event-cost proof and 100% coverage remain
open.

A bound-member recovery case now verifies parent discovery without retaining
unrelated siblings or their addresses, across 1–10,000 siblings and VRF or
ordinary masters. Its omitted-parent control fails. Ten seeded suites,
three musl suites and common checks pass; production coverage mappings
match the preceding collection. Repository record
`audit/phase6/member-inventory-resync-20261101/` gives the current 95.51%
line / 86.34% branch report: 385 lines and 250 branches remain. Production
and guest fixtures are unchanged; the frozen 012764f matrix is running.

Discovery retry cases now check completed-job reuse, partial restarts,
missing/replaced devices and refused startup, preserving accepted peers.
Both omitted-reuse and omitted-dependency controls fail. Ten seeded suites,
three musl rule suites and common checks pass. Repository record
`audit/phase6/discovery-retries-20261101/` gives compatible coverage
mappings and the current 95.59% line / 86.72% branch report: 378 lines and
243 branches remain. Production and guest fixtures are unchanged.

Configuration cases now reject empty/overflowing DNS ports and verify quoted,
escaped key paths and ignored-field diagnostics. Ten seeded suites, three
musl library suites and common checks pass. Repository record
`audit/phase6/config-diagnostics-20261101/` gives unchanged production
mappings and 100% line/branch coverage of the text parser. Overall coverage
is 95.62% lines / 86.83% branches: 376 lines and 241 branches remain.

PID-file cases now reject device/inode mismatches and non-regular paths
both directly and through re-exec state parsing. An omitted-type-check
control fails both tests. Ten seeded suites, three musl binary suites and
common checks pass, with identical production coverage mappings. Repository
record `audit/phase6/pid-authority-20261101/` gives the current 95.63%
line / 87.05% branch report: 375 lines and 237 branches remain.

Eight PID syscall-fault cases now verify original errors, preserved existing
files and temporary-name cleanup; the omitted-cleanup control fails. Ten
seeded suites, three musl binary suites, cross-target compiles and common
checks pass, with identical production coverage mappings. Repository record
`audit/phase6/pid-faults-20261101/` gives the current 95.72% line / 87.38%
branch report: 367 lines and 231 branches remain.

The pre-created PID fixture now rejects a FIFO before truncation or writing,
preserving its inode and type. An omitted-validation control fails. Ten
seeded suites, three musl binary suites and common checks pass, with identical
production mappings. Repository record `audit/phase6/pid-fifo-20261101/`
gives the current 95.73% line / 87.49% branch report: 366 lines and
229 branches remain. Profiling helpers remain unchanged.

The frozen streamed-inventory matrix (`012764f`) now passes five normal and
five clock profiles, both IPv6-absent profiles and missing-driver degradation.
Initial/final publication selections agree. Repository record
`audit/phase6/matrix-20261101T025846Z-1217029/` retains all result markers.

The maintainer approved direct `libc` calls for broken `nix` wrappers,
without requiring contributions to `nix` or a release wait. Checked mask
setup and signal wait now replace the affected wrappers. GNU/musl delivery,
refusal and return-convention tests, actual-daemon errors, both failure
controls, ten seeded suites, three musl suites and common checks pass.
Fresh production coverage is 95.83% lines / 87.65% branches: 358 lines and
226 branches remain. Repository record
`audit/phase6/libc-signals-20261101/` gives exact sources and tests. The
later libc change needs its own required matrix; the complete clause/
resource/event-cost proof and 100% gate remain open.

Installer cases now verify failed-step reporting, preserved conflicting files,
continued independent steps and successful repair/retry. The false-success
control fails. Ten seeded suites, three musl binary suites and common checks
pass, with identical production mappings. Repository record
`audit/phase6/installer-errors-20261101/` gives the current 95.89% line /
87.81% branch report: 353 lines and 223 branches remain. Production code
and guest fixtures are unchanged; the frozen `ce6a70a` matrix is running.

Real task limits now refuse the first and second signal-thread allocations.
Ten GNU and three musl final-driver runs pass; the missing-wakeup control
fails at join. The bounded CI command and checker controls also pass locally.
Repository record `audit/phase6/signal-thread-limits-20261101/` retains the
initial container-creation timeout, its cleanup and the corrected driver.
Compatible profiles bring coverage to 95.95% lines / 87.81% branches,
leaving 348 lines and 223 branches. Production mappings are unchanged.

The file callback now has a semantic reload-conflict and recovery case,
including ERROR/WARN diagnostics and complete retained-entry values. The
false-success control fails. Ten seeded suites, three musl binary suites
and common checks pass, with identical production mappings. Repository
record `audit/phase6/file-reload-conflict-20261101/` gives the current
96.00% line / 87.81% branch report: 344 lines and 223 branches remain.
The separate event-cost witness finds a namespace-wide address scan for one
ordinary VRF-member event; targeted inventory work is under investigation.

The frozen checked-libc source now passes all five required normal and
clock profiles, both IPv6-absent boots and missing-driver recovery. Initial
and final publication checks agree. Repository record
`audit/phase6/matrix-20261101T041133Z-1418227/` records all thirteen profiles
and their exact scope. The later test-only tree also passes both GitHub
jobs, including the signal-thread resource step (run 41277232235).
The reproduced ordinary-event inventory cost and 100% coverage remain open.

Ordinary dependency inventories now use kernel selectors instead of reading
unrelated namespace records. Address/member and new-VRF witnesses remain at
one callback with 1, 100 or 10,000 unrelated records; broad, non-strict,
reopen and fail-open controls fail. Ten seeded suites, GNU/musl live
repetitions, three musl normal/Incus runs, both IPv6-absent boots, root
systemd and common checks pass. Repository record
`audit/phase6/event-inventory-cost-20261101/` gives exact source and fresh
96.01% line / 87.89% branch coverage: 345 lines and 223 branches remain.
The event-order review confirms that a cached previous master must survive
until its ordered member event arrives. A separate reload witness finds
missing siblings when a direct VRF binding is added after only its member
was bound. That inventory-completeness fix, the new production matrix and
complete clause/history/coverage proof remain open.

The confirmed reload defect now distinguishes a VRF's known kind from its
completed member inventory. Both model and live regressions fail on the
preceding code and pass with the fix. The corrected event-order test also
protects prior-master history. Ten seeds, the GNU live collection, three
musl normal and Incus runs, root systemd and common checks pass. A controlled
K41 witness explains the initial eight-request scale failure; serialized
captures retain the strict zero-query assertion and pass. Repository record
`audit/phase6/vrf-inventory-state-20261101/` gives exact source, controls
and fresh 96.05% line / 88.04% branch coverage: 342 lines and 221 branches
remain. The all-fcntl fault's profile-write limitation, new required matrix
and complete clause/history/coverage proof remain open.

The standard-stream fault now refuses only stdin's descriptor probe, preserving
LLVM profile I/O. Its broad-fault control fails the new profile-error check;
three GNU and three musl repetitions, ten seeded suites, cross-target builds
and common checks pass. Repository record
`audit/phase6/coverage-stream-fault-20261101/` gives unchanged production
mappings and 96.07% line / 88.10% branch coverage: 340 lines and 220 branches
remain. Production code is unchanged; the frozen required matrix continues.

Resolver validation cases now verify link/scope refusals, replacement indexes,
explicit DHCPv6 identities, missing/refused MAC fallback and recovery. Both
omitted-scope and lost-identity controls fail. Ten seeded suites, ten
instrumented repetitions, three musl library runs and common checks pass.
Repository record `audit/phase6/resolver-validation-20261101/` gives unchanged
production mappings and 96.25% line / 88.20% branch coverage: 325 lines and
218 branches remain. Shipping logic and live-kernel fixtures are unchanged.

A resolver-adapter drop case now checks per-owner job/index cleanup, continued
answers for a surviving adapter, and eventual permit release. A control that
clears foreign jobs fails. Ten seeded suites, ten instrumented repetitions,
three musl library runs and common checks pass. Repository record
`audit/phase6/resolver-drop-20261101/` gives unchanged production mappings
and 96.28% line / 88.26% branch coverage: 322 lines and 217 branches remain.
Production code is unchanged.

The public Tokio and blocking service constructors now have a live lifecycle
case: configured objects, repeated readiness, one host receiver, late capacity
refusal and complete cleanup. An ignored-configuration control fails. Three
GNU and three musl runs pass all 24 Linux cases, alongside cross-target builds
and common checks. Repository record
`audit/phase6/service-constructors-20261101/` gives unchanged prior production
mappings, nine new generic instantiations and the positive live return counter.
LLVM's aggregate stays at 96.28% lines / 88.26% branches; the gate remains open.
Production code is unchanged.

The library harness now reuses all 88 public rule declarations alongside
private cases, improving generic-instance coverage without new exclusions.
The external target remains. Logger and child-launch interference are isolated;
all 17 serial cases pass three GNU and three musl runs. Ten ordinary and ten
instrumented seeds, three musl runs and final common checks pass. Repository
record `audit/phase6/shared-rule-harness-20261101/` gives unchanged line/branch
denominators and 96.47% line / 88.85% branch coverage: 306 lines and 206 branches
remain. Shipping code is unchanged.

The frozen filtered-inventory/cache implementation now passes all thirteen
required profiles: five normal suites of 27 cases, five clock profiles,
both IPv6-absent boots and missing-driver recovery. Initial/final published
versions agree and both source patches are empty. Repository record
`audit/phase6/matrix-20261101T075850Z-1691154/` identifies `2051827` and the
later test-only scope. Per-kernel documentation and the current checkpoint
now use that result. Complete clause/history proof and 100% coverage remain
open.

Staging cases now require a free eighth name to succeed, eight collisions to
leave no partial state, original creation errnos to survive, and retry to
preserve the tunnel and foreign links. Both draw-bound controls and the
errno-replacement control fail. Ten seeded suites, ten instrumented session
repetitions, three musl library runs and common checks pass. Repository record
`audit/phase6/staging-bounds-20261101/` gives identical production mappings
and 96.50% line / 88.91% branch coverage: 303 lines and 205 branches remain.
Shipping code is unchanged.

Session race tests now interleave a creation-name collision and late ownership
loss/removal before publication. They require safe staging, preservation of
foreign indexes/MACs, bounded recovery and no changes after published ownership
is lost. All three broken controls fail. Ten seeded suites, ten instrumented
service repetitions, three musl service runs and common checks pass. Repository
record `audit/phase6/session-races-20261101/` gives unchanged prior mappings,
five callback instantiations and 96.56% line / 89.02% branch coverage: 298 lines
and 203 branches remain. Shipping code is unchanged.

Descriptor inheritance now has eleven isolated cases for count/name refusals,
ownership and close-on-exec, unannounced cleanup, foreign PID announcements,
and close_range fallback through the hard limit or its original query error.
All three faulty controls fail. Ten ordinary and ten instrumented repetitions,
three musl binary suites, three cross-target checks and common checks pass.
Repository record `audit/phase6/descriptor-inheritance-20261101/` gives
unchanged source regions and 96.67% line / 89.29% branch coverage: 288 lines
and 198 branches remain. Shipping code is unchanged.

The fallback rule case now keeps an AF_INET socket and its published session
through IPv6/IPv4 peer moves, checks a fresh dual-stack sibling independently,
and preserves UP/MAC/index state. The disabled compatibility-guard control
fails. Ten ordinary and ten instrumented repetitions, three full musl
library/rule suites and common checks pass. Both shared rule catalogs have
89 cases. Repository record `audit/phase6/family-fallback-20261101/` gives
identical production mappings and 96.71% line / 89.34% branch coverage:
285 lines and 197 branches remain. Shipping code is unchanged.

The fake controls now have explicit cases for a VRF's own address, stale
address input, unregistered socket descriptor lifetimes and ordinary versus
L2TP MAC changes. All four faulty controls fail. Ten ordinary and ten
instrumented repetitions, three full musl fake suites and common checks
pass. Repository record `audit/phase6/model-controls-20261101/` gives identical
production mappings and 96.71% line / 89.56% branch coverage: 285 lines and
193 branches remain. Neither the model nor shipping behavior changes.

Advisory session-deletion verification now remains pending while deletion
work is queued. Configuration identity changes cancel obsolete tasks even
when cleanup fails, and late notices cannot recreate them. Model and live
regressions fail on the preceding code. Ten seeds, repeated GNU/musl live
tests, three musl normal/Incus runs, root systemd, real-manager checks and
task-limit profiles pass. Repository record
`audit/phase6/event-verification-20261101/` identifies production commit
`11bef84`; its required matrix is running.

The instrumented library now reuses startup fault cases in the serial
profile. Parallel-child interference and the initial child-selection
mistake are retained, with failed profiles quarantined. Ten final seeds,
ten instrumented repetitions, musl tests, the failing child-name control
and common checks pass. Repository record
`audit/phase6/shared-startup-harness-20261101/` gives fresh 96.86% line /
89.68% branch coverage: 272 lines and 191 branches remain. Shipping logic is
unchanged; complete clause/history/resource proof and 100% remain required.

Resolver-pressure reporting now has two complete warning/recovery episodes
that preserve the accepted peer, lookup and socket without kernel mutation.
Both omitted-report controls fail. Ten ordinary and instrumented repetitions,
three musl suites and common checks pass. Repository record
`audit/phase6/worker-pressure-reporting-20261101/` gives identical common
production mappings and 96.92% line / 89.73% branch coverage: 267 lines and
190 branches remain. Shipping logic is unchanged.

Tunable input guards and empty configuration paths now have direct boundary
cases. All three guard controls fail inside networkless containers; the
false-presence control also fails. Ten ordinary and instrumented binary
runs, three musl binary suites and common checks pass. Repository record
`audit/phase6/input-boundaries-20261101/` gives unchanged production source
regions and 96.93% line / 89.84% branch coverage: 266 lines and 188 branches
remain. Shipping logic is unchanged.

Blocking-service channel cases now preserve the original closed/full queue
and abandoned-reply errors. Each altered-message control fails only its
corresponding case. Ten ordinary and instrumented repetitions, three musl
library suites and common checks pass. Repository record
`audit/phase6/blocking-transport-20261101/` gives unchanged common production
mappings and 96.96% line / 89.84% branch coverage: 263 lines and 188 branches
remain. The ordinary library has 237 passing cases. Shipping logic is unchanged.

The released resolver adapter now has live wire checks for anonymous,
link-layer, random and raw identities, retransmission stability, accepted
Replies and bound static DNS queries. All three broken mappings fail.
Ten model and instrumented repetitions, three GNU and three musl live runs,
musl library suites and common checks pass. Repository record
`audit/phase6/resolver-wire-identity-20261101/` gives identical production
mappings and 97.01% line / 89.89% branch coverage: 259 lines and 187 branches
remain. This new wire case has Ubuntu 6.8 scope; other targets remain unrun
for that specific case.

The E27 source `11bef84` now passes all thirteen required matrix profiles:
five normal suites, five clock profiles, both IPv6-absent boots and
missing-driver recovery. Initial/final publication selections agree and
both tracked-source patches are empty. Repository record
`audit/phase6/matrix-20261101T115808Z-2050597/` gives per-kernel timings and
the live replay's scope. This matrix uses iphost 0.4.3; it does not close the
subsequently discovered anonymous-Reply defect or qualify its correction.

### Phase 7 — release

Update the changelog, the top-level README and these pages for what
shipped; tag 0.2.0; publish with `cargo publish --registry crates-io`;
build the `musl-deb` packages for `amd64` and `arm64`
([packaging](packaging.md#musl-deb-a-minimal-debian-package)) and attach
them to the release with the tarballs. The `musl-deb` directory itself
(the build script, the control template, the maintainer scripts and
their CI check) is written in this phase, since it only wraps the
finished binary.

## What is removed

| Removed | Replaced by |
|---|---|
| The discard addresses, null device, grace period and route repair | The disconnected state (K5, T1) |
| `rtnetlink`, `netlink-proto`'s unbounded queue in the monitors, `futures-util`, `async-trait` | `netlink-sys` sockets on `tokio::io::unix::AsyncFd` ([dependencies](dependencies.md)) |
| `clap`, `env_logger` | Hand-written option parsing (P27) and a thirty-line logger (O1) |
| The `--setup` installer and the `setup` feature | `--setup-systemd` behind the `setup-systemd` feature, with the explicit, bounded scope of [packaging](packaging.md): not a substitute for the Debian-family packaging planned in Phase 7's `musl-deb` directory |
| Per-kind `handle_*` methods as the only dispatch | `handle_event` (L10) |
| Twenty-one `privileged_` library tests and seventeen shell scenarios | The current conformance and process suites, with the full scenario suite still planned for Phase 6 in [testing](testing.md) |
