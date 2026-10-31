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
   combined, gate at 100 % of lines and branches of `src/`, with the
   only allowed exclusions being the `kernel::linux` branches that a
   kernel of the verified range cannot reach, each marked and justified.
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

**Status: in progress on 2026-10-31.** The strict source-link check
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
host subset now passes 25 scenarios, including the 300-tunnel scale case. H16 clock steps and monitored pause/resume
pass on all five required kernels, and the low-port-range DHCPv6 positive
case passes. H17 exercises every session, bounds descriptors across shrink
cycles and observes zero requests for unrelated links; a fresh mainline
normal profile passes the expanded 23-scenario suite. Two retained map
allocations are fixed. The lifetime subscriber now indexes deletion work
by interface and incarnation, with passing native/live/host cases. There
are three uncited rules (G15, G16, G20). Deadline selection now uses ordered indexes, with
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
Complete event-cost/resource/history proof, remaining clauses and
final matrix/coverage refreshes are still open. No global gate is declared
complete; strict CI flags remain off. The latest record is repository file
`audit/PHASE6_VERIFICATION_2026-10-31.md`; the approved H11 MAC limitations
remain in [H11](spec/hosts.md#other-network-managers).
[Required-kernel behavior](kernel-behavior.md) records all five targets'
observations, proof scope and limitations.

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
