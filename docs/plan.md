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

- **Nothing is kept for its own sake.** The current tree (17,000 lines,
  of which `runtime.rs` 6,600 and `state.rs` 4,200) is read for the
  kernel facts it learned, not for its structure; the target is under
  7,000 lines of library and 1,500 of binary, excluding tests.
- **One boundary makes everything testable.** The reconciler talks to the
  host only through the `Kernel` trait of the [architecture](architecture.md#the-kernel-boundary).
  A fake implementation encodes the kernel facts K5–K41; the real one
  wraps the sockets. Every behavioural rule is tested against the fake,
  deterministically; every kernel fact and every real implementation is
  tested against the live kernel.
- **Every rule has a number, every test names one.** A test that guards
  rule T21 carries `#[spec("T21")]`-style markers in its name or doc
  comment (`// spec: T21`), and a check in CI fails when a rule of the
  specification has no test naming it ([testing](testing.md#gates)).
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
| 1 | Configuration: types, validation, lenient conversions, serde, TOML merging in the binary | 0 |
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
   the `l2tp` multicast events; it needs `/proc` for the namespace (R7,
   accepted). `iphost` 0.4.0 provides configured resolvers, the `ipv6`
   method and `retain_stale_values`.
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

### Phase 1 — configuration

Implements [configuration](spec/configuration.md) C1–C17 and the
library types of L3–L4.

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

Exit: every C rule and L3–L4 mapped to a passing test; `cargo doc`
clean.

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
3. `kernel::linux`: the real implementation over `l2tp::TunnelSocket`,
   `l2tp::L2tpHandle`, and `netlink-sys` sockets with
   `netlink-packet-route` for the rtnetlink requests and the two
   subscriptions; the event monitor attaches the classic BPF program of
   A5 through `socket2`; `SO_RCVBUFFORCE` then `SO_RCVBUF` (R10); the
   lifetime socket answers ordered lookups (A7); `ENOBUFS` is surfaced as
   a loss (E21); only port 0 is accepted (E22). Every function cites the
   kernel source lines of the fact it relies on, in the form the
   source-link check reads (`// kernel: net/l2tp/l2tp_ip.c:333-334 (K22)`).
4. Live tests (`tests/kernel/`), one per K fact, run against the real
   kernel in a privileged container and against the fake; the same test
   body for both (the conformance suite of [testing](testing.md#the-conformance-suite)).

Exit: every K fact has a conformance test passing on the fake and on the
running kernel; the fake is the only kernel the phase 3 tests use.

### Phase 3 — the reconciler

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
   retry (V12), answers polled once a second (V4).
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

Exit: every M, T, S, V, E, G rule mapped to a passing deterministic
test; the reconciler has no `tokio` dependency except the channel types.

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
   service, `cargo doc -D warnings`.

Tests: the service tests of L5–L13 against the fake kernel (converge
with a conflict, run then reload, a full queue, a callback panic, drop
without shutdown, adopted descriptors verified and refused); doc tests;
a `#[non_exhaustive]` and re-export check (L3).

Exit: every L rule tested; the library builds with no default features,
with `serde`, and under `cargo doc -D warnings`.

### Phase 5 — the binary

Implements [process](spec/process.md) P1–P27 and
[observability](spec/observability.md) O1, O7, O8.

1. Command line (P27) by hand, no `clap`: the nine options, exclusive
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
   descriptors closed.
9. Restart (P26, E26): the `--adopt-version` probe, close-on-exec cleared
   on the handed sockets only, `execve` of the path the daemon was started
   with, signal mask reset in the new instance.
10. Capability report (R49): read `/proc/self/status` `CapEff` and report
    each missing one once.
11. The systemd unit (P21) shipped as `contrib/rs-l2tpd.service`, with a
    test that parses it for every required key.

Tests: unit tests for the command line, the merging, the rendering, the
PID-file rules (on a temporary directory), the signal merging (with the
service on the fake kernel); container tests for daemonisation,
readiness, the PID file, the store protocol against a tiny notify-socket
listener, the restart exec, and the capability report.

Exit: every P and O rule tested; the binary runs on glibc and musl
targets (P24).

### Phase 6 — proof

1. The container suite (`tests/docker/`), rewritten as Rust integration
   tests driven by one runner script, one scenario per H rule and per
   G promise, against the real kernel: the dual-stack and IPv4-only
   hosts, `disable_ipv6`, `ipv6.disable` (QEMU only), VRFs, routers with
   no default route, containers, networkd and udev renames, hot-plugged
   devices, address churn, missing modules and capabilities, clock jumps,
   hundreds of sessions, `bindv6only`, the non-systemd contract.
2. The QEMU kernel matrix: every release from v6.8 to the newest, booted
   with TCG, running the conformance suite and the K5 sweep; a kernel
   built without IPv6 for H4 and T4.
3. Coverage: `cargo llvm-cov` over unit, fake-kernel and container tests
   combined, gate at 100 % of lines and branches of `src/`, with the
   only allowed exclusions being the `kernel::linux` branches that a
   kernel of the verified range cannot reach, each marked and justified.
4. The source-link check: every function of `kernel::linux` carries a
   `// kernel:` citation that names a K fact, and every K fact is cited
   by at least one function.
5. The rule map: every numbered rule of every page appears in at least
   one test; the report lists the tests per rule.
6. Determinism: the fake-kernel suite runs with a seeded random source
   and a virtual clock; the container suite waits on events, never on
   sleeps of fixed length; each suite is run ten times in CI without a
   flake before the gate is enabled.

Exit: all five gates green on the running kernel and the matrix.

### Phase 7 — release

Update the changelog, the top-level README and these pages for what
shipped; tag 0.2.0; publish with `cargo publish --registry crates-io`.

## What is removed

| Removed | Replaced by |
|---|---|
| The discard addresses, null device, grace period and route repair | The disconnected state (K5, T1) |
| `rtnetlink`, `netlink-proto`'s unbounded queue in the monitors, `futures-util`, `async-trait` | `netlink-sys` sockets on `tokio::io::unix::AsyncFd` ([dependencies](dependencies.md)) |
| `clap`, `env_logger` | Hand-written option parsing (P27) and a thirty-line logger (O1) |
| The `--setup` installer and the `setup` feature | Nothing: packaging installs the unit (`contrib/`) |
| Per-kind `handle_*` methods as the only dispatch | `handle_event` (L10) |
| Twenty-one `privileged_` library tests and seventeen shell scenarios | The conformance suite and the scenario suite of [testing](testing.md) |
