# Developer guide

For developers integrating the library or changing the project.
The other guides address installation and operation. The
[specification](spec/README.md) is authoritative; generated Rust API
documentation is available with `cargo doc --all-features --no-deps`.

## Build and contribute

Use Rust 1.89 or later on Linux. The default build includes the daemon;
`--no-default-features` builds the library, and `--features serde` adds
configuration serialization. Release artifacts use static musl targets.

Before each commit, run:

```sh
rustup target add x86_64-unknown-linux-musl
./test-ci-gates.sh
```

The script requires Git, ShellCheck, rustfmt and Clippy. It checks POSIX
shell, formatting, warning-denied analysis/documentation, library feature
combinations, GNU/musl tests and both strict traceability maps.
Use `./commit.sh` for signed commits with a Signed-off-by trailer and
`./sync.sh` to fetch, rebase and push. Commit only your own changes.

Keep protocol defects in their upstream libraries; keep daemon policy here.
The narrow checked-libc exceptions are described in
[checked libc exceptions](#checked-libc-exceptions). Preserve error conventions,
check outputs only after success, and exercise GNU and musl failure paths.

## Gates

A test citation provides traceability. An executed assertion proves only
the behavior and environment it actually exercises. Keep semantic clause
cases, kernel-source reasoning, live execution and coverage distinct.

| Gate | Required evidence |
|---|---|
| Rule map | Strict mapping for every active numbered rule, with assertions for each clause and table case |
| Kernel sources | Every Linux-facing function cites the applicable K facts; delegated/source-only facts retain explicit classifications |
| Scenarios | Complete host/process scenarios, including scale and fragmentation |
| Required kernels | All thirteen profiles on stable published selections and unchanged source |
| Coverage | 100% merged production source lines and executable condition outcomes |
| System container | Executed unprivileged Incus/LXD profile |
| Root unit | Unmodified systemd unit in its root mount/capability sandbox |

Repository file `audit/VERIFICATION.md` identifies qualified source and results.
A routine CI pass covers common gates, one live guest, merged coverage,
source-work curves and GNU/musl allocations. It does not replace the full
kernel matrix, Incus or root-unit qualification. A skip is not a pass.

Test-only bodies are excluded from coverage instrumentation while their
required suites still execute. Production exclusions are limited to marked
`kernel::linux` branches unreachable across the verified kernel range.
A reachable missing path needs a test. Do not weaken assertions or exclusions
to close a gate.

## Suites and isolation

| Suite | Purpose |
|---|---|
| `src/` unit tests | Private state, parsing and syscall fault paths |
| `tests/rules/` and `tests/properties/` | Policy and seeded reload invariants over the fake kernel |
| `tests/kernel/` | Shared fake/live operations, private live cases and review probes |
| `tests/process.rs` | Actual daemon startup, signals, PID files and restart |
| `tests/scenarios/` | End-to-end host, manager, scale and fragmentation behavior |

Use virtual clocks, injected results and barriers for ordering. Fault fixtures
trace only their own child and require Linux `PTRACE_GET_SYSCALL_INFO`.
Fork-based cases run serially after parallel fake descriptor owners finish.
Ignored declarations do not count as execution.

Keep host-kernel scale and request-count windows serial. Network namespaces
share neighbor capacity, and older kernels broadcast L2TP deletions across
namespaces. Independent QEMU kernels isolate both effects. Clock/pause
profiles also run serially.

Do not change host networking, modules, sysctls or services. Every test link,
address and route belongs to a disposable namespace, networkless container
or guest. Docker builds and runs use `--network none`. Incus tests attach no
host interface, explicitly use `security.privileged=false`, and clean up on
failure. Missing Incus access exits 77 and leaves the gate open.

## Kernel targets

The required matrix resolves the latest two Ubuntu LTS kernels, their latest
vanilla equivalents and mainline before and after each run. It rejects
changed selections and source patches. Each kernel gets normal and H16
clock/pause boots; mainline also gets both IPv6-absent boots, and modular
Ubuntu gets missing-Ethernet-driver recovery.

```sh
tests/docker/run.sh matrix required
tests/docker/run.sh scenarios
tests/docker/run.sh incus
```

The normal profile must pass every suite/result marker and the expected
guest release. Clock runs additionally require `H16_CONTROLLER_RESULT=0`;
a successful QEMU exit alone proves nothing. Publication HTML is fetched
and parsed temporarily, never committed.

Repository files `tests/kernel/README.md` and `tests/docker/README.md`
give image preparation, required and optional kernel commands, and
Debian 13/Rocky 9/10 package verification. Optional kernels extend the
record without qualifying their distribution userspace.

## System containers

Run three fresh scenario/Incus pairs when qualifying a changed source.
Provide L2TP, VRF, dummy and veth modules and an Incus root-disk storage pool.
The profile checks namespace-local tunables, actual
`SO_RCVBUFFORCE=EPERM` fallback, systemd storage/adoption, re-exec and cleanup.
Manager races must preserve the active device; tests must not lower it to
force MAC assignment.

## Root systemd unit

```sh
tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD
```

Prepare the Ubuntu 24.04 systemd image from a fresh checkout:

```sh
tests/kernel/build-systemd-image.sh
# Rebuild using only the already fetched indexes and packages:
tests/kernel/build-systemd-image.sh --offline
```

The caller fetches Ubuntu's InRelease files, indexes and packages over HTTPS.
The resolver container verifies signatures with Ubuntu's archive keyring;
apt verifies package digests before installation. Both Docker build stages
and the resolver container use `--network none`. The maintained
[Dockerfile](https://github.com/menhera-org/rs-l2tpd/blob/main/tests/kernel/Dockerfile.systemd) installs systemd, udev, dbus,
iproute2, procps and kmod. The runner consumes the resulting
`rs-l2tpd-systemd:ubuntu24.04` image. Cached inputs live under
`target/systemd-image/`; preserve them for a later offline rebuild.
Offline mode requires the cached Ubuntu base image as well as the fetched
files. Apt's signature and expiry checks remain enabled.

Install through `--setup-systemd` inside the guest. Leave the unit unmodified
and check startup ordering, the tunable-write exception, PID directory and
three capabilities. Check crash/store survival, adoption, in-place restart
preserving interface indexes, and clean stop. A user-manager transport check
does not establish the root sandbox result.

## Coverage and work bounds

Use pinned nightly `2026-10-28`, LLVM tools and `cargo-llvm-cov` 0.9.1.
Collect ten native seeds, the complete instrumented guest and thread/fork
failure profiles from one unchanged source. Run calibration and negative
controls first. Repository file `tools/coverage/README.md` gives the commands.

The checker merges matching production source spans and repeated condition
occurrences across executable copies. Keep its source/mapping inventory,
complete compressed LLVM export, diagnostics and raw summary. Reject changed
sources and inconsistent mappings. Raw per-instantiation percentages remain
separate from merged source coverage.

The strict gate's ten-seed/live repetition qualification remains in
[history](https://github.com/menhera-org/rs-l2tpd/tree/c599b1f9c2343a3ffe6be315a6d77c4b68106744/audit/phase6/strict-gates-20261031).
Maintain deterministic regressions without automatic retries.

## Documentation

```sh
cargo install mdbook --version 0.5.4 --locked --registry crates-io
mdbook build docs
mdbook serve docs
```

`docs/SUMMARY.md` lists the book chapters. Output goes to ignored
`target/mdbook/`. The SHA-pinned Pages workflow in
`.github/workflows/pages.yml` builds pull requests and deploys `main`
through GitHub Pages artifacts with `.nojekyll`. Generated HTML stays out of Git.

Keep these guides current. Verify obsolete material is in Git before removing
it; retain only brief summaries and immutable history links. Current gating
code belongs in `tests/`, `tools/` or the repository root, outside `audit/`.
Do not record machine-specific facts.

## Acceptance cases

The guest-only `no-vrf` profile tests R45 with a modular stock kernel:
`tests/kernel/run-guest.sh IMAGE MODULES CONFIG no-vrf RECORD`. It leaves
the VRF driver unloaded and disables guest module autoload, requires a real
VRF creation refusal, then tests ordinary-device binding and frames over both
families. It is a scoped profile, separate from the normal suite; it never
changes the host's modules or autoload policy. See the
[archived host-requirement record](https://github.com/menhera-org/rs-l2tpd/tree/c599b1f9c2343a3ffe6be315a6d77c4b68106744/audit/phase6/host-requirements-20261031).

These acceptance cases remain mandatory. They cover policy, real kernel
boundaries, service callbacks/queues and process crash/re-exec behavior.
Whole-daemon timing/resource and kernel/host qualification remain separate
gates; no one layer's test substitutes for another.

| Rules | Deterministic policy case | Real boundary evidence |
|---|---|---|
| S23, M18, S24 | Lose lifetime notifications while staged; replace the device using both its index and temporary name. No rename/MAC operation may hit the replacement. Verify ambiguity/refusal preserves it, and confirmed absence precedes restaging. | Namespace move/reuse on the live kernel; compare the registration incarnation, not only current name/index. |
| L12, T26, P8, P25 | Delay success to the last instant before 5 s: no tunnel registered meanwhile, then fresh dual-stack socket. Cover failure, exact deadline, late success, still-v6-only read-back, multiple waiters and shutdown. Existing sessions never re-create. | Set `bindv6only=1` in an isolated namespace; confirm fresh socket read-back after write, both V4/V6 fallbacks and the kernel's fixed per-socket option. |
| P14, P26, L13 | Inherit removed or changed-peer tunnels; retain exact names through rejection, distinguish a failed query from a mismatch, and serialize old-name withdrawal before replacement storage. Cover failed/missing acknowledgements and cleanup retries. | With a real systemd store, close only the local duplicate and show the tunnel remains; then withdraw the stored copy and confirm absence. Exercise crash/re-exec with changed config, a delayed removal/barrier and bounded failing shutdown. |
| V3, V15, G23 | Block eight fake libc calls; repeatedly replace/remove names and create/drop services. No ninth system worker starts; permits return only when calls do. Configured DNS, kernel events, readiness and shutdown still progress. Verify one pending/latest result per current key and release of unused discovery refs. | Adapter tests use a controllable blocking resolver rather than waiting on real DNS; test namespace ownership and actual thread/descriptor counts. |
| V10 | A+B, then refresh or withdraw A alone: B remains. Include no-RDNSS RA, interleaved routers, split netlink delivery, lifetime/stale rules and capacity overflow. | Upstream Rust parser/state regressions; raw and ND_USEROPT paths yield equivalent updates. Downstream tests use the released corrected crate. |
| V14 | Enable fallback: DHCPv6 timeouts/SERVFAIL with working RA; positive/negative DHCPv6 finality; partial-family success; recovery next refresh; both sources fail. | Upstream transport tests verify default compatibility, per-family results and policy-dependent 33/63 s upper bounds. Downstream tests enable the released option explicitly. |

Use barriers, injected results and virtual clocks for delayed calls and
deadlines; no fixed sleeps or uncontrolled Internet DNS in unit tests.
Upstream and daemon tests have separate ownership:
[resolver integration](peer-discovery.md).


## Library

These dependency examples describe v0.2.0, published on crates.io.

```toml
[dependencies]
rs-l2tpd = { version = "0.2", default-features = false }               # no TOML, no serde
# Or use this alternative instead of the line above:
# rs-l2tpd = { version = "0.2", default-features = false, features = ["serde"] }
```

- `config`: `Config` is always valid (L4); `PartialConfig` offers the
  strict and the two lenient conversions with every problem (C15).
- `service::Service` (Tokio): `new(config, adopted)`, `converge`, `run`
  with a reload callback and a restart callback, `control()` (L5–L7).
- `blocking::Service`: the same on a runtime of its own; `Drop` shuts
  down (L8).
- `runtime::Runtime`: `new`, `reconcile`, `handle_event`, `shutdown`;
  every `ControlEvent` goes to `handle_event` (L9, L10); the program
  answers `WriteTunable`, `StoreSocket` and `ForgetSocket` (L12, L13).
- `Control`: `reload`, `reload_wait`, `shutdown`, `restart`, `config`
  (L6).
- Errors use a non-exhaustive enum (L11). Foreign types are re-exported
  next to their use; public enums are non-exhaustive (L3).
- The library does no standard or file I/O, reads no environment,
  installs no handler, writes no tunable (L1).

The library surface above is implemented. Constructors take
`Vec<AdoptedSocket>`; startup failures return `(Error, Vec<AdoptedSocket>)`
so the caller retains cleanup authority. Service reload callbacks take
the accepted `Config` and return `Result<Config>`; restart callbacks take
owned socket duplicates and return `Result<()>` if exec did not happen.
Both services offer `set_store_capacity` and `take_requests` before
convergence for optional host integration. Drain the request receiver
and answer through `Control`; without integration the library declines
tunable writes and uses local socket ownership.
Ordinary host threads can use `Receiver::blocking_recv`,
`Control::tunable_written_blocking` and `Control::socket_forgotten_blocking`,
including from `tokio::task::spawn_blocking`. Async workers use the async
completion methods. The blocking service waits for orderly cleanup on drop;
the Tokio service's drop only requests shutdown. Await its `run` to observe
cleanup completion and errors while the caller's runtime stays active.

Configuration problems retain valid tunnel/session identifiers from the merged
input, including for left-out entries and unknown keys. Their display and
strict-conversion errors include that context; missing or invalid IDs are
omitted, and cookie values remain redacted.

Reload callbacks do not suspend kernel events, timers or host completions.
Reloads accepted during initial convergence are ignored; restarts accepted
at any time, and reloads accepted after convergence, are retained for `run`.
A panicking restart callback ends `run` with `Error::RestartPanicked` after
cleanup, as a reload panic does. Deferred operator requests share a
bounded admission budget, so a blocked callback cannot create an unbounded
backlog. Injected blocking callbacks run outside Tokio context and may build
and drive a runtime of their own.

`Runtime::next_event` is the program-driven receive operation.
Its synchronous preparation keeps injected kernel callbacks on the caller's
thread; the returned future performs the wait. Constructors remain synchronous
so startup errors immediately return the adopted descriptors. Runtime-dependent
work checks for Tokio context; a missing context during a timed event wait
produces `ControlEvent::Failed`, which `handle_event` returns as an error.
Channel-only control/completion futures also work with other executors.
`Runtime::shutdown` returns `Ok(false)` while cleanup is pending; keep
forwarding events until it returns `Ok(true)` or a cleanup error.
Dropping a program-driven runtime closes its active and retiring tunnel sockets
without performing ordered session deletion. Explicit shutdown is needed to
observe cleanup completion and errors, particularly with external socket copies.

## Build tools


These tools are not linked into the daemon.

| Tool | Use |
|---|---|
| Stable Rust with rustfmt and Clippy | Build and common checks |
| `cross` | Static x86_64 and aarch64 release builds |
| ShellCheck | POSIX shell checks |
| Docker, QEMU TCG, cpio, binutils and kmod | Disposable kernel and host-condition tests |
| Incus/LXD and systemd | System-container and manager integration tests |
| curl, tar, gzip and xz | Fetch and unpack published kernels and package metadata |
| Nightly Rust `2026-10-28`, LLVM tools and `cargo-llvm-cov` 0.9.1 | Branch-instrumented verification |
| `serde_json` in the isolated coverage tool | Read LLVM exports; no daemon dependency |
| mdBook 0.5.4 | Build this book and deploy it through GitHub Pages Actions |
| CodeQL and Qlty | Security and maintainability analysis |

The review-image builder resolves packages from signed Alpine indexes and
installs them in a networkless Docker build. The optional matrix extracts
Debian and Rocky kernel packages without installing them on the host.
The archived v0.1.5 peer is built separately for interoperability tests.


## Checked libc exceptions


Required APIs are supplied by the locked `l2tp` and `iphost` releases.
Report defects against their own contracts; daemon policy belongs here.
Required missing upstream functionality must be fixed upstream before
dependent work proceeds.

The binary uses checked direct libc signal calls because `nix` 0.30.1
mishandles some pthread error/output conventions. Its test-only ptrace
fixture also checks the output-buffer size and errno directly. GNU and
musl fault cases guard these exceptions. Details and source references
remain in [signed history](https://github.com/menhera-org/rs-l2tpd/blob/f5a2e7b/docs/dependencies.md#checked-libc-exceptions);
the [developer checks](developer.md) keep them covered.

## Kernel evidence

This map is for developers checking the kernel boundary. Live, shared,
delegated and source-only evidence have different scope. The source-link
gate reads the last column; keep each classification explicit.

| Fact | Evidence kind and location | Source-link scope |
|---|---|---|
| K1 | requirement + live: `LinuxKernel::new` resolves the family in every fixture; `conformance_on_the_linux_kernel` | linux |
| K2 | live: `sockets_bind_connect_and_report_their_source`, both native V4 and V6 sockets | linux |
| K3 | shared: all session creation cases explicitly request Ethernet with no sublayer | linux |
| K4 | requirement + live positive: V6 socket creation; refusal policy is tested with both errnos in `socket_family_fallback_never_recreates_existing_tunnels`; the scoped mainline H4/T4 boots exercise ipv6.disable=1 and CONFIG_IPV6=n (see kernel-support.md) | linux |
| K5 | shared: `disconnected_sessions_count_frame_drops`; live: `disconnected_sessions_drop_outbound_but_receive_only_matching_cookies` transmits and observes counters | linux |
| K6 | shared: `connect_selects_the_source_of_the_device`, disconnect/reconnect across families | linux |
| K7 | shared: `the_monitor_reports_links_and_addresses`, `inventories_select_only_the_requested_dependency`; live: ordered lifetime requests, filtered inventories, IPv6-state and lost-reply/reopen tests | linux |
| K8 | requirement: kernel command capability checks cited by `LinuxKernel::new` and the L2TP adapter; privileged positive operation runs | linux |
| K9 | live: `links_are_found_by_name_and_dumped`; shared VRF/zone/source cases | linux |
| K10 | unit: BPF instruction cases; live: production filtered monitor observes link and address changes; R6's child-only SO_ATTACH_FILTER refusal proves unfiltered address recovery and real frames on Ubuntu 6.8.0-147 | linux |
| K11 | live: `a_tunable_write_changes_only_fresh_sockets` | linux |
| K12 | removed; no evidence obligation | removed |
| K13 | delegated requirement: released iphost DHCPv6 socket implementation; live positive port-546 bind in `released_unified_adapter_enables_per_family_failure_fallback`; capability scenario proves EACCES at unprivileged-port start 1024 and an actual port-546 exchange without CAP_NET_BIND_SERVICE at start 0 | delegated |
| K14 | delegated implementation plus live daemon fallback: H15's `without_net_raw_router_discovery_requires_accept_ra_and_binding_still_reconnects` removes CAP_NET_RAW, proves accept_ra gating and actual DNS/frames; upstream `parses_netlink_useropt` and raw/netlink equivalence regressions remain separate source evidence | delegated |
| K15 | live: `disconnected_sessions_drop_outbound_but_receive_only_matching_cookies`, foreign source and correct/wrong/absent cookies | linux |
| K16 | shared: stored-name and rename cases; live review: duplicate stored creation names; policy: ambiguity refuses deletion | linux |
| K17 | shared: closing the socket deletes tunnel and sessions; live real-manager reference test and handover test | linux |
| K18 | shared: identifier reuse after deletion; live review: 32 delete/recreate cycles; policy: reuse waits for confirmed absence; source comparison establishes the release boundary | linux |
| K19 | shared: tunnel and namespace-wide session uniqueness, wrong-tunnel lookup and deletion refusal; verified on both sides of the newer lookup behavior | linux |
| K20 | shared: a taken name leaves no session; live production unit: a foreign registration between capture arming and session creation makes the capture uncertain instead of proving the foreign index | linux |
| K21 | source/requirement: autoload call sites in the kernel specification; fixtures exercise normal family/link creation, without claiming that already-loaded modules prove autoload policy | linux |
| K22 | shared: bound/unbound binding semantics; fake runs without NET_RAW, live runs with it; reconnect policy is tested without that capability in the fake | linux |
| K23 | live: tunable write, old socket stays v6-only, fresh socket reads dual-stack; fake policy covers both fallbacks and failed read-back | linux |
| K24 | shared: stale source/bare connect refusal and disconnect/reselection | linux |
| K25 | live: `the_kernel_keeps_the_previous_ipv6_peer_after_disconnect` | linux |
| K26 | shared: empty IPv6 VRF refusal (EADDRNOTAVAIL, or ENETUNREACH on vanilla 6.8.12), link-local/binding refusal; fake policy explicitly covers every transient connect errno; route-type errno table remains source evidence | linux |
| K27 | shared: zone must equal the bound link or belong to its VRF; policy tests replacement, rename and membership dependencies | linux |
| K28 | shared: ordinary bound link without a route, VRF source selection | linux |
| K29 | live production unit tests: actual lifetime overflow, missing mutation reply with applied mutation and socket reopening; unit framing/absolute deadline tests | linux |
| K30 | live: a second netlink port sends a forged removal; ordered production lookup preserves the registration | linux |
| K31 | shared: hardware-address EBUSY while up, unchanged address succeeds, rename while up | linux |
| K32 | requirement + unit: configuration name validation; shared explicit-name and name-collision operations | linux |
| K33 | source: IPv6 down transition; the Kernel boundary has no operation to lower a device, and policy tests preserve administrative state and child records | source-only |
| K34 | shared/live: unspecified IPv4 source and missing IPv6 source; policy treats an unspecified returned source as a failed connect | linux |
| K35 | live production unit: every cookie length 0 through 8 is read; invalid configuration lengths stay rejected and Debug hides bytes | linux |
| K36 | source/requirement: initial-user-namespace capability check; live production unit: `subscription_buffer_matches_force_or_capped_fallback` compares the production buffer with FORCE or ordinary-buffer behavior; the unprivileged Incus runner requires the EPERM fallback branch to run; the current GNU QEMU coverage guest checks constrained ordinary buffers and the full doubled 8 MiB FORCE request, retaining the reduced-buffer failure control; finite-buffer overflow is exercised separately | linux |
| K37 | live: descriptor duplicate/adoption and real systemd manager holds the only reference until acknowledged withdrawal | linux |
| K38 | delegated source/requirement: released iphost shared DHCPv6 listener and the kernel socket-selection sources; downstream live adapter binds 546 and exchanges a Reply | delegated |
| K39 | requirement + live: raw RA socket under NET_RAW; fake binding conformance also runs without NET_RAW | linux |
| K40 | live raw-source adapter explicitly receives RDNSS with `accept_ra=0`; netlink gating is source/requirement evidence | delegated |
| K41 | shared: commanded deletions announced; live: socket close not announced; review probe tests colliding foreign-namespace IDs on pre-7.3 and 7.3 kernels | linux |
| K42 | live: namespace move and explicit index/name reuse within one lifetime generation; old proof remains Removed and new registration has a distinct incarnation | linux |
| K43 | source + live H20: session MTUs 1500/9000 over a 1500-byte underlay, IPv4/IPv6, ordinary/VRF binding; full-size bidirectional frames, sender fragments and receiving session counters; no daemon path depends on this implementation detail (T5) | source-only |
| K44 | source + live T5 option setting on every tunnel socket (`kernel::linux` socket creation cites it); a live case reads the options back with `getsockopt` on both families; the H20 scenario proves the IPv4 contract and, together with K43, the IPv6 behaviour | linux |

The source-link gate reads the scope column. Every active fact needs an
explicit scope: linux requires a production function citation; delegated
and source-only require a test declaration citation and the evidence above.
These classifications do not claim that a source assertion ran on a kernel.
The classifications preserve the maintainer-approved distinction between source and execution evidence.

K13, K14, K33, K38 and K40 are not facts used by production functions in
`kernel::linux`: the resolver operations are delegated to iphost and device
lowering is absent. Their classified test evidence satisfies the source-link
gate without manufacturing production citations or equating source assertions
with live execution.

## Build DEB and RPM packages

The isolated Rust crate in `musl-deb/` writes uncompressed DEB ar/ustar
packages and RPM v4 cpio packages. The pinned pure-Rust `rpm` dependency
handles RPM headers and digests; compression and signing backends are disabled.
Neither distribution's build tools are required. It reads the root crate version and invokes
`build-release.sh` with `--no-default-features --features bin` in separate
target directories. Docker builds run with networking disabled; Cargo fetches
the locked sources beforehand. The builder rejects wrong-architecture or
dynamically linked ELF input. It always builds the daemon rather than trusting
an existing installer-enabled artifact.

```sh
cargo run --locked --manifest-path musl-deb/Cargo.toml
cargo run --locked --manifest-path musl-deb/Cargo.toml -- --target x86_64-unknown-linux-musl
cargo run --locked --manifest-path musl-deb/Cargo.toml -- --list rs-l2tpd_0.2.0-1_amd64.deb
cargo run --locked --manifest-path musl-deb/Cargo.toml -- --list rs-l2tpd-0.2.0-1.x86_64.rpm
```

The default builds both formats for x86_64 (DEB amd64) and aarch64 (DEB arm64)
and requires `cross`. `--target` limits both outputs to one target. Packages have
root ownership, fixed modes and zero archive timestamps. Unit tests check
deterministic writers, malformed/truncated archives, ELF validation and
version-field injection. The Packages workflow builds both architectures
and uses real Debian 13 dpkg to exercise install, upgrade, remove and purge.
A recorded systemctl stub checks service actions and failure propagation.
The real Debian helpers are exercised with policy-rc.d denial and allowed
startup, plus administrator-disabled and masked units. Upgrade preserves
configuration and leaves the running daemon in place. The helper package
is a declared Debian dependency; the daemon needs no shared-library package.
This consumer test does not qualify Debian's real service manager.

The Rocky Linux 9 and 10 consumers use real RPM transactions and a systemctl
stub. They check presets, first-install startup, disabled/masked units, upgrades
without daemon interruption, stop/disable on erase, reinstall presets,
`.rpmnew`/`.rpmsave`, fragment retention and scriptlet failures. All notice
files remain installed with `--excludedocs`. The consumers do not qualify a
real Rocky service manager or SELinux policy. RPM has no purge phase; its
approved configuration and uninstall differences are described in
[installation](installation.md#rpm-packages).

Both formats package the same stripped daemon and notices. RPM version fields
replace SemVer prerelease hyphens with `~`; RPM files use
`rs-l2tpd-VERSION-1.ARCH.rpm`. `--list` validates RPM digests or the tool's
uncompressed DEB format, lists paths and never extracts or executes scripts.

The package layout is described in [installation](installation.md).

## Reproducible releases

Canonical release builds use `build-release.sh`. `release-config.sh` pins
Rust 1.99.1, cross revision `a9301e91f72bba3850460512685f6b16062015ff`
(version 0.2.5) and both Linux amd64 cross images by digest.
Install the pinned compiler and cross before building:

```sh
. ./release-config.sh
rustup toolchain install "$RELEASE_TOOLCHAIN" --profile minimal --target x86_64-unknown-linux-musl,aarch64-unknown-linux-musl
cargo "+$RELEASE_TOOLCHAIN" install cross --git https://github.com/cross-rs/cross --rev "$RELEASE_CROSS_REV" --locked
./build-release.sh
```

Both musl architectures remain stripped. The helper fixes source-date,
locale and timezone, disables incremental compilation, remaps the cross
mount paths, and omits the linker build ID. Current cross preserves host
mount paths. `tools/release-rustc.sh` applies their mappings at compiler
invocation, keeping varying checkout paths out of Cargo's flag hash. Cargo vendors the checksum-verified
locked sources into a fixed project path before compilation; registry-cache
names therefore cannot leak into binaries. Target directories stay separate.
The existing `FEATURES`, `TARGETS` and `CROSS_TARGET_DIR` settings still select
the requested build; custom flags and configured paths are build inputs.

The shared Rust tar writer sets ownership, modes and timestamps explicitly.
Gzip runs with `-n` inside the pinned build image, so host tar/gzip versions,
source mtimes and archive creation times cannot affect the release bytes.
DEB packages use the same fixed metadata in their uncompressed ar/ustar
members. RPM v4 uses fixed build/file timestamps, no build-host identity and
an uncompressed cpio payload. No unstripped binary is packaged.

All three formats carry `musl-deb/README.binary.md` as README.md; its guide URLs
point to the published book. `musl-deb/prepare-notices.sh` obtains the union
of both musl targets' all-feature normal/build dependency graphs from Cargo.
It copies license, copyright and notice texts from the checksum-verified
vendor tree and records exact crate-source URLs. A dependency without a
license text fails the build; fqdn 0.5.2 has an explicit MIT-text supplement
because its published manifest declares MIT but omits a license file.

The artifacts also carry the pinned compiler's complete copyright inventory,
compressed with timestamp-free gzip in the pinned image, and its license
texts. The additional [musl notice](https://github.com/menhera-org/rs-l2tpd/blob/main/musl-deb/licenses/MUSL-COPYRIGHT)
is the verbatim [musl 1.2.5 COPYRIGHT](https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT?h=v1.2.5),
SHA256 `f9bc4423732350eb0b3f7ed7e91d530298476f8fec0c6c427a1c04ade22655af`.
The notice bundle includes unused/build-time components to cover both feature
variants; it does not claim they are all linked.

```sh
musl-deb/test-reproducible.sh target/verification/reproducibility
```

Run from a clean committed tree. The check exports the same Git revision to
different paths, varies source mtimes and umasks, and builds each copy with
separate clean target directories. It compares both feature variants'
binaries and tarballs, plus DEBs and RPMs for both architectures, byte for byte. It also
extracts the tarballs and checks their executable bytes, and uses readelf to
reject debug sections and a symbol table. Embedded registry-cache paths also
fail the check. The Packages workflow requires
this check and retains the results. Reproduction requires the same source,
locked dependencies, pinned build tools and explicit build options.

## Release readiness

The [current review](https://github.com/menhera-org/rs-l2tpd/blob/main/audit/RELEASE_READINESS.md)
records package-policy, notice, installed-documentation, build-tool and
systemd-image qualification. These changes preserve the production source
qualified by the kernel and coverage gates. Independent clean-build
comparisons must pass for the refreshed release inputs before distribution.

The checked release candidate passes the declared Rust 1.89 minimum on GNU
and musl, the library feature combinations, and an all-feature musl build
from a clean source package. Reproduce those checks from a clean checkout:

```sh
cargo +1.89.0 check --locked --all-targets --all-features
cargo +1.89.0 check --locked --all-features --target x86_64-unknown-linux-musl
cargo +1.89.0 check --locked --lib --no-default-features
cargo +1.89.0 check --locked --lib --no-default-features --features serde
cargo package --locked --all-features --target x86_64-unknown-linux-musl
cargo audit
cargo audit --file tools/coverage/Cargo.lock
cargo audit --file musl-deb/Cargo.lock
```

Install the minimum compiler's musl target before its check. Use a fresh
official registry index for the dependency scan and inspect its output;
an index-lookup error can accompany exit 0 and does not complete the audit.

The three project lockfiles and the pinned cross revision's unchanged
upstream lockfile pass the dependency scan without ignored advisories.
To scan that exact tool revision from a fresh checkout:

```sh
. ./release-config.sh
git --no-pager clone --no-checkout https://github.com/cross-rs/cross target/cross-audit
git --no-pager -C target/cross-audit checkout --detach "$RELEASE_CROSS_REV"
cargo audit --file target/cross-audit/Cargo.lock
```

The older published cross lock's yanked dunce and advisory findings remain
in the [prior audit](https://github.com/menhera-org/rs-l2tpd/blob/1f261be0dbff7584a14cc39a3bfe91b38919fd4e/audit/phase6/release-candidate/dependency-audit/applicability.md).
