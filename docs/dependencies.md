# Dependencies

[Documentation index](README.md)

The crates and tools used by the current implementation. A dependency stays
when the code it replaces justifies its maintenance and supply-chain cost.
Cargo.lock resolves 65 external packages for the daemon's all-feature graph;
the isolated coverage tools have their own lockfile.

## Library

| Crate | For | Spec |
|---|---|---|
| `l2tp` 0.5 | Tunnel sockets, shared checked types and `KernelMessage` decoding; production requests/events use the daemon's raw adapter | T6, T21, K16, K41, L13 |
| `iphost` 0.4.4 | General-purpose system/configured DNS and discovery, incremental RDNSS updates, opt-in failure fallback, namespace-scoped listeners and bounded DHCPv6 client queues; daemon scheduling and retention stay here | V1–V15, G23 |
| `netlink-sys`, `netlink-packet-core`, `netlink-packet-route`, `netlink-packet-generic`, `netlink-packet-l2tp` | Bounded generic-netlink requests and events, the rtnetlink request socket, event monitor and lifetime subscription: raw sockets on `AsyncFd`, so that the kernel's buffer and `ENOBUFS` are seen (already dependencies of `l2tp`) | A5, A7, E20, E21, K29 |
| `socket2` | `SO_BINDTOIFINDEX`, `SO_ATTACH_FILTER`, `IPV6_V6ONLY` read-back, `SO_RCVBUF`, socket type and protocol queries for adopted descriptors | T10, K10, T26, R10, P14 |
| `libc` (via `nix::libc` in the library) | The one `setsockopt` no safe crate exposes: `IP_MTU_DISCOVER` on an `AF_INET6` tunnel socket, under L2's bounded exception; `l2tp`'s `set_pmtu_discovery` and `set_ipv6_dontfrag` cover the other T5 options | T5, K44, L2 |
| `nix` (`socket`, `process`, `signal`, `fs`, `poll`) | `SO_RCVBUFFORCE`, process/signal/filesystem wrappers; the `bin` feature adds `uio` for `sendmsg` with `SCM_RIGHTS` | R10, P14 |
| `tokio` (`rt`, `sync`, `time`, `net`) | The loop, the bounded channel, timers, `AsyncFd` | A6, M14 |
| `log` | The facade | O1 |
| `getrandom` | Temporary interface names from the kernel's random source, without file I/O or unsafe code | S4, L1, L2 |
| `serde` (optional) | The `serde` feature | L1 |

`netlink-packet-route` is pinned to the release that depends on
`netlink-packet-core` 0.9, the version `l2tp` uses (0.33 in Cargo.toml), so that one copy of the core crate is built.

## Binary (`bin` feature)

| Crate | For | Spec |
|---|---|---|
| `toml` | Parsing the documents | C1 |
| `serde` | With it | C5 |
| `libc` | Checked signal-mask and signal-wait calls under the documented `nix` exception; capability, fork, descriptor-relative PID-file and exec handover operations; `unshare(CLONE_FILES)` isolates exec descriptor remapping from live threads. The library's sole exception is L2's socket-option call | R49, P4, P10, P12, P16, P26, L2 |

The `setup-systemd` feature ([packaging](packaging.md)) adds no crate:
the unit is embedded with `include_str!`, the copy is `std`, and
`systemctl` is run as a child process.

Nothing else: the command line (P27) is parsed by hand,
the logger is a small adapter over `log::Log` (O1), and the process/store code
uses `std`, `nix` and the documented direct `libc` calls.

## CI analysis

| Tool | For |
|---|---|
| `github/codeql-action` v4, pinned by commit in the workflow (`.github/workflows/codeql.yml`) | Rust and Actions security analysis; the configuration (`.github/codeql-config.yml`) retains the extended suite and excludes `rust/cleartext-logging`, which mistakes public tunnel/session identifiers for credentials |
| `actions/upload-artifact` v4, pinned by commit in CI (`.github/workflows/ci.yml`) | Retains live-suite, coverage and source-work records for 14 days, including failed runs |

## Upstream needs

Required `l2tp` and `iphost` APIs are available in the locked registry
releases. A new missing capability stops its dependent implementation until
it ships upstream (`CONTRIBUTING.md`, step 5). Fix library defects against
their own contracts; keep daemon policy and scheduling here.

| Boundary | Current contract |
|---|---|
| Tunnel sockets (`l2tp` 0.5.0) | Bound unconnected sockets, disconnect, descriptor adoption/duplication and typed local/peer tunnel identifiers; no Debug parsing or daemon-owned L2TP sockaddr construction |
| Handle ownership | Production owns `TunnelSocket` directly. Fixture handles immediately disable automatic deletion; drop-by-identifier is unsafe for T8. Closing the owned socket and confirming absence implements tunnel removal |
| Bounded requests/events | The daemon's raw adapter uses five-second total deadlines, sender validation, finite buffers and persistent loss state. Upstream's runtime-free/bounded event APIs remain alternatives; its handle timeouts do not supply the required uncertain-mutation recovery |
| Foreign cookies (`l2tp` 0.5.0) | `KernelMessage` accepts reported lengths 0–8 through `KernelCookie`; configuration still accepts only its documented lengths, and Debug redacts bytes |
| Namespace identity | `l2tp` uses namespace cookies without procfs on the required kernels. The daemon creates sockets on its owning threads and never calls `setns`. Older iphost namespace fallback may use `/proc/thread-self/ns/net` |
| Resolver protocols (`iphost` 0.4.4) | Incremental bounded RDNSS, explicit per-family failure fallback, namespace-scoped shared DHCPv6 listeners, receiver cleanup, finite queues and anonymous Reply validation; see [resolver integration](upstream-iphost.md) |
| Resolver policy | The daemon validates non-VRF bind devices, selects/retains answers and owns the separate eight-system/eight-configured lookup budgets. Libc execution remains unbounded; obsolete calls retain permits until return |
| Zoned literals | The daemon parses the zone and gives iphost the bare address |

### Checked libc exceptions

Broken `nix` wrappers may use narrowly scoped direct calls under the
maintainer's exception. Document return conventions, check errors before
reading outputs, and test success/failure on GNU and musl. No upstream `nix`
contribution or release is a prerequisite.

`nix` 0.30.1's signal wrappers mishandle positive pthread errors and can
read failed wait/get-mask outputs before initialization. The binary uses
checked `libc::pthread_sigmask` and `libc::sigwait`, handling positive error
numbers and musl's -1/errno convention before reading initialized outputs.
Safe signal-set construction and unrelated wrappers remain in `nix`.
The test-only syscall barrier follows the same checked mask convention.
[PR #2852](https://github.com/nix-rust/nix/pull/2852) and the independent
overflow-fixture [PR #2853](https://github.com/nix-rust/nix/pull/2853) preserve
the upstream proposals; this documentation makes no claim about their merge
status.

The test-only `PTRACE_GET_SYSCALL_INFO` fixture also avoids `nix`'s
`syscall_info` wrapper. Its `ptrace_get_data` passes a null address where
the request requires the output-buffer size; the kernel returns the required
size but copies no bytes, after which the wrapper assumes initialization.
That API is also GNU-only. The fixture passes the size of a zero-initialized
UAPI structure, checks errno before reading output and requires a complete
entry payload. GNU/musl tests cover valid and zero-size queries, sentinel
preservation, all-ones PEEKDATA success, invalid pointers/requests, bounded
pathname reads and callback-failure cleanup. Sources are `nix`'s
`src/sys/ptrace/linux.rs:501–512,573–576` and Linux's
`kernel/ptrace.c:ptrace_get_syscall_info`.

These signal/fixture exceptions do not expand L2's library unsafe-code
boundary: its sole call remains the cited socket option above.

## Build

Rust 1.89; `cargo build --release --locked --target x86_64-unknown-linux-musl`
for a static binary; `build-release.sh` builds the musl targets with
`cross` and enables `setup-systemd` by default. Ordinary Cargo builds
default to `bin`, without the optional installer. Publishing uses
`--registry crates-io`.

## Verification tools

| Tool | For |
|---|---|
| mdBook 0.5.4 | Builds these Markdown chapters for GitHub Pages; the Pages workflow verifies the official musl release archive's SHA-256; no daemon dependency |
| `cargo-llvm-cov` 0.9.1 | Phase 6 combined line/branch coverage; no daemon dependency |
| `serde_json` 1.0.154, isolated in `tools/coverage` | Decode LLVM exports for the merged-source gate without a handwritten JSON parser; no daemon dependency or change to its lockfile |
| Rust `nightly-2026-10-28`, `llvm-tools-preview` | Branch instrumentation for coverage only; shipped builds remain on stable |
| Archived `rs-l2tpd` v0.1.5 and its own lockfile | G11/G22 peer interoperability only; isolated build cache, no dependency added to the current daemon |
| QEMU TCG, cpio, binutils | Disposable kernel guests, initramfs creation and stripping only; not linked into the daemon |
| curl, gzip, xz, tar | Published kernel/package metadata and source archives for the matrix |
| Rocky Linux 9 `rpm2cpio` in Docker | Extract checksum-verified Rocky 9/10 kernel RPMs for the optional matrix; each run retains the extractor image identity |
| Docker; Debian kernel build toolchain (build-essential, flex, bison, bc, libelf/libssl headers); kmod/libkmod2 | Kernel builds and package extraction in networkless containers, module loading inside guests; recipes and package digests recorded with runs |
| Alpine apk-tools and signed v3.22 indexes | Resolve and verify the amd64 review image's existing package set; downloads use host curl, Docker resolution and installation use `--network none` |
| Incus/LXD, systemd, iproute2, BusyBox, util-linux | Disposable system-container and host-condition fixtures; no daemon dependency |
| GNU libc and libgcc from Ubuntu 24.04 | GNU coverage executables in the review image; shipped binaries remain musl |
| dnsmasq and radvd from signed Alpine indexes | Existing upstream `iphost` DNS, VRF, RA and DHCPv6 live fixtures in a disposable networkless container; no daemon dependency |

The process-test fixture enables `nix`'s test-only `resource` feature for
`getrlimit` and `setrlimit`. It restores its owned daemon child's descriptor
limit with checked `libc::prlimit`, which `nix` 0.30.1 does not expose;
it requests no output and checks the syscall result before continuing.
This adds no production feature or dependency.
