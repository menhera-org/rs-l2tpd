# Phase 5 — binary verification, 2026-10-29

The starting tree was clean at `48753db` on `main`, with Phase 4 and its
audit follow-up implemented. The binary modules were empty and main exited
2. This change implements the process layer around the existing blocking
service; it adds no dependency. The `bin` feature enables the existing
`nix/uio` feature for SCM_RIGHTS.

## Implementation and evidence

| Rules / phase item | Implementation and executed cases |
|---|---|
| P2, P27, O1 | Hand-written exclusive modes, native byte paths, logger initialized before loading files, no environment level override. `args::tests::modes_and_errors`, `startup_changes_directory_before_loading_and_logs_problems`, `check_cli_and_no_process_side_effects`. Diagnostics containing newlines remain one log line. |
| C1, C2, C3, C4, P3, O5, O8 | Main file then non-hidden ASCII-case-insensitive TOML drop-ins in filename byte order, including non-UTF-8 filenames. Documents merge before conversion. Absence, followed symlinks, dangling links, loops, wrong types, parse failures, unreadable files, unlistable directories and uninspectable paths are explicit cases in `files`; reload refuses file errors and accepts removals. Check rendering asserts table order, omitted defaults, tolerated corrections and cookie output. Parser diagnostics omit source excerpts. |
| P1, P4, P6, P7, P8, P9, P22 | Real disconnected tunnels and sessions become ready with no network. Parent exits only after readiness, and foreground makes no PID file. `foreground_reload_and_clean_shutdown_without_network`, `daemon_readiness_pid_inode_and_reexec`, `pid_publication_failure_does_not_revoke_kernel_readiness`. The overlapping-instance case spends the bounded conflict budget and becomes ready without touching the first instance. Detailed degradation and virtual-time handshake clauses also use the earlier rule/service suites. |
| P5, P9, O7 | Seccomp denies AF_NETLINK in the actual binary. Kernel-open failures withhold readiness; TERM terminates both foreground startup and the waiting double-fork parent with exit 1: `failed_kernel_open_withholds_readiness_and_parent_shutdown_returns_one`. Startup preserves unconsumed adoption descriptors while retrying. |
| P10, P11 | Descriptor-relative directory traversal/publication, owner checks, explicit fresh-inode mode, safe pre-created-file fallback, inode-conditional removal and no permission changes to existing directories. Unit cases cover replacement, symlink refusal, trusted directory symlinks, modes and an open reader of the old inode. The root-only permission fixture drops uid and tests allowed fallback, group-write refusal, hard links and foreign ownership. PID publication failure leaves readiness valid. |
| P12, P13 | sigwait collector, coalesced pending requests, independent persistent shutdown and a capacity-retrying forwarder. The fake-runtime queue is filled to 1,024 and shutdown remains observable ahead of it. Startup reload/restart requests are ignored; shutdown wins. Live HUP reload and refused file reload preserve session identity. Earlier service tests cover callback blocking, supersession and panic cleanup/exit errors. |
| P14, P18, P19, L13 | Native Unix datagrams and SCM_RIGHTS, exact inherited names, announced capacity, close-on-exec on adoption and closure of unannounced descriptors. `rights_and_ordered_processing_barrier` and the tiny manager verify message order and descriptor ownership. Live cases cover crash survival, adoption through both forks, exact rejection withdrawal before replacement, crash cleanup without storage, malformed/closed announcements and bounded failed cleanup. A manager deliberately retaining its reference causes exit 1; closing that final reference then removes the tunnel. Earlier fake cases cover uncertain verification, duplicate groups and request incarnations. |
| P15, P26, E26 | Original resolved executable pathname and argv survive exec. Probe output must exactly match version 1. Exec uses a short-lived thread with a private CLONE_FILES table so descriptor shuffling cannot clobber the running service. A successful probe followed by ENOENT leaves the shared table and flags intact. Live cases replace the binary inode on disk, preserve PID/PID-file inode/interface index, re-exec with zero tunnels, and reject an incompatible replacement while continuing reload/shutdown. Invalid marker/state exits before a fork. P15 continuity/configuration behavior is exercised; its comparative timing promise remains a Phase 6 measurement. |
| P16, P17, P20, O7 | Live orderly shutdown verifies kernel absence. Overlapping instances do not delete foreign objects. Failed manager cleanup exits nonzero within the bounded windows. The library's earlier cleanup tests retain session-identity and per-tunnel deletion-window coverage. |
| P21, P23, R49 | Template parsed for every required key and both installation binary paths. A real user systemd manager runs the native transport with the template AF_UNIX/AF_NETLINK/AF_INET/AF_INET6 filter and confirms stored count 1 then 0 after barriers. capget uses no procfs; a uid-dropped actual binary reports each absent capability and runs an empty configuration. A procfs-free process run uses `fix_bindv6only=false`. |
| P24 | Ordinary binary/process cases and all live process cases run with both static musl and glibc userspace. |
| P25 | Namespace-local `bindv6only=1`: opt-out leaves it alone; opt-in logs the previous value, completes the runtime handshake and writes 0 before affected creation/readiness. The earlier fake cases cover timeout, late acknowledgement, coalescing and read-back failure. |
| Optional installer, P27 | Atomic binary replacement, idempotence, preserved configuration and edited/unknown units, and upgrade of the exact embedded legacy installer text. Unit paths render for /usr/local/sbin and /usr/sbin. Prefix integration executes this binary's mode. A recording systemctl fixture in a disposable root container checks the exact two-run sequence: is-enabled, daemon-reload, enable --now; then is-enabled, daemon-reload. Options precede command names. Existing services are never restarted. |

The supplied unit selects `/run/rs-l2tpd/rs-l2tpd.pid` with an explicit
option so only its dedicated runtime directory must be writable under
ProtectSystem=strict. Standalone defaults are unchanged. The interface and
packaging pages give the matching command-line restart option.

The legacy text is the exact generated installer unit from baseline
`741117b`. It is recognized only at the documented new installer
destination; the installer does not migrate or delete the historical
/usr/local/bin or /usr/local/lib paths.

## Executions

- [All musl suites](phase5/tests-musl.log): 64 ordinary library cases,
  18 binary unit cases, 6 ordinary process cases, 23 service cases,
  63 rules/property cases, 15 shared fake operation bodies, five tool
  tests and six doc cases pass. Ignored cases are listed separately.
- [Glibc binary suites](phase5/tests-glibc.log): the same 18 binary and
  six ordinary process cases pass.
- [Musl live run](phase5/linux-musl.log) and
  [glibc live run](phase5/linux-glibc.log): 15 actual-binary cases and
  both uid-dropping permission fixtures pass on **6.8.0-147-generic**.
  Glibc userspace reports **2.43**. These containers share the host kernel.
- [Real manager](phase5/systemd.log), [unit verification](phase5/unit-verify.log)
  and [procfs-free run](phase5/no-proc.log) pass.
- [Installer command sequence](phase5/installer-systemctl.log) passes
  inside a disposable container using a recording systemctl fixture.
- [Warning/feature/MSRV gates](phase5/gates.log): all-feature and default
  Clippy, no-default library and serde-only musl builds, warning-denied
  rustdoc, Rust 1.89 all-feature check and formatting pass.
  [Final parent-handler gates](phase5/parent-final-gates.log) repeat
  all-feature Clippy, MSRV and formatting after making parent signal
  forwarding immediate through readiness acknowledgement.
- [Traceability](phase5/traceability.log) remains lenient as specified until
  Phase 6. A citation is not a coverage or execution claim.
- [Ten seeded ordinary repetitions](phase5/repeats-fake.log) include the
  library, binary, process, service, rules and fake conformance targets.
  [Ten live musl repetitions](phase5/repeats-live.log) exercise all 15
  kernel/process cases plus the installer command fixture, including
  the real conflict and cleanup windows.
  The final parent signal guard additionally passes
  [ten targeted repetitions](phase5/repeats-parent.log); both complete
  libc live suites were rerun after it.

Reproduction commands are in [tests/process](../tests/process/README.md).
The binary's real-manager test checks the actual address-family restriction,
not a full root system-manager boot. In particular it does not execute
ProtectKernelTunables=yes with ReadWritePaths=-/proc/sys/net/ipv6/bindv6only;
the sandboxed unit's P21/P25 tunable access remains unverified. The namespace
write case proves the handshake outside that system-unit mount sandbox.
Installer systemctl operations are
recorded in a disposable container and prefix file operations tested; no
installer was run against the host's system service installation.

## Remaining gates

Phase 6 still owns the complete required QEMU kernel matrix, Incus/LXD,
whole-daemon scenario/resource/timing promises (including comparative P15),
100% combined line/branch coverage and strict global rule/source gates.
No such gate is marked complete by these host-kernel runs. The Phase 5
process implementation is complete within that scope. Release packaging
and publication remain Phase 7; nothing was installed on the host.

The rewrite's binary size target is still unmet: 1,875 physical source
lines before inline test modules, including the optional installer,
against the plan's target of fewer than 1,500. This remains rewrite sizing
work alongside the global proof gates.
