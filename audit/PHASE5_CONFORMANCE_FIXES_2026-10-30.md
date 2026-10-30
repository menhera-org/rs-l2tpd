# Phase 5 conformance fixes, 2026-10-30

Follow-up to [the conformance review](PHASE5_CONFORMANCE_REVIEW_2026-10-29.md).
Each finding was checked against the implementation and specification before
changing it. Kernel-dependent behavior was checked against the sources below
and fresh executable tests. This record covers the audit follow-up;
it is not a claim that the global Phase 6 gates are complete.

## Dispositions

| Item | Confirmed behavior and resolution |
|---|---|
| A1 | Cargo defines setup-systemd, not setup. The release script now defaults to setup-systemd and describes the matching option. |
| A2 | All 14 identified links left the Pages source. They now name repository files in prose; navigation inside docs remains linked. |
| A3 | The installer used current_exe. It now receives executable_at's resolved argv0 path. Both installation and foreground operation pass with procfs hidden. |
| B1 | Both readiness-pipe writes now use the same EPIPE handling. A real pipe with its reader closed exercises the PID announcement and readiness byte; both log without aborting. Other I/O errors remain errors. |
| B2 | The claimed empty signal mask is incorrect for Rust 1.89 and the installed toolchain. Both inherit it. A real bug was confirmed instead: a failed Command::exec leaves SIGPIPE at SIG_DFL. A pre-exec hook restores SIG_IGN. The failed-exec regression fails before the hook and passes afterward; subprocess tests also verify mask inheritance and the new Rust image's SIGPIPE disposition. |
| B3 | Sticky directories no longer warn. Removal traverses without publication ownership checks and warns rather than failing when inspection is unavailable. EPERM joins EACCES/EROFS for the validated in-place fallback. Subprocess tests inject each creation errno with seccomp while actual inode open/write/removal still run; a root-container fixture changes directory ownership after publication. |
| B4 | Check and startup use files::report_errors. An actual-binary test compares the complete diagnostic lines. |
| B5 | Usage advertises setup-systemd and prefix only with that feature. Tests execute both feature selections. |
| B6 | SIGUSR1 is removed from the blocked/waited set. Collector teardown uses thread-directed SIGTERM after marking the collector stopped. A subprocess exercises thread joins; an actual daemon exits from external SIGUSR1 with its default signal status. No signal reservation or specification weakening was added. |
| B7 | Nonempty option values beginning with -- are accepted, including non-UTF-8 byte paths. Empty values remain errors. |
| B8 | The extra binary failure warning is removed. Reconciler::tunable_written already ends a matching handshake and reports failure once; stale/repeated acknowledgements do not report again. Existing handshake/fallback tests and the live binary tunable case pass. |
| C1 | The actual production forwarder runs on a thread with a full 1,024-request queue. A test-only counter confirms that the forwarder actually hit its full-queue retry branch before capacity is released; the test then processes queued reloads and observes the forwarded restart. |
| C2 | The overlapping-instance case now starts a daemon parent, polls try_wait while the conflict budget is unspent, then checks readiness and successful parent exit. The denied-netlink case also polls while readiness is withheld. |
| C3 | Invalid marker and orphan-state cases use daemon mode. A subprocess subreaper verifies nonzero exit, no PID file, and ECHILD rather than an orphaned descendant. |
| C4 | The foreign file is now 0666 so uid 65534 can open it. The fixture asserts the specific unsafe-pre-created-file validation error rather than accepting open's EACCES. |
| C5 | The PID permission fixture cites P10 only. |
| C6 | The original verification record and process instructions now explicitly state the untested ProtectKernelTunables/ReadWritePaths combination. This resolves the evidence overclaim using the review's permitted wording correction; the root system-unit mount-sandbox test remains open. |

## Source checks

The relevant upstream Linux v6.8 sources were fetched and read, and compared
with the existing v7.3 source tree used for the QEMU image:

- [fs/namei.c, v6.8](https://github.com/torvalds/linux/blob/v6.8/fs/namei.c#L2931):
  __check_sticky and may_delete establish the directory/file-owner protection.
  inode_permission (lines 504–519) returns EPERM for an immutable inode;
  directory publication and later file access are separate permission checks.
  The v7.3 counterparts are __check_sticky and may_delete_dentry.
- [fs/pipe.c, v6.8](https://github.com/torvalds/linux/blob/v6.8/fs/pipe.c#L467):
  pipe_write sends SIGPIPE and returns EPIPE with no readers. The v7.3
  counterpart is anon_pipe_write.
- [kernel/signal.c, v6.8](https://github.com/torvalds/linux/blob/v6.8/kernel/signal.c#L531):
  flush_signal_handlers preserves ignored dispositions; do_tkill and
  do_sigtimedwait implement thread-directed delivery and synchronous collection.
  The same functions were checked in v7.3, along with begin_new_exec in fs/exec.c.
- [Rust 1.89 Unix process implementation](https://github.com/rust-lang/rust/blob/1.89.0/library/std/src/sys/process/unix/unix.rs#L346):
  do_exec explicitly inherits the mask, resets SIGPIPE, then calls pre-exec
  hooks. The installed toolchain's corresponding source has the same order.
  Rust's Unix runtime resets SIGPIPE to ignore before main.

[Source hashes and tool versions](phase5-conformance/sources.log) identify the
inspected files. The EPERM test is controlled syscall failure injection,
not an assertion that a particular filesystem supports immutable flags.

## Fresh executions

- [Musl ordinary binary/process tests](phase5-conformance/tests-musl.log):
  27 binary cases and seven ordinary process cases pass.
- [Glibc ordinary binary/process tests](phase5-conformance/tests-glibc.log):
  the same cases pass.
- [Without the installer feature](phase5-conformance/no-setup.log):
  CLI usage and parser tests pass; six ordinary process cases pass.
- [Complete all-feature musl tests](phase5-conformance/all-tests.log):
  all ordinary library, binary, integration, property, traceability and
  documentation tests pass. Privileged tests are explicitly ignored there.
- [Musl live container](phase5-conformance/linux-musl.log) and
  [glibc live container](phase5-conformance/linux-glibc.log):
  17 privileged process cases and three file/ownership fixtures pass on
  Ubuntu kernel 6.8.0-147-generic. The glibc container reports 2.43.
  All changes to networking, installation paths and sysctls stay in the
  disposable containers.
- [Procfs hidden](phase5-conformance/no-proc.log): prefix installation and
  foreground reload/shutdown pass after a container-local tmpfs covers /proc.
- [Real user systemd manager](phase5-conformance/systemd.log): the native
  notification protocol and address-family restriction case passes.
- [QEMU 6.12.114](phase5-conformance/qemu612.log),
  [QEMU 6.18.59](phase5-conformance/qemu618.log), and
  [QEMU 7.3](phase5-conformance/qemu73.log): each runs 27 ordinary binary
  cases, the three privileged file/ownership fixtures, and all 24 process
  cases, with CONFORMANCE_RESULT=0. The first two images are Alpine stock
  kernels; 7.3 is the existing locally built mainline image. These are fresh
  runs, not the Phase 2–3 logs.
- [Rust 1.89 native exec regressions](phase5-conformance/msrv-exec.log):
  four cases pass. The 1.89 musl standard library is not installed, so this
  toolchain-specific execution uses the existing GNU target.
- [Expected failing regression before the SIGPIPE hook](phase5-conformance/failed-exec-before.log).
- [Every configured CI command, run locally](phase5-conformance/ci.log):
  formatting, warning-denied native Clippy, no-default/serde library builds,
  default daemon build, all-feature native tests, musl binary/process tests,
  rule/source checks in their configured lenient mode, and warning-denied docs.
- [Clippy](phase5-conformance/clippy.log) and
  [final build/format/source gates](phase5-conformance/gates.log) pass.

Reproduction starts with the commands in [tests/process](../tests/process/README.md).
For the QEMU runs, the existing kernel-test initramfs roots were copied to fresh
temporary directories. Only those copies received the static binary, binary
test executable and process test executable at its compiled-in binary path.
Guest init mounted devtmpfs/proc/sysfs/devpts, loaded the L2TP modules when
not built in, and ran the above suites. Debug sections were stripped only
from the copied guest executables. Guest exit required CONFORMANCE_RESULT=0;
a zero QEMU exit alone was not treated as success.

## Remaining limits

No complete required Ubuntu/vanilla release-kernel matrix, Incus/LXD run,
100% combined line/branch coverage, comparative restart timing or complete
system-unit mount/capability sandbox is claimed. In particular C6's root
mount-sandbox test is still missing. The optional D observations were left
unchanged. No dependency was added, and nothing was installed on the host.
