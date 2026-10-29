# Phase 5 conformance review, 2026-10-29

Review of commit `e213962` ("feat: implement phase 5 binary and process
integration") against `docs/spec` (process P1–P27, observability O1/O7/O8,
configuration C1–C4, requirements R49, library L13, events E26), the phase 5
section of `docs/plan.md`, the verification record
`audit/PHASE5_VERIFICATION_2026-10-29.md`, and the standing project rules
(docs stand alone, no `/proc` outside the bindv6only write, byte-string
paths, no new dependency).

Verdict: the commit conforms in substance. Every rule traced is implemented
and guarded by a `/// spec:` tagged test. On the committed tree, Clippy with
all features and `-D warnings`, rustfmt, the 18 binary unit tests and the
ordinary process tests pass. The live container, QEMU and real-systemd
suites were not rerun; their committed logs under `audit/phase5/` were
taken as evidence.

Each item below is a fix list entry. Tick it when the fix lands, and cite
the item number in the commit message.

## A. Must fix

- [ ] **A1. `build-release.sh` names a feature that no longer exists.**
  `build-release.sh:14` defaults to `FEATURES=setup`; the commit renamed the
  feature to `setup-systemd` (`Cargo.toml` `[features]`), so
  `cargo build --features setup` fails with "does not contain this feature".
  Fix: default to `setup-systemd` and update the comment above it.

- [ ] **A2. Links from `docs/` to non-Pages repo files (docs rule).**
  `docs/` is the GitHub Pages source and must stand alone; it names
  non-Pages files in prose instead of linking them. Added by this commit:
  - `docs/README.md:28` → `../audit/PHASE5_VERIFICATION_2026-10-29.md`
  - `docs/plan.md:410` → `../audit/PHASE5_VERIFICATION_2026-10-29.md`
  - `docs/plan.md:416` → `../tests/process/README.md`
  - `docs/testing.md:34` → `../audit/PHASE5_VERIFICATION_2026-10-29.md`
  - `docs/testing.md:35` → `../tests/process/README.md`
  - `docs/spec/README.md:89` → `../../audit/PHASE5_VERIFICATION_2026-10-29.md`

  Pre-existing from earlier phases, fix in the same pass:
  - `docs/plan.md:212`, `:226` → `../audit/PHASE23_VERIFICATION_2026-10-29.md`
  - `docs/plan.md:330` → `../audit/PHASE4_VERIFICATION_2026-10-29.md`
  - `docs/plan.md:337` → `../audit/PHASE4_REMEDIATION_2026-10-29.md`
  - `docs/testing.md:179`, `:181` → PHASE23 / PHASE4 records
  - `docs/kernel-evidence.md:3` → `../audit/PHASE23_VERIFICATION_2026-10-29.md`
  - `docs/upstream-iphost.md:8` → `../audit/PHASE23_VERIFICATION_2026-10-29.md`

  Links within `docs/` (`../README.md`, `../plan.md`, `../testing.md`,
  `../upstream-iphost.md`) and the external systemd link in
  `docs/spec/process.md:181` are fine.

- [ ] **A3. Installer reads `/proc/self/exe` (P23).**
  `src/bin/rs-l2tpd/setup.rs:100` calls `std::env::current_exe()`, which on
  Linux is a readlink of `/proc/self/exe`. P23 allows `/proc` only for the
  P25 bindv6only write. `main.rs:73` already resolves the running binary's
  path procfs-free via `restart::executable_at`; pass that path into the
  installer instead.

## B. Spec deviations, small

- [ ] **B1. P12: a parent gone before readiness kills the grandchild.**
  `src/bin/rs-l2tpd/daemon.rs:47` writes the grandchild's PID to the
  readiness pipe with `?`; only `ready()` (`daemon.rs:113`) logs `EPIPE`.
  The spec says a vanished parent is an `EPIPE` the daemon logs, not a
  death. Treat `EPIPE` on the first write the same way as in `ready()`.

- [ ] **B2. P26: signal window in the new image after exec.**
  `src/bin/rs-l2tpd/restart.rs:230-232` says the blocked mask is kept
  across exec until the new image's sigwait thread starts. Rust's
  `Command::exec` resets the signal mask to empty and `SIGPIPE` to
  `SIG_DFL` before `execve`, so the new image runs logger init,
  `files::load` and `daemon::start` (`main.rs:34-83`) with default
  dispositions until `signals::prepare()` (`signals.rs:170`). A `SIGHUP`,
  `SIGTERM` or `SIGUSR2` in that window kills the new image and the init
  system restarts it. Either block the four signals (and ignore `SIGPIPE`)
  first thing in `main` when the re-exec marker is present, or re-block
  them via a pre-exec hook; fix the comment either way.

- [ ] **B3. P10/P11: PID-file edge cases.** `src/bin/rs-l2tpd/pidfile.rs`:
  - `:99-104`: the "other users could replace the file" warning tests
    `mode & 0o022` only; a sticky (`1777`) directory warns although others
    cannot replace the file. Skip the warning when the sticky bit is set.
  - `:229-233`: `remove()` re-walks `directory()`, so it repeats the
    warning and re-runs the root-or-daemon-user ownership check; a failure
    there becomes `Err` and exit 1, where P11 says only the inode decides
    and anything else is left alone with a warning. Open the directory
    without the checks at removal.
  - `:152`: in-place update is attempted only on `EACCES` or `EROFS`;
    `EPERM` (immutable directory, LSM denial) is a hard failure. P10 says
    "a directory it cannot write to"; add `EPERM`.

- [ ] **B4. O8: check mode wording differs from start-up.**
  `src/bin/rs-l2tpd/check.rs:7-9` logs an unreadable file as `{error}`,
  start-up (`main.rs:77-79`) as `{error}; file left out`. O8 wants the same
  words. Share one formatting site.

- [ ] **B5. P27: usage text advertises `--setup-systemd` unconditionally.**
  `src/bin/rs-l2tpd/args.rs:5` has one `USAGE` constant; a binary without
  the `setup-systemd` feature prints an option it then rejects as unknown.
  Gate that line on the feature.

- [ ] **B6. P12/P22: `SIGUSR1` is consumed.** `src/bin/rs-l2tpd/signals.rs:64`,
  `:135`, `:190` add `SIGUSR1` to the blocked and waited set as the
  collector's private wake-up and drop it at `:46`. An external `SIGUSR1`
  therefore has no effect instead of its default action. Either use a
  real-time signal (`SIGRTMIN+n`) or a pipe/eventfd for the wake-up, or
  document `SIGUSR1` as reserved in P22 and `docs/interface.md`.

- [ ] **B7. P27/C1: option values starting with `--` are refused.**
  `src/bin/rs-l2tpd/args.rs:43` treats a value that is empty or begins with
  `--` as a missing argument, so a path literally named `--x` cannot be
  given to `--config`, `--config-dir` or `--pid-file`. Low priority; accept
  any non-empty value, or document the restriction.

- [ ] **B8. P25: repeated warning on failed tunable write.**
  `src/bin/rs-l2tpd/tunable.rs:10` logs `warn!` on every failed attempt;
  P25 says the failure "is reported once". Confirm the service's episode
  reporting already covers it and drop the binary's line, or make it once.

## C. Verification record: claims stronger than the evidence

Fix by adding the missing case, or by narrowing the wording in
`audit/PHASE5_VERIFICATION_2026-10-29.md`.

- [ ] **C1. P12 "capacity-retrying forwarder" is untested.** The only test
  (`signals.rs:208`) drives `Shared::observe` directly; the forwarder thread
  and its retry-on-full path (`signals.rs:111-124`) never execute. Add a
  test that fills the queue and observes the forwarder delivering after
  capacity returns.

- [ ] **C2. P4/P6 "parent exits only after readiness" is not observable.**
  `tests/process.rs:260-261` waits for the "ready" log and then `wait()`s
  the parent, which cannot detect an early parent exit. Poll the parent
  with `try_wait()` while readiness is still withheld (for example before
  the conflict budget of the overlapping-instance case is spent).

- [ ] **C3. P26 "invalid marker/state exits before a fork" is not
  observable.** `tests/process.rs:308-320` passes `--foreground`, so a
  fork could not be seen. Run the case without `--foreground` and assert
  the process exits non-zero with no child and no PID file.

- [ ] **C4. P10 "foreign ownership" refusal comes from `open`, not the
  owner check.** In `precreated_permissions_links_and_owner`
  (`pidfile.rs:335`) the root-owned `0600` file is unopenable by uid 65534,
  so `openat` fails with `EACCES` before the owner check at `pidfile.rs:166`
  runs. Make the foreign file `0666` so the owner check is what refuses.

- [ ] **C5. Wrong rule citation.** `pidfile.rs:332` cites `spec: P10 C3`;
  C3 is a configuration-file rule. Cite the PID-file rule only.

- [ ] **C6. Unit tunables untested.** The real-manager test checks the
  address-family filter but not that
  `ReadWritePaths=-/proc/sys/net/ipv6/bindv6only` is honoured under
  `ProtectKernelTunables=yes` (P21/P25). Add a case or state the gap.

## D. Observations, no action required

- `caps.rs:21` uses a raw `libc::syscall(SYS_capget, …)`; `libc::capget`
  is bound on both gnu and musl targets and would remove one `unsafe`
  surface. Optional.
- The binary is 1,832 lines before inline tests against the plan's target
  of under 1,500; the plan already records this as open.
- The verification record's test counts match the tree once the
  `setup-systemd` feature is enabled (22 process tests, 6 ordinary); the
  feature-gated pair at `tests/process.rs:569` and `:935` explains the
  difference seen without it.

## Method

Three independent reviewers each took a slice of the diff with the rule
list for it (front half: args/files/check/logger/main/caps/tunable; process
half: daemon/pidfile/signals; hand-over half: fdstore/restart/setup/unit/
docs), read the spec pages first, then the code and tests, and compared
each row of the verification record to the test it names. The gates run
locally were `cargo clippy --all-features --all-targets -- -D warnings`,
`cargo fmt --check`, and `cargo test --features bin,fake-kernel --bin
rs-l2tpd --test process`.
