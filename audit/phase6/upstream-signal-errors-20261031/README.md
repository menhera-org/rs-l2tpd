# Upstream signal error handling blocks the signal-fault package

Pinned nix 0.30.1 reports `Ok(())` when a subprocess filter refuses
`rt_sigprocmask` with EIO. `pinned-repro.rs` checks the public API directly;
`pinned-baseline.log` records its safe assertion failure. A proposed daemon
case also misses the expected EIO and continues into kernel-open retry
(`daemon-baseline.log`). That process proposal remains unapplied.

The wrapper passes pthread-style positive error codes through
`Errno::result`, which only rejects -1. The same pattern precedes reads of
outputs in `SigSet::wait` and get/swap-mask wrappers. A failed libc call
need not initialize those outputs. The regression checks mask-set refusal
first, failing safely on the old implementation before invoking those reads.

The defect also exists in upstream revision
`89339c618783622e3cdd8d7a6b17319a65337e94` (master, package 0.31.3).
[Upstream PR #2852](https://github.com/nix-rust/nix/pull/2852) contains the fix,
regression and changelog. Its branch is signed and carries Signed-off-by;
the final changelog commit is `a0332041ac529b816596ee625b5d2b1638bf1cbd`.
`upstream.patch` is the full proposal against that upstream base.

## Compatibility and verification

The first fix handled only positive codes. It passed GNU but failed musl:
musl's `sigwait` returns -1 with errno. The final fix preserves both
conventions and checks success before reading an output. It also returns a
failed signal conversion as an error rather than panicking.

Primary implementations and contracts:

- [POSIX pthread_sigmask](https://pubs.opengroup.org/onlinepubs/9699919799/functions/pthread_sigmask.html)
  and [sigwait](https://pubs.opengroup.org/onlinepubs/9699919799/functions/sigwait.html)
  specify error-number returns.
- [Musl sigwait implementation](https://git.musl-libc.org/cgit/musl/tree/src/signal/sigwait.c)
  returns -1 after failed sigtimedwait. Its source was fetched directly after
  the documentation browser could not access it.
- [Nix source at the tested upstream base](https://github.com/nix-rust/nix/blob/89339c618783622e3cdd8d7a6b17319a65337e94/src/sys/signal.rs)
  identifies the original wrappers.

All 26 signal tests pass on x86_64 GNU and musl. All-feature library builds
pass on ARM64, RISC-V64 and PowerPC64LE musl; these are compile checks only.
Formatting passes. The old upstream code fails the new regression at the
first mask assertion. The initial musl and formatting drafts are retained
separately. Cargo build durations are omitted.

The Linux regression installs a filter only on its subprocess's test thread,
covering set/get/swap-mask and wait failures. It needs no privileges and
changes no host network or unit. A GNU/musl signal-suite pass does not mean
the full upstream multi-platform test suite ran locally.

## Downstream integration remains pending

There is no daemon workaround, Cargo patch or unpublished replacement.
The repository requires fixing dependencies upstream before integration.
A compatible published fix is still needed before enabling the proposed
daemon signal-fault cases and collecting their production coverage.
Unrelated proof work may continue. H11/P5, final qualification, complete
clause/resource/event-cost proof and 100% coverage also remain open.

The preceding daemon source and its tests still pass common checks; coverage
remains 95.00% lines / 84.86% branches. CI runs 41249093334 and 41249482678
pass both jobs in about fourteen and thirteen minutes. Later runs remain
separate from this upstream proof.

```sh
# In the upstream checkout:
cargo test --test test sys::test_signal:: -- --test-threads=1
cargo test --target x86_64-unknown-linux-musl --test test sys::test_signal:: -- --test-threads=1
cargo check --all-features --lib --target aarch64-unknown-linux-musl
# Also riscv64gc-unknown-linux-musl and powerpc64le-unknown-linux-musl.
cargo fmt --all -- --check
# In the daemon checkout:
./test-ci-gates.sh
```
