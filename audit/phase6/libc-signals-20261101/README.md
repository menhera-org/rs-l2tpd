# Checked libc signal calls

The maintainer authorized direct `libc` calls when a `nix` wrapper is broken,
with a documented exception, and clarified that contributing to `nix` is not
required. `CONTRIBUTING.md`, `docs/phase6.md` and `docs/dependencies.md`
record that policy. The existing upstream proposals remain references;
the daemon no longer waits for a compatible release.

## Defect and scope

Nix 0.30.1 treats positive pthread errors as success. Its wait wrapper can
then read an output that libc never initialized. The original
[upstream record](../upstream-signal-errors-20261031/README.md) retains the
pinned reproduction, upstream source and GNU/musl checks.

The binary replaces two affected calls: signal-mask setup and signal wait.
It checks zero for success, positive return values as error numbers, and
-1 through thread-local errno. POSIX specifies error-number returns for
[pthread_sigmask](https://pubs.opengroup.org/onlinepubs/9699919799/functions/pthread_sigmask.html)
and [sigwait](https://pubs.opengroup.org/onlinepubs/9699919799/functions/sigwait.html);
[musl's sigwait](https://git.musl-libc.org/cgit/musl/tree/src/signal/sigwait.c)
returns -1 with errno after a failed sigtimedwait. The latter source was
fetched directly again because the documentation browser could not access it.

The wait output starts initialized and is interpreted only after success.
A failed conversion to a known signal returns an error. Safe signal-set
construction and unrelated `nix` APIs remain unchanged. The existing `libc`
dependency suffices; Cargo.toml and Cargo.lock are unchanged. The library's
L2 unsafe-code boundary and public APIs are unchanged.

The kernel paths are `kernel/signal.c`: native
[rt_sigprocmask, v6.8.12](https://github.com/gregkh/linux/blob/v6.8.12/kernel/signal.c#L3177-L3206),
[do_sigtimedwait and rt_sigtimedwait, v6.8.12](https://github.com/gregkh/linux/blob/v6.8.12/kernel/signal.c#L3604-L3693),
and their v7.3 counterparts at lines 3388–3417 and 3815–3904.
The mask syscall validates the kernel set size and copies the input; the
wait syscall copies signal information only after a positive signal return.
Libc supplies the kernel ABI size. Our mask is borrowed for the call, its
old-mask output is null, and the wait output is a local initialized integer.

The GNU implementations are
[pthread_sigmask](https://github.com/bminor/glibc/blob/glibc-2.39/nptl/pthread_sigmask.c#L23-L46)
and [sigwait](https://github.com/bminor/glibc/blob/glibc-2.39/sysdeps/unix/sysv/linux/sigwait.c#L22-L36)
at glibc 2.39. Both return positive errors. GNU retries EINTR inside sigwait;
libc retains that behavior. Any surfaced wait error follows the daemon's
existing shutdown policy. `libc-sources.json` and `kernel-source-artifacts.log`
identify the inspected sources. The fault filters verify refusal handling;
the successful delivery cases exercise the actual signal syscalls.

## Tests and controls

The new isolated subprocess cases verify the exact blocked set, an unblocked
SIGUSR1, and successful thread-directed delivery of SIGHUP, SIGTERM, SIGINT
and SIGUSR2. Refused rt_sigprocmask and rt_sigtimedwait calls must return EIO.
Each child exits before its signal state or syscall filter can affect another
test. Return-convention checks also prove that zero ignores stale errno,
a positive error takes precedence over a different errno, and -1 preserves
errno.

The actual daemon process fixture adds mask and wait failures to its six
existing setup failures. It requires the original EIO, exit code one, an
unchanged pre-existing PID file, and the collector's shutdown diagnostic
for the wait failure. Socket calls are independently refused, so this
fixture never opens live network interfaces.

The old pinned-wrapper control fails at the mask case: it enters kernel-open
retry instead of returning EIO. It stops there, before testing the old
unsafe wait-output path. `old-nix-control.log` retains the failure. The
second control treats positive errors as success; the return-convention
test fails. Its log and patch remain separate from the shipping source.
`process-regression.patch` and `positive-error-control.patch` each apply to
`revision`; `source.patch` reconstructs the shipping implementation/tests.

## Verification

The final source passes ten seeded ordinary suites and three musl binary
suites. Both GNU and musl run the focused two-test signal package three
times; the actual musl daemon fault package also passes three times. The GNU
daemon package passes directly and in the full isolated process suite.
Common strict rule/source maps, Clippy, feature builds and rustdoc pass.
ARM64, RISC-V64 and PowerPC64LE musl all-target checks pass; those are
compile checks, not live architecture results. Cargo build durations are
omitted from retained logs.

Fresh nightly GNU profiles use a separate coverage target. No profiles from
the preceding implementation are merged. The live collection passes
14 privileged library, 20 Linux, five review, three privileged binary,
28 process and all 26 normal scenario cases; the latter finish in 158.10 s.
The real user-manager case passes. The full unprivileged GNU Incus case
passes in 23.63 s and exports seven daemon profiles. The unmodified stable
musl root-systemd case passes in 27.99 s, ROOT_SYSTEMD_RESULT=0. These manager
results apply to Ubuntu 24.04 userspace and kernel 6.8.0-147-generic.
Three fresh stable musl Incus cases pass in 18.39, 9.18 and 14.72 s, with
all containers deleted. Three complete stable musl normal suites pass
serially in 160.88, 160.96 and 161.00 s. They do not overlap the GNU host
scale workload.

The preceding source passes both jobs in
[CI run 41270177487](https://github.com/menhera-org/rs-l2tpd/actions/runs/41270177487).
Fresh production coverage is **95.83% lines** (8,233/8,591) and **87.65%
branches** (1,604/1,830), leaving 358 lines and 226 branches. The new return
checker and wait function have every source region exercised across their
production/test instantiations. No production exclusions, profile mismatches
or saturated regions are recorded; test-only helpers remain excluded while
the tests run.

The initial fresh report is retained separately. Its runtime/service branch
summaries were each one below the preceding collection despite the same
combined source-coordinate outcomes. Ten additional instrumented library/
service seeds pass; their current-source profiles recover those summaries
and cover further paths. The final report uses the unchanged llvm-cov gate;
no preceding implementation's profiles or replacement counting scheme is used.

Current-source CI, required-kernel qualification, complete clause/resource/
event-cost proof and 100% coverage remain separate requirements.

```sh
cargo test --locked --all-features --bin rs-l2tpd signals::libc_tests -- --nocapture
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd signals::libc_tests -- --nocapture
cargo test --locked --all-features --test process daemon_setup_failures_return_the_original_error_before_kernel_startup -- --ignored --exact --nocapture
cargo test --locked --all-features --target x86_64-unknown-linux-musl --test process daemon_setup_failures_return_the_original_error_before_kernel_startup -- --ignored --exact --nocapture
# Repeat focused GNU/musl unit and musl process packages three times.
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-libc-signals-20261101"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/libc-signals-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/process-errors-20261031/run-live.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
TEST_SEED=1 cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report --lib --test service
# Repeat instrumented library/service seeds 2 through 10.
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
tests/docker/run.sh incus
# Repeat with three fresh containers.
tests/docker/run.sh scenarios
# Repeat three times serially, after the GNU scale workload.
# Root guest command and artifact identities: root-systemd/command.log and artifacts.log.
```
