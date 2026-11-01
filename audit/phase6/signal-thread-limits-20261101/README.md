# Signal-thread allocation failures

The actual daemon runs as the sole initial task in disposable networkless
containers. A task limit of one refuses its collector thread; a limit of
two allows the collector and refuses the forwarder. Both must return the
original EAGAIN and exit one before kernel startup, without readiness or
panic. The second case must stop, wake and join the already-started collector.

`tests/docker/thread-limits.sh` implements this check. Docker's pids
controller and a `timeout` command are required. The driver explicitly
disables Docker's init wrapper so daemon defaults cannot add another task. The kernel source is
[v6.8.12 kernel/cgroup/pids.c](https://github.com/gregkh/linux/blob/v6.8.12/kernel/cgroup/pids.c#L150-L189):
`pids_try_charge` refuses a count above the hierarchical limit with EAGAIN;
`pids_can_fork` charges one task. `kernel-source-artifacts.log` identifies
the inspected source. Only disposable-container task limits change.

## Verification and controls

The final driver passes ten GNU runs and three stable musl runs, each with
both limits. The exact new CI shell command also passes locally. Every
container is removed; `remaining-containers.log` is empty. Common strict
rule/source maps, ShellCheck, Clippy, feature builds, ordinary GNU/musl tests
and rustdoc pass. The extracted CI shell block passes syntax and ShellCheck.
The CI step has a three-minute limit and uploads its records with the
existing live artifacts. Creation is bounded separately at 60 seconds,
then attached execution at 20 seconds.

The negative control replaces the collector's wakeup signal with signal
zero, a liveness query. The one-task case still returns EAGAIN; the two-task
case hangs at join and fails the execution deadline. Its binary, patch and
logs remain separate from shipping source. Five fake-executable controls
also verify rejection of success, silent failure, kernel retry, readiness
and panic. Bad argument count and a missing binary are rejected before
starting a container.

The collection kernel is 6.8.0-147-generic. GNU uses the recorded Ubuntu
24.04 review image; musl uses the Alpine review image. This resource fixture
has not run inside the five bare-kernel matrix guests. The frozen `ce6a70a`
matrix separately qualifies the daemon's normal/kernel/process behavior.

Production code and coverage mappings are unchanged. Forty profiles from
the fully passing GNU cases add five covered lines. Coverage is
**95.95% lines** (8,243/8,591) and **87.81% branches** (1,607/1,830),
leaving 348 lines and 223 branches. No production exclusions, profile
mismatches or saturated regions are recorded. The cleanup counters show
the forwarder-refusal branch executing. Initial-driver profiles and the
negative-control binary do not contribute. The earlier fully passing
no-init-default runs are retained in `pre-explicit-init/`; the final driver
makes that setting explicit and passes another ten GNU/three musl runs.

The checked libc source passes both jobs in
[CI run 41272054292](https://github.com/menhera-org/rs-l2tpd/actions/runs/41272054292).
The later installer-test head passes
[CI run 41272918857](https://github.com/menhera-org/rs-l2tpd/actions/runs/41272918857).
The new resource step still needs its own CI result. Final qualification,
complete clause/resource/event-cost proof and the 100% gate remain open.

## Initial driver failure

The initial combined create/start command passes five GNU repetitions, then
times out creating the sixth run's two-task container. The daemon never
starts: Docker reports Created, Pid 0 and an unset StartedAt. The command
log begins at 04:30:54.994190658 UTC; cleanup is attempted at
04:31:15.008461596. Docker registers the container at
04:31:15.235887969, after that attempt. It is removed explicitly afterward.
The state, events, original driver and all original transcripts remain in
`initial-driver/`. None of its eleven profiles is merged.

The final driver completes creation before timing execution and keeps the
registered container until explicit removal. Ten subsequent GNU and three
musl repetitions pass. The execution bound stays 20 seconds; the separate
creation allowance covers the container API rather than daemon behavior.

`revision` and `source.patch` identify the new driver and CI invocation.
The negative-control patch applies to that revision independently.

```sh
tests/docker/thread-limits.sh rs-l2tpd-coverage:phase6 \
    target/phase6-coverage-libc-signals-20261101/x86_64-unknown-linux-gnu/debug/rs-l2tpd \
    audit/phase6/signal-thread-limits-20261101/gnu-N \
    target/phase6-coverage-libc-signals-20261101/thread-profiles
# Repeat ten times, with distinct record directories.
tests/docker/thread-limits.sh rs-l2tpd-audit-vm:local \
    target/x86_64-unknown-linux-musl/debug/rs-l2tpd \
    audit/phase6/signal-thread-limits-20261101/musl-N \
    target/phase6-thread-limit-musl-profiles
# Repeat three times.
./test-ci-gates.sh
# After successful GNU collection, copy its profiles into the coverage root.
CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-libc-signals-20261101" \
    cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
