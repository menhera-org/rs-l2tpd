# Event and lifetime ordering

This batch starts from signed `0bb8100`. Production behavior is unchanged.
Moving shared test helpers changes source locations, so coverage uses a
fresh collector and merges no preceding batch's profiles. It covers
**8,642/8,705 lines (99.28%)** and **1,787/1,840 branch outcomes (97.12%)**.
**63 lines and 53 outcomes remain uncovered.** There are no production
exclusions. Phase 6 remains open.

The new lifetime fixture orders a failed send against a replacement
generation, stops a reader after a refused reopen, and stops a quiet
reader without invalidating its registrations. It reuses the checked
syscall tracer and temporary-directory helper. Separate children and
network namespaces isolate each case. The quiet-reader case checks state
and ordering; it makes no elapsed-time claim about the poll interval.

Model cases check both closed subscription forwarders, successful/refused/
panicked reload completions during shutdown, repeated left-out conflicts,
partial adopted reports without creation names, and a refused chain rename
that stages only the owned blocking holder. The adoption input is a
defensive model fixture, not a claim that a verified Ethernet kernel
normally omits its creation name. Conflict assertions check deadlines and
identity changes, not log counts.

Optional-feature checks also expose an older TOML-based runtime case compiled
without `serde`. Its declaration and a serde-only test import now use the
matching feature guard. No-default and serde-only library suites pass. The
shared tracer imports libc through the existing nix dependency, so library
tests do not require the binary's optional direct libc dependency.

The existing container task-limit helper now exercises both daemon forks
as well as signal-thread creation. Direct container task limits avoid the
preceding fixture's failed cgroup migration. Both fork failures must return
the original OS error and exit 1 before kernel initialization, with no panic.

## Results

- Ten fresh instrumented ordinary suites pass. Three GNU and three musl
  library/binary container repetitions pass. The final lifetime fixture
  separately passes three GNU, three musl and three instrumented runs.
- Shared CI gates, Rust 1.89 and three additional musl architecture compile
  checks pass. Strict maps still cover 333 active rules and 43 kernel facts.
- The fresh GNU live collection passes serial library/Linux/review tests,
  35 process cases and all 27 non-Incus scenarios. Fresh unprivileged Incus
  passes and exports seven daemon profiles.
- Three instrumented manager/task-limit repetitions pass. The expanded
  four-case task-limit helper also passes three stable GNU and three stable
  musl repetitions. First- and second-fork panic controls are both rejected.
- The unmodified root systemd unit passes. Three fresh GNU buffer-force
  guests pass and each exports seven profiles.
- All five required normal profiles pass all 27 scenarios and 35 process
  cases; both IPv6-absent boots and missing-driver recovery pass. All five
  clock/pause profiles pass a separate serial replay with the shipping
  two-CPU/default-TCG runner unchanged. Individual exit files and guest/
  controller markers are checked in `results.log`. This replay does not
  erase the failed parallel attempt or establish ten-run determinism.
- The publication recheck retains Ubuntu 6.8.0-147.147 and 7.0.0-42.42,
  vanilla 6.8.12 and 7.0.14, and mainline 7.4-rc1.
- Five additional restored controls reject stale-generation damage, a stuck
  closed-queue forwarder, skipped nameless adoption, the wrong slow retry
  deadline and staging the wrong session.

The normal guests ran the first lifetime fixture and the original calibration
profile. The later quiet-reader revision removes an incidental elapsed-time
assertion; final focused repetitions qualify it. The subsequent serial
calibration selection passes common checks and the final GNU/musl runs.
No shipping timing threshold changed. Ordinary suites leave privileged
and child-launch declarations ignored; separate
live and manager profiles supply their stated scope. Earlier shipped-musl
scenario/Incus evidence remains in the checked-boundary record; this batch
does not claim a new three-pair shipped-musl run.

`source.patch` records tracked source changes against `revision`;
`shared-testdir.txt` retains the new shared helper. Control patches use
`control-base-revision` and include that checkout's pending batch changes.
All mutations were restored. Coverage export logs contain only the known
unstable-branch-option notice, with no mismatched or saturated profiles.

## Rejected attempts and limits

The initial parallel launch passes all five normal profiles and three
clock profiles, but fails two clocks. Ubuntu 7.0 panics with INT3 before
userspace. Vanilla 6.8 observes a 1.706-second retry interval above the
existing 1.5-second fixture limit. All logs remain under
`rejected-parallel-kernels/`; successful normal/boot profiles are also
copied into `kernels/`. Only the clock replay uses serial launches.

A malformed experimental runner first failed shell parsing before boot.
After correction, single-thread TCG with either two CPUs or one CPU boots
all five kernels and passes conformance, but every H17 scale case exceeds
its existing readiness timeout. A separate one-CPU/default-TCG Noble
experiment also fails scale. These are rejected experiments, not qualified
runner configurations. The shipping runner and its documentation are
restored byte-for-byte.

The boot signature is consistent with
[QEMU issue #4669](https://gitlab.com/qemu-project/qemu/-/work_items/4669),
which describes stale translated INT3 code despite changed instruction
bytes under MTTCG. That correspondence is an inference, not proof of this
boot failure's cause. The serial replay's success does not prove that the
emulator fault or scheduling sensitivity is resolved.

The final common check exposed interference between the newly shared tracer
calibrations and concurrent fake descriptor owners. A diagnostic replay
also fails immediate fake shutdown. A standalone GNU/musl witness holds a
child before exec and confirms that its inherited socket delays the parent's
last-close observation. Both calibrations now run in an explicit serial
profile in the common CI script, including musl. They are still executed;
ordinary model suites no longer launch them concurrently. Final common
checks pass; ten final instrumented suites and three model/calibration runs
per libc qualify this arrangement. Failed runs remain as
`rejected-common-parallel.log` and `diagnostic-parallel-*.log`.

Initial fixture/setup failures are retained separately. A report wrapper
also failed to find `jq` after writing the successful coverage export;
totals were then extracted with the installed tool's explicit path. An
instrumented calibration command first put its test filter before the
argument separator; the corrected invocation runs both cases in both
executables. The rejected command log is retained.
Complete clause/history/resource/event-cost proof, raw 100% coverage and
its CI enforcement remain outstanding.
