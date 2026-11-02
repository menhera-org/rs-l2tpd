# Signal delivery and ownership guards

This batch extends signed `958671c`. Production function bodies remain
unchanged. The collector covers **8,589/8,687 lines (98.87%)** and
**1,765/1,852 branch outcomes (95.30%)**: eight more lines and seventeen
outcomes than the preceding report. **98 lines and 87 outcomes remain
uncovered.** No production exclusion is added.

All 4,331 function mappings retain their region locations and filename
lists. One function's formerly empty branch list now contains the existing
Signals::attach guard; the line/branch denominators remain unchanged.
`mapping-change-detail.json` records that difference. The production prefixes
of the edited implementation files also compare byte-for-byte with `revision`.
Profiles from earlier production implementations are not merged.

The tracer now forwards signal-delivery stops. Its calibration installs
handlers, raises SIGUSR1 and SIGCHLD on the traced worker and checks that
both handlers ran. The preceding commit's coverage CI failed because the
helper treated a normal SIGCHLD stop as unexpected. That commit's live CI
and CodeQL pass; the coverage failure is retained in `preceding-ci.json`
and `preceding-ci-failure.txt`. It was a fixture failure, with no timeout.

The signal fixtures check worker cleanup with present/absent handles and
both thread-creation failures. The harness itself has two threads:
`pids.max=2` refuses the collector; three allows that collector but refuses
the forwarder. Each case checks the limit, matching peak and exactly two
remaining threads. Docker's initial cgroup includes runtime setup peaks,
so container runs use a fresh child in an explicitly private cgroup namespace.
The rejected initial peak check is retained. The relevant kernel source is
`kernel/cgroup/pids.c`, including `pids_can_fork` and `pids_peak_read`.

A narrow SIGPIPE selector preserves disposition queries, write-only resets
and other signals. Its assertions include non-null pointers whose low word
is zero, without allowing the kernel to dereference those synthetic values.
GNU/musl cases verify EIO after a compatible probe. This refusal occurs in
Rust's exec reset; it does not cover our later pre-exec hook's separate error
arm. That arm remains in the missing-lines report.

The model cases cover repeated tunable requests, changed conflict identity,
stale reverse-index ownership, missing or lost device proof, unreadable MAC
state, an already satisfied name and defensive inherited-owner/shutdown
guards. The last two operate on private verifier state; public inheritance
remains restricted to startup. Later cases check shutdown before attaching
a service, resolver answers without a local record and reload cleanup of
that missing record. These assertions run over the fake kernel.

All five frozen guest binary profiles pass: Ubuntu 6.8.0-147.147 and
7.0.0-42.42, vanilla 6.8.12 and 7.0.14, and mainline 7.4-rc1. Each runs 73
ordinary CLI cases, three selected filesystem cases and both task-limit
variants. These profiles use `guest-base-revision` plus `guest-source.patch`;
`guest-source-comparison.log` records the comparison at that freeze. They
also qualify the updated shipping guest fixture. Later model additions and
the manager-socket fixture correction are recorded in `late-state.patch`
and `manager-close.patch`; those additions were qualified locally, outside
the guest scope. `source.patch` records the final shipping changes against
`revision`.

Final common gates, Rust 1.89 and three additional musl architecture compile
checks pass. Final model/daemon suites pass ten instrumented repetitions;
final ordinary process cases pass another ten concurrent instrumented runs.
Three final musl repetitions include models, daemon units and process cases.
Three GNU and three musl container repetitions each pass the frozen daemon
suite and both task-limit variants. Three further container repetitions per
libc pass the final ordinary process suite concurrently. Three GNU
instrumented task-limit pairs contribute their profiles through independent
filenames; `profile-transport.log` retains the exported identities.

The broader run caught a manager-fixture race: another fork could retain a
listener after its parent dropped it. The final fixture deliberately keeps
an extra listener descriptor, observes the live peer, releases that reference
and waits for a fresh connection to return ECONNREFUSED before shutdown.
It requires that same precise refusal in the withdrawal report. The tested
boundary is an unavailable recipient before withdrawal; later barrier phases
retain their separate tests. The rejected common-gate run is retained.

Eight restored mutations fail at their intended runtime assertions:

- Ignore high pointer words in the signal selector.
- Reject signal-delivery stops in the tracer.
- Remove a reverse index without checking its current owner.
- Apply a deferred MAC without proving device identity.
- Retain a conflict counter after its identity changes.
- Lose shutdown when attaching a new service.
- Converge an answer with no local owner record.
- Keep the test manager's final listener reference open.

The main controls use `control-base-revision` plus `control-source.patch`;
the later state and IPC controls retain their own source snapshots. Rejected
and diagnostic executions of the same production implementation remain in
the incremental collector; rejected attempts are not determinism passes.
Affected synthetic-path logs encode NUL as `<NUL>`, with checked byte-for-byte
reconstruction and raw Git identities in `nul-encoding.log`. Cargo build
durations are removed.

This package does not replace the full thirteen-profile matrix or establish
new Incus/root-unit scope. Its own push CI is checked after publication.
The 100% gate and complete clause proof remain open.
