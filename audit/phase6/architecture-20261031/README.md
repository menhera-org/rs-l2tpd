# Architecture, restart and host-visible identity assertions

This package strengthens existing assertions and connects 15 previously
uncited architecture/event/observability rules to test declarations. It changes
no production behavior or dependency. Test-declaration coverage is traceability;
it does not replace clause coverage, live execution or the coverage gate.

## Stronger execution checks

The seeded planner now compares the converged session's tunnel/session/peer
identifiers, both cookies and current interface name with accepted configuration
after every transition. It also checks the tunnel's peer identifier, device
binding and selected source. Existing assertions continue to require justified
identity changes only, foreign-object preservation, manager administrative
state, idempotent fixed points and cleanup. Every invocation runs 32 sequences
of 64 steps. TEST_SEED changes the starting seed; the ten ranges overlap.

The failed staging-address case now requires exactly one initial session create,
no premature rename, the same index and correct hardware address after retry,
and no second creation. Staging publication additionally requires tunnel
registration before session creation. The existing failed scoped-connect case
tests retaining a side-effected binding and recovering on the same socket.

The restart/PID case checks the exact PID-plus-newline representation before
and after exec, and the fixture directory's exact contents at readiness,
after exec and after shutdown. Only the fixture's input/executable and, while
running, the PID file may be there. This observes that directory, not every
filesystem path; the existing library-boundary checks supplement it. SIGUSR2
exec preserves the session index and PID-file inode. The service restart case
separately drives restart through `Control` and checks supplied socket IDs.

The H6 scenario records its original device count, then requires the session
to be the sole additional device at readiness without routes. It still requires
real disconnected-frame drops and bidirectional frames after configuring the
first route within the measured connection bound. Existing namespace devices
are allowed; no fixed host module/interface inventory is assumed.

## New declaration citations

| Rules | Declarations and assertion scope |
|---|---|
| A1, A3, A4 | `library_boundary_and_extensible_api` in [runtime/tests.rs](../../../src/runtime/tests.rs) checks public modules, process-I/O separation and binary service integration; the planner below checks observable policy/state behavior. These are the module-map/source-boundary checks allowed by P1, not kernel conformance |
| A3, A4, A11, A20 | `reload_sequences_converge_without_unjustified_identity_changes` in [planner.rs](../../../tests/properties/planner.rs), with the stronger object/configuration comparisons and existing fixed-point/identity/foreign-state assertions |
| A8 | `a_session_is_staged_then_published` in [sessions.rs](../../../tests/rules/sessions.rs) asserts register/create/address/rename order; `withdrawal_precedes_close_and_replacement_storage` in [store.rs](../../../tests/rules/store.rs) checks dependency release before replacement |
| A9 | Worker budget and blocked-call declarations in [workers.rs](../../../src/reconciler/workers.rs) require separate system/configured admission, bounded obsolete jobs, refresh deadlines and latest-result handling |
| A10 | `daemon_readiness_pid_inode_and_reexec` in [process.rs](../../../tests/process.rs), with exact directory contents and preserved kernel/PID identity across exec |
| A12 | `failed_staging_address_is_retried_before_publication` in [sessions.rs](../../../tests/rules/sessions.rs); `a_failed_scoped_connect_can_change_its_kernel_binding` in [completion.rs](../../../tests/rules/completion.rs), retaining partial records until recovery |
| A15 | Literal-peer socket preservation in [tunnels.rs](../../../tests/rules/tunnels.rs) and retained/changed DNS-answer handling in [resolvers.rs](../../../tests/rules/resolvers.rs) |
| A16 | Manager rename and staged-loss/reused-index cases in [sessions.rs](../../../tests/rules/sessions.rs); real moved-device/index reuse in [linux.rs](../../../tests/kernel/linux.rs) |
| A17 | `staged_loss_never_modifies_a_reused_index_and_name` in [sessions.rs](../../../tests/rules/sessions.rs) refuses ambiguous stored-name proof and unsafe mutation after loss |
| A19 | H6 in [hosts.rs](../../../tests/scenarios/hosts.rs), with only the session added, actual outbound drops without a route, then real frames after reachability |
| E26 | `reload_error_keeps_config_then_success_applies_and_restart_resumes` in [service.rs](../../../tests/service.rs) and SIGUSR2 exec in [process.rs](../../../tests/process.rs) |
| O9 | Exact PID newline in [process.rs](../../../tests/process.rs), staged/cyclic temporary names in [sessions.rs](../../../tests/rules/sessions.rs), and the live previous-peer/empty-source tunnel dump in [linux.rs](../../../tests/kernel/linux.rs) |

The source-boundary test now also checks the library's public module map and
rejects direct kernel/reconciler-record references from the binary entry point.
Its existing source assertions are explicitly supplementary to execution.
The P1 instruction permits these checks for module-map statements; they do not
prove the entire architecture from a textual match.

## Commands and results

```sh
cargo test --locked --all-features --lib --test rules --test service -- --nocapture
# Each TEST_SEED=1..10:
cargo test --locked --all-features --lib --test rules --test service -- --nocapture
./test-ci-gates.sh
RULEMAP_STRICT=1 cargo test --locked --all-features --test rulemap -- --nocapture
cargo test --locked --all-features --target x86_64-unknown-linux-musl --test kernel-linux --test process --no-run
# Disposable privileged Docker, --network none, read-only checkout:
kernel-linux --ignored --test-threads=1 --nocapture
process --include-ignored --test-threads=1 --nocapture
tests/docker/run.sh scenarios
```

All Cargo commands use `--locked --all-features` except other feature sets in
the common CI gate. Ordinary suites use the native target. Live artifacts use
`x86_64-unknown-linux-musl` on `6.8.0-147-generic`; no host networking, sysctl,
module or process limit is changed.

[first.log](first.log) passes 92 ordinary library cases (11 live ignored),
75 rules and 25 service cases before the H6 baseline-count refinement.
[fake-ten.log](fake-ten.log) passes the same counts for each of ten seeds on
the library/rule/service source used by the final checks. [live.log](live.log)
passes 19 kernel and 27 process cases. These runs precede only the H6 test's
iterator refinement, which does not change those suites or daemon behavior.
[The full host run](../scenarios-20261031T124231Z-3883852/run.log) passes all
25 scenarios in 163.50 seconds before that refinement. The initial
[warning-denied Clippy run](ci-before-iterators.log) correctly rejects two
index-based loops in the new H6 assertion; they now enumerate their arrays.
[ci-gates.log](ci-gates.log) then passes the common formatting, ShellCheck,
warning-denied Clippy/docs, feature builds, native/musl ordinary suites and four
strict source-link cases. The [final focused H6 run](../scenarios-20261031T124648Z-3893780/run.log)
passes in 4.45 seconds; both controller summaries retain `SCENARIO_RESULT=0`.
No product fix or lint suppression was needed.
[rulemap.log](rulemap.log) remains red, exit 101: 343 total / 333 active /
330 cited / three missing (G15, G16, G20). No strict CI flag is enabled yet.

`revision` and `source.patch` identify tested source; source-identity.log checks
the final snapshot and hashes artifacts. docs-checks.log checks local Markdown
file targets and whitespace, excluding web URLs and anchors. Cargo build
durations are omitted.

The other four required kernels, final Incus/root-manager profiles, complete
clause/resource/event-cost proof, coverage, three remaining promise citations
and strict CI are still open. No global Phase 6 gate is closed by this package.
