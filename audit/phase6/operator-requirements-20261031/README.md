# Operator, peer and manager requirement assertions

This package links 23 previously uncited requirements to assertions and
strengthens four existing fixtures. It changes no production behavior or
dependency. The complete specification, coverage and final matrix gates remain
open; a declaration citation is traceability, not proof of every clause.

## Strengthened assertions

- Configuration loading now exercises invalid UTF-8 bytes, startup omission
  and reload refusal, alongside malformed TOML and unreadable paths. No input
  text is copied into the diagnostic.
- The staging and cyclic-rename cases first observe the deterministic fake's
  chosen temporary name in an independent run, then occupy that candidate with
  a foreign device. Both `rsl2tp-t` and `rsl2tp-r` collisions must select another
  name, converge, and preserve the foreign device's complete link record.
- The live raw-frame case sends missing/wrong cookies and a correct cookie with
  the wrong session identifier. Each negative case must leave receive counters
  unchanged throughout a 100 ms negative window. The correct identifier/cookie
  then delivers exactly one frame. A disconnected tunnel still drops outbound
  traffic. This is scoped frame admission evidence, not a test of every foreign
  encapsulation or sequencing format.
- The container filesystem case masks both `/proc` and `/sys` with empty tmpfs
  mounts in each daemon's private mount namespace. It verifies those mounts,
  exactly the three required effective capabilities, readiness, bidirectional
  frames and cleanup. The fixture's observer retains its own `/proc` access.

## Newly cited requirements

Paths below identify test declarations, not production-code inspection.

| Rules | Test locations and assertions |
|---|---|
| R11, R31 | `a_moved_session_is_forgotten_without_deleting_a_replacement` in [sessions.rs](../../../tests/rules/sessions.rs) refuses deletion after identity removal/reuse; `a_reused_index_and_creation_name_never_revive_an_old_registration` in [linux.rs](../../../tests/kernel/linux.rs) moves the real device into another namespace and proves the old registration removed while the session still exists |
| R12 | `foreground_reload_and_clean_shutdown_without_network` in [process.rs](../../../tests/process.rs) operates without an init/readiness consumer; H19 in [hosts.rs](../../../tests/scenarios/hosts.rs) exercises the POSIX init contract |
| R13 | `failed_documents_are_omitted_and_diagnostics_redact_input`, `permission_child`, `permission_errors_name_unreadable_unlistable_and_uninspectable_paths` in [files.rs](../../../src/bin/rs-l2tpd/files.rs); process reload case preserves the session after refused reload |
| R14 | `uniqueness_in_byte_order_of_names` in [config/tests.rs](../../../src/config/tests.rs) rejects later configured duplicate tunnel/session identifiers and names; H12 in [managers.rs](../../../tests/scenarios/managers.rs) preserves foreign collisions; overlapping process case preserves the first owner's interface |
| R15 | Live raw-frame admission case in [linux.rs](../../../tests/kernel/linux.rs), with positive and separate negative windows |
| R16 | `the_selected_address_is_retained` in [resolvers.rs](../../../tests/rules/resolvers.rs) preserves an answer across negative lookup and replaces it when a new usable answer arrives; other bounded-worker tests remain separate |
| R17 | `cleanup_cannot_delete_a_foreign_replacement_tunnel` in [tunnels.rs](../../../tests/rules/tunnels.rs) closes only the old socket, preserving the replacement's socket and peer identifier |
| R18 | `an_externally_deleted_session_is_created_again` in [sessions.rs](../../../tests/rules/sessions.rs) delivers the external deletion and requires a new session index |
| R19 | Staged publication and cyclic name-swap cases in [sessions.rs](../../../tests/rules/sessions.rs), with occupied deterministic candidates and foreign record preservation |
| R21 | `overlapping_instance_becomes_ready_without_deleting_foreign_objects` in [process.rs](../../../tests/process.rs) uses distinct PID files, observes withheld readiness initially, then conflict-budget readiness and unchanged owner interface after second-instance shutdown |
| R23, R29, R36 | Hardware-address deferral and manager-raised staging cases in [sessions.rs](../../../tests/rules/sessions.rs) preserve administrative state and overrides, apply deferred work only when down, publish the staged device, and retain child addressing |
| R24, R25 | H1 in [hosts.rs](../../../tests/scenarios/hosts.rs) exchanges real frames on mirrored IPv4/IPv6 IP-encapsulated sessions; raw-frame case rejects wrong identifier/cookie combinations |
| R26 | H6 in [hosts.rs](../../../tests/scenarios/hosts.rs) reaches readiness without routes, observes actual drops, then carries frames after source/route configuration within the measured bound; this does not diagnose a blocked path |
| R28 | `another_managers_rename_is_kept` in [sessions.rs](../../../tests/rules/sessions.rs) requires no mutation after delivery and identical reconcile |
| R30 | Manager-raised staging case retains child/master/address state; H10 in [managers.rs](../../../tests/scenarios/managers.rs) retains a VLAN child moved to the other namespace through reload/rename and removes it with its parent |
| R34 | H13 in [hosts.rs](../../../tests/scenarios/hosts.rs) exercises absent, renamed, removed and replaced bind devices while preserving session indexes |
| R43 | H9 in [hosts.rs](../../../tests/scenarios/hosts.rs) works with empty `/proc` and `/sys`; H19 exercises a POSIX init; musl is the live artifact target |
| R44, R48 | H18 in [hosts.rs](../../../tests/scenarios/hosts.rs) checks correction and opt-out, both socket families carrying frames, and a later manager sysctl change followed by reload without session replacement |

Existing tests cover other parts of these requirements; this table records
the assertions attached to the new citations without claiming complete global
proof. R35 burst behavior and R45 absent VRF support remain uncited.

## Executions

All Cargo checks use `--locked --all-features` unless the common CI gate checks
another feature set. Ordinary seeded tests use the native target. Live
container and user-manager artifacts use `x86_64-unknown-linux-musl` on
`6.8.0-147-generic`. Containers are disposable and privileged, with
`--network none` and a read-only checkout; no host networking, sysctl or process
limit is changed.

```sh
cargo test --locked --all-features --test rules sessions:: -- --nocapture
./test-ci-gates.sh
# Each TEST_SEED=1..10:
cargo test --locked --all-features --lib --test rules --test service -- --nocapture
RULEMAP_STRICT=1 cargo test --locked --all-features --test rulemap -- --nocapture
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd --test kernel-linux --test process --no-run
# In the container, all with --test-threads=1 --nocapture:
kernel-linux --ignored
process --include-ignored
binary-unit-tests --include-ignored --skip fdstore::manager_tests
tests/docker/run.sh scenarios
```

[sessions.log](sessions.log) passes 18 focused cases. The
[shared CI gate](ci-gates.log) passes formatting, ShellCheck, warning-denied
Clippy/docs, feature builds, native/musl ordinary tests and four source-link
cases. [Ten seeded runs](fake-ten.log) each pass 92 ordinary library cases
(11 live ignored), 74 rule cases and 25 service cases. The planner's 32-seed
ranges overlap; this remains scoped determinism evidence.

[The corrected live profile](live.log) passes 19 kernel cases, 26 process cases
and 41 binary unit cases. One real-manager case is explicitly filtered there:
it requires a user systemd service rather than a plain container.
[user-manager.log](user-manager.log) runs that exact case successfully through
`systemd-run --user --wait --pipe --collect`, with `Type=exec`,
`NotifyAccess=all`, `FileDescriptorStoreMax=65536` and the template's
`RestrictAddressFamilies`. The test checks the actual manager properties,
stores one descriptor, checks its count, withdraws it, and checks zero.
The transient unit exits successfully and is collected. This is not a fresh
P6 root-system-unit sandbox run.

[live-profile-fixture.log](live-profile-fixture.log) retains the initial runner
mistake: 19 kernel and 26 process cases passed, then blindly including all
ignored binary cases attempted the real-manager case without its required
`PHASE5_NOTIFY_UNIT`, failing that prerequisite. It is not a product failure
and is not counted as an overall passing run.

[The full host run](../scenarios-20261031T120932Z-3826812/run.log) passes all
25 scenarios in 164.59 seconds. controller.log retains its `SCENARIO_RESULT=0`
marker. [The strict rule map](rulemap.log) still fails, exit 101:
343 total / 333 active / 312 cited / 21 missing. No strict CI flag is enabled.

`revision` and `source.patch` identify the tested source; source-identity.log
checks that snapshot and records the static artifacts' hashes. docs-checks.log
checks local Markdown file targets and diff whitespace, excluding web URLs and
anchors. Cargo build durations and unrelated manager resource summaries are
omitted from archived logs.

The strengthened live cases still need the other four required kernels and
current-code Incus/root-manager refreshes. Complete event/resource/history
proof, remaining clauses, combined coverage and final strict CI remain open.
