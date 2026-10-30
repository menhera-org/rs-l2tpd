# F1 and F2 entry fixes, 2026-10-30

Scope: the two Phase 6 entry defects in
[the Phase 5 completion review](PHASE5_COMPLETION_CONFORMANCE_2026-10-30.md#f-follow-up-after-the-fix-commit-6075fde).
F3–F7 and the six Phase 6 gates remain separate work.

## Changes and regression evidence

- **F1:** the production address-dump collector checks the family before
  interpreting address attributes. Foreign families are skipped; an empty
  payload or an undecodable IPv4/IPv6 record still returns `EPROTO`.
  Link-dump validation is retained. The dump collector regression feeds
  IPv4, MCTP, Phonet and IPv6 records through the production callback,
  verifies that both IP records survive, and checks truncated headers,
  short address attributes and unrelated message types.
- **F2:** `recreate_session` releases only the absent session's name
  reservations before creation. Both callers have just confirmed that
  session absent. The extended
  `direct_creation_and_recreation_preserve_publication_rules` checks
  link-removal, L2TP-deletion and a failed-then-retried verification,
  with and without a configured hardware address. It asserts the stored
  creation name, absence of a rename for direct creation, and address-before-
  rename ordering for staging.
- The new ignored live test
  `event_recreation_uses_the_configured_creation_name_on_linux` deletes
  a real session through `ip l2tp`, consumes each subscription type
  independently, and checks the replacement device's new index and its
  kernel-stored creation name. It uses a private network namespace and
  a two-second deadline.

Both targeted regressions were run before the behavioral fixes and failed:
[F1](phase6/f1-f2/regression-f1-before.log) returned `EPROTO` on a
foreign-family record; [F2](phase6/f1-f2/regression-f2-before.log) found
a staging creation name after a monitor deletion. For F1 the unchanged
dump callback had first been extracted into the collector used by the test.

Source checks: `net/core/rtnetlink.c:rtnl_dump_all` walks registered
families for an AF_UNSPEC address dump; IPv4/IPv6 producers use
`ifaddrmsg`. MCTP's `mctp_fill_addrinfo` and Phonet's `fill_addr`
emit one-byte addresses. The production collector carries K7/K29 source
citations. Sources inspected:
[Linux v6.8 rtnetlink](https://github.com/torvalds/linux/blob/v6.8/net/core/rtnetlink.c),
[v6.8 MCTP](https://github.com/torvalds/linux/blob/v6.8/net/mctp/device.c),
[v7.3 Phonet](https://github.com/torvalds/linux/blob/v7.3/net/phonet/pn_netlink.c),
and [v6.8 family identifiers](https://github.com/torvalds/linux/blob/v6.8/include/linux/socket.h).

## Verification

All commands used rexec. Live runs used kernel `6.8.0-147-generic`;
all containers were disposable, privileged and used `--network none`
with a read-only checkout mount. Host networking was not changed.
Each passing log records the exact command, explicit environment,
kernel, feature set, exit and elapsed seconds. Tests use the default
native glibc target or `x86_64-unknown-linux-musl` as stated below.
Cargo commands use `--locked`; all-features unless a row says otherwise.

| Check | Result | Log |
|---|---|---|
| `cargo fmt --all --check` | pass | [fmt](phase6/f1-f2/fmt.log) |
| `cargo clippy --all-targets --all-features -- -D warnings` | pass | [Clippy](phase6/f1-f2/clippy.log) |
| Library build, no default features | pass | [build](phase6/f1-f2/build-nodefault.log) |
| Library build, no defaults + serde | pass | [build](phase6/f1-f2/build-serde.log) |
| Docs with warnings denied | pass | [docs](phase6/f1-f2/docs.log) |
| `cargo test --all-features` | pass; counts below | [native](phase6/f1-f2/test-native.log) |
| Musl build of all tests | pass | [build](phase6/f1-f2/build-musl-tests.log) |
| Musl binary and ordinary process tests | pass: 38 binary, 8 process | [musl](phase6/f1-f2/test-musl-bin-process.log) |
| Rules, fake conformance, service ×10 | pass each time: 73, 1, 23 | `phase6/f1-f2/determinism-{1..10}.log` |
| Native live kernel suites | pass: 9 production unit, 14 kernel integration, 5 review | [glibc](phase6/f1-f2/kernel-native.log) |
| Musl live kernel suites ×3 | pass each time: 9, 14, 5 | [run 1](phase6/f1-f2/kernel-musl-1.log), [run 2](phase6/f1-f2/kernel-musl-2.log), [run 3](phase6/f1-f2/kernel-musl-3.log) |
| Privileged process suite | pass: 18 on each libc | [glibc](phase6/f1-f2/process-native.log), [musl](phase6/f1-f2/process-musl.log) |
| Strict rule map | fail: existing 101 uncited rules | [strict rules](phase6/f1-f2/strict-rulemap.log) |
| Strict source links | fail: existing K13, K14, K33, K38, K40; zero uncited functions | [strict sources](phase6/f1-f2/strict-srclink.log) |

The ten repeat commands set `TEST_SEED` to 1000, 1032, 1064, 1096,
1128, 1160, 1192, 1224, 1256 and 1288; the property test exercises 32
seeds per run. No repeat failed. No strict CI flag was enabled.

Native ordinary counts: 75 library tests, 38 binary tests, one fake
conformance test, eight process tests, three rule-map tests, 73 rules
and properties, 23 service tests, two source-link tests and six doctests.
The binary and rules harnesses re-exec an individual child case; that child
is not counted again in these counts. Privileged tests are ignored by
ordinary Cargo runs and are counted separately above.

The first native and musl live attempts exposed a new fixture error
(missing `ip_version` for a peerless tunnel), before reaching its
behavioral assertion. Those logs are retained as
`kernel-native-fixture-error.log` and `kernel-musl-1-fixture-error.log`.
The fixture was corrected and both complete suites rerun successfully,
including all three musl repeats.

## Limits and remaining work

- Foreign-family address records are synthetic dump-callback inputs.
  Actual IPv4/IPv6 dumps ran against the live kernel; no live MCTP or
  Phonet address was provisioned.
- The new live test proves the creation name; it does not rerun udev's
  persistent-MAC policy experiment.
- No alternative-kernel/QEMU matrix, Incus/LXD, coverage collection,
  systemd descriptor-store suite or root unit sandbox was run for these
  entry fixes. The four unrelated ignored binary fixture tests were not
  rerun. The required kernel matrix and full path coverage remain Phase 6
  obligations.
- The strict failures are the documented entry gaps, not passing gates.
  F3–F7 remain unchecked. No specification was changed.

All live containers exited and were removed; `docker ps` showed no
remaining containers after the runs.
