# Upstream DHCPv6 namespace isolation and listener-cache cleanup

`iphost` **0.4.2 is published and pinned**. Signed upstream commit
[`9674ff6`](https://github.com/metastable-void/iphost/commit/9674ff6731a063d04f3182f1f853084c0bf72c15)
fixes DHCPv6 listener reuse across network namespaces and releases dead
listener-cache records. [Publication](publish.log),
[signature/sign-off](upstream-commit-identity.log),
[downloaded VCS identity](released-vcs.json) and
[package digest](released-package.log) identify the release.
[Source checks](source-checks.log) compare the downloaded DHCPv6 source
with that commit. The daemon uses the registry release, with no path override.

The preceding daemon commit `902e3ba` passes CI build/coverage but fails
the shared-discovery case in the normal guest:
[CI 41226718700](https://github.com/menhera-org/rs-l2tpd/actions/runs/41226718700),
[job metadata](ci-jobs.json), [guest log](ci-guest-failed.log).
Its initial RA-only assertion fails because an earlier test's live DHCPv6
listener is reused in a new namespace with the same interface name.

The focused [upstream baseline](upstream-baseline-live.log) reproduces
that reuse while both namespaces' listeners remain alive. It also checks
sharing within each namespace. The test-only
[regression patch](upstream-regression.patch) applies to upstream
`34b6e2c` (`0.4.1`). An intermediate namespace-keyed proposal still leaves
dead cache records; [that regression](upstream-cache-before-live.log)
fails after five seconds even though the listener has no strong owner.
[Its exact source](upstream-cache-before.patch) is retained.

The release keys listeners by namespace and interface using ordered maps.
Linux/Android use `SO_NETNS_COOKIE`, with a namespace-inode fallback only
when the kernel reports that option unsupported. The required kernels
therefore need neither procfs nor extra privileges. Other platforms retain
interface-based sharing. A listener removes its own cache entry on drop;
an old listener cannot remove its replacement. Receiver-spawn failure
unlocks the cache before destroying the partial listener and closes its socket.

Five live upstream probes pass in each of three final runs:

- Same interface name in two network namespaces creates distinct listeners;
  repeated construction in one namespace shares its listener.
- Dropping the last listener releases its global cache record.
- Namespace cookies work inside an empty chroot without `/proc`.
- Refusing the cookie option with `ENOPROTOOPT` exercises the legacy
  namespace-inode fallback and preserves namespace isolation.
- Three consecutive refused receiver-thread spawns return `EAGAIN`,
  leaving no socket, cache entry or locked registry behind.

[Final run 1](upstream-final-live-1.log),
[run 2](upstream-final-live-2.log) and
[run 3](upstream-final-live-3.log) each execute all five probes.
Earlier three-run logs cover the namespace-only proposal and then its
four-probe extension; they remain separate from the final five-probe results.

| Upstream check | Result |
|---|---|
| All-feature tests and docs | 58 ordinary unit and three doctests pass; five unit and 19 integration live cases explicitly ignored in the ordinary run |
| Rust 1.89 | Same ordinary tests and doctests pass |
| No defaults | Four unit and one doctest pass |
| Custom only | 30 unit and one doctest pass |
| RA only | 48 unit and three doctests pass |
| DHCPv6 only | 42 unit and three doctests pass |
| RA + DHCPv6, no defaults | 56 unit and three doctests pass |
| Formatting, Clippy, warning-denied docs | Pass, including final release checks |
| Existing API consumer | Compiles; public signatures are unchanged |
| Cross-target checks | Windows MSVC, Intel/ARM macOS, FreeBSD, NetBSD, illumos, ARM64/PowerPC64LE/RISC-V64 Linux musl pass |
| Existing Linux binding suite | 18 privileged and two unprivileged cases pass in 10.62 and 8.01 seconds |
| Publish verification | Both dry runs pass; clean signed source publishes as 0.4.2 |

Feature logs state their ignored live counts. Cross-target checks compile
the library; they do not execute another operating system. No external API
compatibility tool was installed. The existing consumer and unchanged
public declarations provide the compatibility check. All functional checks
initially ran before the version-only bump; release unit/lint/doc/package
checks then ran at 0.4.2. The live fixture uses signed Alpine packages in
a prepared image; its network setup and assertions are unchanged. Only the
in-container package download is removed from
[linux-bind-prepared.sh](linux-bind-prepared.sh). The container runs with
`--network none`; [image recipe](Dockerfile.live) and
[package paths](live-package-paths.log) are retained.

The old-kernel fallback is fault-injected on Ubuntu `6.8.0-147-generic`,
not executed on a pre-cookie kernel. Such kernels require readable
`/proc/thread-self/ns/net`; inability to identify the namespace is an error.
Native execution on other operating systems remains unchecked. This release
does not establish complete discovery-resource or event-cost proof.

Downstream common gates and all ten seeds pass: 109 ordinary library,
68 fake, 78 rules, 27 service cases and eight startup/resolver faults per seed.

| Fresh downstream profile | Result |
|---|---|
| Native all-feature coverage | Pass; live tests explicitly ignored |
| Live GNU probes | 12 library, 19 kernel, five review and three privileged binary cases pass |
| Full process suite | 27 pass |
| Normal GNU scenarios | All 26 pass in 158.46 seconds |
| Real user manager | FD-store barrier and address-family assertions pass |
| Instrumented unprivileged Incus | Full case passes in 19.74 seconds; seven daemon profiles exported |
| Unmodified musl normal guest | All probes and 26 scenarios pass; scenarios take 575.52 seconds |
| Unmodified musl Incus | Full P5 case passes in 14.62 seconds; container deleted |
| Unmodified musl root-systemd | Full P6 case passes in 25.88 seconds with no drop-ins |

[Native](native.log), [live](live.log), [manager](manager.log),
[coverage Incus](incus.log), [normal guest](normal-guest/README.md),
[unmodified Incus](../incus-20261031T183522Z-163634/README.md) and
[root-systemd](root-systemd/README.md) retain the results. Both Incus runs
observe EBUSY in the concurrent MAC-write race and persistent addresses on
both ordered creations. The root guest's concurrent creation gets the
persistent address. The approved H11 limits remain in force.

Fresh merged coverage is **93.32% of production lines** (7,868/8,431)
and **80.95% of branches** (1,436/1,774), leaving **563 lines and
338 branches**. [Merged report](merged.log) and [counts](counts.log)
contain no production exclusions or profile-mismatch warnings. The fresh
target excludes earlier profiles and retains the approved exclusion of
47 test-only modules and one helper while running every test.

A subsequent subscriber-lifecycle probe still finds closed subscriber
records and an unbounded pending-datagram queue. That separate upstream
work is under `audit/phase6/upstream-dhcp-queues-20261031/`; this release
does not close G23. Remaining coverage, clauses/event cost and the final
five-target matrix also remain open. This package needs its own CI result
after commit.

`revision` plus `source.patch` reconstruct the daemon
tree; `upstream-revision` plus `upstream-final.patch` reconstruct the upstream
release. Controller path mistakes remain separate from actual test failures.
Cargo build durations and download progress are omitted.

```sh
# In the upstream checkout:
cargo test --locked --all-features
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo +1.89.0 test --locked --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --all-features --no-deps
cargo test --locked --all-features --target x86_64-unknown-linux-musl --no-run
# Run the unit test executable's ignored tests in a privileged,
# networkless disposable container, three times.
cargo publish --registry crates-io --dry-run
cargo publish --registry crates-io

# In the daemon checkout:
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-iphost042-final-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/upstream-netns-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/coverage-current-20261031/run-live.sh
sh audit/phase6/coverage-current-20261031/run-incus.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
sh tests/kernel/run-guest.sh IMAGE MODULES CONFIG normal RECORD
tests/docker/run.sh incus
sh tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD
```

For the real-manager profile, `BINARY` is the instrumented binary test
executable listed in `native.log`:

```sh
unit=phase6-iphost042-manager-20261031
systemd-run --user --no-pager --wait --pipe --collect --unit="$unit" \
  --property=Type=notify --property=NotifyAccess=all \
  --property=FileDescriptorStoreMax=8 --property=NoNewPrivileges=yes \
  --property=RuntimeMaxSec=30s \
  --property='RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6' \
  --setenv="PHASE5_NOTIFY_UNIT=$unit.service" \
  --setenv="LLVM_PROFILE_FILE=$CARGO_LLVM_COV_TARGET_DIR/manager-%p-%m.profraw" \
  "$BINARY" --ignored --exact fdstore::manager_tests::actual_manager_processing_and_address_family_filter --nocapture
```
