# Released DHCPv6 queue bounds and subscriber cleanup

`iphost` **0.4.3 is published and pinned** from signed upstream commit
[`91fd9f8`](https://github.com/metastable-void/iphost/commit/91fd9f881a76c7700583ce8720587c0060f6a61b).
[Publication](publish.log), [signature/sign-off](upstream-commit-identity.log),
[downloaded VCS identity](released-vcs.json) and
[package digest](released-package.log) identify the release. The downloaded
DHCPv6 source matches that commit; no path override is used downstream.

Two focused failures apply to released 0.4.2, after the namespace-cache fix:

- [Subscriber history](baseline-removed_subscriptions_do_not_wait_for_another_packet.log):
  with one surviving subscriber, creating and dropping 1,000 receivers
  leaves 1,001 cached senders. Cleanup previously waited for another packet.
- [Stalled receiver](baseline-stalled_subscriber_has_a_bounded_fifo.log):
  all 1,024 injected datagrams remain queued. The channel was unbounded.

The [regression patch](regressions.patch) extracts the unchanged fan-out
operation and adds those tests over upstream `9674ff6` (0.4.2). Both
baseline runs fail as expected on Ubuntu `6.8.0-147-generic` in disposable
networkless containers.

The release uses a 64-entry synchronous FIFO per client, with nonblocking
fan-out. Full clients drop incoming datagrams; other clients keep receiving.
A receiver owns its subscription record and removes it on drop, including
failed client-thread creation. An ordered map stores only current subscribers.
Public signatures, dependencies, packet validation and RFC 8415 retransmission
are unchanged.

The limit is **64 pending datagrams per client**, not reliable delivery under
arbitrary bursts. Each received datagram is at most the listener's 65,536-byte
buffer, so pending payload is at most 4 MiB per active client, plus channel
metadata. Kernel buffers, the current packet and discovery state have separate
bounds. The receiver releases its queue immediately on drop; a real discovery
client's background thread first notices that its configuration was released.
The tests allow that existing bounded cleanup interval.

Nine final live probes pass three times. They include the five namespace/cache
probes from 0.4.2 and four subscriber checks:

- 1,000 removed receivers leave one live subscriber, which still receives.
- A stalled receiver retains the first 64 packets in order. An active receiver
  receives all 1,024 packets; draining the stalled receiver restores delivery.
- Four epochs each create/drop 32 real discovery clients while one survives.
  After cleanup, the subscriber map returns to one and every removed client's
  shared state has zero strong references.
- Three refused client-thread spawns return `EAGAIN` and remove their
  subscriptions without waiting for traffic.

[Release run 1](release-live-1.log), [run 2](release-live-2.log) and
[run 3](release-live-3.log) retain the final nine-probe results. Earlier
seven- and eight-probe proposal logs are supplementary.

Upstream formatting, all-feature tests (58 ordinary unit cases and three
doctests), Clippy, warning-denied docs, Rust 1.89 and the existing API consumer
pass. No-default, custom-only, RA-only, DHCPv6-only and combined-feature tests
pass. Windows MSVC, Intel/ARM macOS, FreeBSD, NetBSD, illumos and
ARM64/PowerPC64LE/RISC-V64 Linux musl compile checks pass; other operating
systems are not executed. The existing Linux DNS/VRF/RA/DHCPv6 fixture passes
18 privileged and two unprivileged cases in 10.92 and 8.01 seconds.
The prepared networkless fixture/image from the preceding upstream record
is reused. Both package verification and publication succeed.

The preceding daemon [CI run 41230781172](https://github.com/menhera-org/rs-l2tpd/actions/runs/41230781172)
passes both jobs on their first attempts at `da65fc5`, including the normal
guest that previously failed. [Job metadata](ci/iphost042-jobs.json) is retained.

The initial fresh 0.4.3 collection misses one service-readiness branch that
the previous collection reached incidentally. A new test starts `run` without
a convergence waiter and queues a restart. The callback must observe the
accepted host setting, then shut down. This makes coverage of that ordering
deterministic. A draft fixture awaited asynchronous fake-kernel cleanup
without advancing its manual clock; [that failure](readiness-draft.log)
is retained. The existing physical-object startup test is unchanged.
The added test is in an already excluded test-only module; production bodies
and positions remain byte-identical. Final native profiles add it to the
fresh 0.4.3 collection. [Source checks](source-checks.log) record that boundary.

Common checks and all ten final seeds pass: 110 ordinary library cases,
68 fake cases, 78 rules, 27 service cases and eight startup/resolver faults
per seed. The earlier 109-case seeds remain separate. Musl process/startup,
strict maps, formatting, Clippy and warning-denied docs also pass.

| Downstream profile | Result |
|---|---|
| Final native all-feature coverage | Pass; every ordinary case and the new readiness test execute |
| Live GNU probes | 12 library, 19 kernel, five review and three privileged binary probes pass |
| Full process suite | 27 pass in 17.41 seconds |
| Normal GNU scenarios | All 26 pass in 159.62 seconds |
| Real user manager | FD-store barrier and address-family assertions pass |
| Instrumented unprivileged Incus | Full case passes in 8.59 seconds; seven daemon profiles exported |
| Unmodified musl Incus | Full P5 case passes in 11.91 seconds; container deleted |
| Unmodified musl root-systemd | Full P6 case passes in 27.27 seconds with no drop-ins |

[Native](native.log), [live](live.log), [manager](manager.log),
[coverage Incus](incus.log), [unmodified Incus](../incus-20261031T185702Z-200369/README.md)
and [root-systemd](root-systemd/README.md) retain the results. Both Incus
runs observe EBUSY in the concurrent MAC-write race and the same persistent
address on both ordered creations. The root guest's concurrent creation
gets the persistent address. The approved H11 limits remain unchanged.

Merged coverage is **93.32% of production lines** (7,868/8,431) and
**80.95% of branches** (1,436/1,774), leaving **563 lines and 338 branches**.
No production exclusions or profile-mismatch warnings occur. The initial
collection is fresh for the new dependency; only the subsequent test-only
readiness addition is incremental. The 47 test-only modules and one helper
stay excluded while all tests execute. Earlier dependency-version profiles
are not merged. The live kernel is Ubuntu `6.8.0-147-generic`; features
are `all`, coverage is GNU with pinned nightly-2026-10-28 and
cargo-llvm-cov 0.9.1; unmodified P5/P6 binaries are musl on stable.

No new local full normal QEMU run is claimed for 0.4.3. Its CI guest after
commit and the final consistent-source matrix remain required. The full
G23 inventory, remaining clause/event-cost proof and 100% coverage also
remain open. This record closes the two reproduced upstream gaps, not the
whole resource gate.

`revision` plus `source.patch` reconstruct the final daemon test tree.
`initial-source.patch` identifies the fresh live/root collection before the
test-only addition. `upstream-revision` plus `upstream-final.patch` reconstruct
the release. Earlier profiles and the readiness draft remain distinguishable.
Cargo build durations and download progress are omitted.

```sh
# Upstream:
cargo test --locked --all-features
cargo +1.89.0 test --locked --all-features
cargo clippy --locked --all-features --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --all-features --no-deps
cargo test --locked --all-features --target x86_64-unknown-linux-musl --no-run
# Run the unit executable's ignored tests in a privileged, networkless
# disposable container three times; run the prepared Linux binding fixture.
cargo publish --registry crates-io --dry-run
cargo publish --registry crates-io

# Daemon:
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --test kernel-fake --test rules --test service --test startup -- --nocapture
# Repeat with seeds 2 through 10.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-iphost043-final-20261031"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/upstream-dhcp-queues-20261031"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/coverage-current-20261031/run-live.sh
sh audit/phase6/coverage-current-20261031/run-incus.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
tests/docker/run.sh incus
sh tests/kernel/run-guest.sh IMAGE MODULES CONFIG systemd RECORD
```

The real-manager command uses the instrumented binary test executable
listed in `native.log` as `BINARY`:

```sh
unit=phase6-iphost043-manager-20261031
systemd-run --user --no-pager --wait --pipe --collect --unit="$unit" \
  --property=Type=notify --property=NotifyAccess=all \
  --property=FileDescriptorStoreMax=8 --property=NoNewPrivileges=yes \
  --property=RuntimeMaxSec=30s \
  --property='RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6' \
  --setenv="PHASE5_NOTIFY_UNIT=$unit.service" \
  --setenv="LLVM_PROFILE_FILE=$CARGO_LLVM_COV_TARGET_DIR/manager-%p-%m.profraw" \
  "$BINARY" --ignored --exact fdstore::manager_tests::actual_manager_processing_and_address_family_filter --nocapture
```
