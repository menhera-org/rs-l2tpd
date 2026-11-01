# Upstream receive-overflow fixture

The four native Linux jobs for [nix PR #2852](https://github.com/nix-rust/nix/pull/2852)
pass the new signal regression but fail the unchanged receive-overflow test.
Each reports two drops where the fixture expects one. The old job excerpts
retain the assertion and each suite's pass/fail/ignored counts.

The fixture assumes two 2 KiB datagrams fit in its requested receive buffer.
Linux accounts packet allocation size. The
[Linux v7.0 UDP enqueue path](https://github.com/torvalds/linux/blob/v7.0/net/ipv4/udp.c#L1714-L1776)
checks that size against the buffer and records a drop-count snapshot when
enqueueing a packet. A fixed packet-capacity assumption is not portable
across that accounting.

[Independent PR #2853](https://github.com/nix-rust/nix/pull/2853) reads the
effective buffer capacity, sends enough payload to overflow it, and counts
received packets in the first burst. The next burst must report exactly the
observed earlier loss. It requires positive loss and received payload; a
missing or incorrect counter fails. No library implementation changes.

## Controls and CI

All local networking runs inside disposable Docker containers with
`--network none`, on Ubuntu 6.8.0-147-generic.

| Local case | Reported buffer | Burst | Expected / reported loss | Result |
|---|---|---|---|---|
| Final GNU fixture | 8,192 bytes | 6 | 4 / 4 | Three pass |
| Final musl fixture | 8,192 bytes | 6 | 4 / 4 | Three pass |
| Reduced-buffer musl control | 4,096 bytes | 4 | 3 / 3 | Three pass |
| Old fixture, reduced-buffer control | 4,096 bytes | 3 | Hardcoded 1 / actual 2 | Fails as expected |

The reduced-buffer old-source control reproduces the capacity assumption;
it is not a claim that this host runs the CI kernel. Formatting passes.

All four native jobs pass in
[run 41254219217](https://github.com/nix-rust/nix/actions/runs/41254219217):
x86_64 GNU (385 passed / four ignored), x86_64 musl (356 / 25), ARM64 GNU
(374 / four) and ARM64 musl (363 / twelve). Those are the main upstream test
executable counts. The excerpts also retain other executables and doctests;
ignored cases are not counted as passes. At the November 1 check, all 30 jobs
returned by the upstream run-jobs API pass, including its cross-target,
macOS, FreeBSD and Solaris jobs. Their checks retain their own platform scope.

The proposal is based on upstream
`89339c618783622e3cdd8d7a6b17319a65337e94`. Final signed commit
`2a5e9cddf03f7e9ba11a5cf04ef78036a04480e6` names the changelog after PR #2853.
`upstream.patch` is the complete fixture proposal. It is independent of the
signal-library fix; PR #2852 still needs the fixture correction integrated
upstream before its full CI can pass.

## Downstream status

No daemon dependency or specification changes. A compatible published signal
fix is still required before the pending daemon signal-fault cases can run.
Phase 6 also awaits the H11/G23 decisions, final qualification, full clause/
resource/event-cost proof and 100% production coverage. Cargo build durations
are omitted from retained local logs.

```sh
# In the upstream checkout:
cargo test --target x86_64-unknown-linux-musl --test test --no-run
# Run the printed binary in a networkless container:
# --exact sys::test_socket::test_recvmsg_rxq_ovfl --nocapture
cargo fmt --all -- --check
```
