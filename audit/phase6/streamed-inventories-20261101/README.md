# Streamed link and address inventories

The approved G23 bound counts current dependency state, not completed
history or unrelated host state. The daemon still collected every link or
address into a temporary vector before selecting its dependencies. This
change sends inventory records through visitors, using the existing
netlink request transport and its completion/error contract.

`Kernel::scan_links` and `scan_addrs` are the streaming primitives. The
Linux and fake adapters implement them; the service test adapter forwards
them. Existing public `dump_links` and `dump_addrs` still collect an owned
inventory when a caller requests one. The reconciler uses
only streaming primitives; no dependency is added.

The monitor resync first retains configured/owned indices. If their VRFs
or parents require another pass, it streams those dependencies separately.
Members may precede their VRF in kernel order. No unrelated member or
address is retained. VRF discovery stages only matching member indices;
address seeding stages only the watched devices' canonical addresses.
Staged state is committed after successful completion. The existing
transport still validates framing, sender, sequence, dump completion and
absolute deadlines.

## Regression evidence

Two new resource tests cover:

- One configured tunnel with 1, 100 and 10,000 direct-device addresses or
  VRF members/addresses, alongside unrelated host state. Members have lower
  indices than the VRF. Resync preserves the expected retained counts;
  removing the final dependency releases all 32 tracked cache/index/queue
  counts and every deadline.
- Failure after records were visited but before inventory completion, at
  initial VRF discovery, either resync link pass and address seeding. Failed
  link inventories preserve the prior completed state; failed address
  seeding commits no visited addresses. A one-second retry recovers.

The fake's one-shot `dump-end` fault represents refused completion after
visited records. The negative control commits addresses inside the visitor
before completion; the final regression fails its empty-cache assertion.
`negative-control.patch` reconstructs it against the candidate source.

These assertions measure retained records, not byte-level allocator or RSS
peaks. The fake owns the simulated host inputs separately from the daemon
caches. Temporary filtering is also established by the production visitor
paths; the H17 live resource envelope remains a separate check.

## Verification

`revision` plus `source.patch` identifies the final implementation and
fixtures. Ten seeded suites pass: 131 ordinary library, 51 binary, 68 shared
fake cases plus six fake-only cases, 87 rules, 30 service cases and startup
faults. Three musl library/fake/rule suites, common strict checks, Clippy,
feature builds and rustdoc pass. ARM64, RISC-V64 and PowerPC64LE musl
all-target/all-feature checks pass; they are compile checks only.

Fresh instrumented GNU collection passes 14 privileged library, 20 Linux,
five review, three privileged binary and 28 process cases. All 26 normal
scenarios pass in 172.32 seconds. The real user-manager processing/filter
case passes. The full unprivileged Incus case passes in 8.95 seconds and
exports seven daemon profiles; its container is deleted. The unmodified
stable musl root-systemd case passes in 26.64 seconds,
`ROOT_SYSTEMD_RESULT=0`.

Three unchanged stable musl normal suites pass serially in **158.12,
162.29 and 157.99 seconds**. The first attempted overlap with GNU scale
traffic fails its single-packet check at session 196, side 0; that full
transcript remains in `parallel-host-failure/`. No packet assertion or
normal timing allowance is changed. The separate
[neighbour-pressure control](../neighbour-pressure-20261101/README.md)
reproduces this failure mechanism inside a disposable guest and establishes
why host-kernel scale workloads run serially.

Fresh production coverage is **95.51% lines** (8,193/8,578) and **86.17%
branches** (1,577/1,830), leaving **385 lines and 253 branches**. Only this
production implementation's profiles contribute. There are no production
exclusions, profile mismatches or saturated inferred regions. Test-only
instrumentation exclusions retain the approved scope. Cargo build lengths
and host user-manager resource accounting are omitted from retained logs.

The isolated earlier suites/Clippy precede the final initial-VRF failure
subcase; `isolated-resource.log`, the final negative control and the main
collection include it. 
The final five-target matrix, upstream compatible nix release, complete
clause/resource/event-cost proof and 100% coverage remain open. Existing
collecting callers keep their signatures; custom Kernel adapters implement
the two new visitor primitives.

```sh
./test-ci-gates.sh
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
cargo test --locked --all-features --target x86_64-unknown-linux-musl --lib --test kernel-fake --test rules
# Repeat three times.
tests/docker/run.sh scenarios
# Repeat three times serially, after any GNU host scale workload finishes.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-streamed-inventories-20261101"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/streamed-inventories-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/process-errors-20261031/run-live.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
# Root guest command and artifact identities: root-systemd/command.log and artifacts.log.
```
