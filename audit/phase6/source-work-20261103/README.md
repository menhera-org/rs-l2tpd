# Measured event-dispatch work

The permanent source-work runner passes ten repetitions of all eight
workloads at 1, 100 and 300 configured bindings: 240 actual test processes.
The [integrated collection](../resource-cost-integration-20261103/source-work-driver.log)
uses the final parser and fixture. The earlier four-workload qualification,
extended candidate qualification and deliberate failures remain here.

Each case builds its fake host and connected tunnels before taking a
profile snapshot, delivers 500 events, then takes another snapshot. The
checker requires identical source-region mappings and sums nonnegative
counter differences for daemon src/ regions. FakeKernel's host emulation
is excluded from this cost measurement; it remains included in P4 coverage.
Every original tunnel socket and connection must survive, readiness must
hold, and affected address/member cases require exactly 500 reconnects.

| Workload | Source-region executions at 1 / 100 / 300 bindings |
|---|---|
| Deliberate per-binding calibration | 1,500 / 150,000 / 450,000 |
| Unrelated link | 27,500 / 27,500 / 27,500 |
| Unchanged configured link | 52,500 / 52,500 / 52,500 |
| Actual rename away/back | 172,000 / 172,000 / 172,000 |
| One bound VRF member moves | 216,500 / 216,500 / 216,500 |
| One bound device's address churns | 152,500 / 152,500 / 152,500 |
| Unrelated address churn | 15,250 / 15,250 / 15,250 |
| One present tunnel's deletion is announced | 12,000 / 12,000 / 12,000 |

The final runner rejects a no-op loop over every configured tunnel: its
unrelated-link work rises from 28,500 to 78,000 at 100 bindings. The older
functional/cache witness still passes on that faulty source. Both the
initial control and final-runner control are retained, and all mutations
are restored. Production src/ is unchanged from e29c6f3.

Four parser tests pass on GNU and musl through the common checks. They
cover real deltas, changed mappings/schema, malformed coordinates/counters,
duplicate identities, unsupported layouts, overflow and the fake-host
boundary. The original two-test parser and first build's incompatible
--no-run/--no-report invocation remain as historical attempts.

Snapshots use LLVM's sized, initialized profile buffer and check its return
code before writing. The ABI is declared in
[InstrProfiling.h](https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/profile/InstrProfiling.h);
[LLVM's source coverage documentation](https://github.com/llvm/llvm-project/blob/main/clang/docs/SourceBasedCodeCoverage.md)
describes the profile/mapping export. The runner pins the same nightly
and LLVM tools as P4, uses one fixed binary, records source/binary hashes,
and requires all cases and final hash checks to pass. No cost profiles
are imported into the P4 coverage collector.

This measures executed source regions, not assembly instructions, standard
library internals, kernel work, RSS or wall-clock latency. It complements
existing zero-request spies, live netlink captures, history bounds and
semantic index tests; it does not independently prove every part of G12.
The profiling fixture runs on GNU. Ordinary shipped-musl behavior and the
parser's musl tests have separate qualification.

Full LLVM exports, test output and measured totals remain in their case
directories. JSON and profile buffers are losslessly xz-compressed where
present; decompress them before replaying the original command transcripts.
The permanent runner retains compressed full exports and removes redundant
runtime buffers after checking them. Cargo build-duration fields alone are
normalized in logs; counters and exported source paths are unchanged.
