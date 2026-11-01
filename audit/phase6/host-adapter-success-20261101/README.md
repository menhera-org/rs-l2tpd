# Successful host adapters

The binary tests now exercise capability reporting against the actual
effective bits, successful descriptor-store processing through the host
worker, and an allowed bindv6only write in a disposable network namespace.
The existing file-backed tunable case also proves that an already-correct
value keeps its deliberately fixed modification time.

`revision` identifies signed fb0620d; `source.patch` changes test-only code
in caps.rs, fdstore.rs and tunable.rs. Production code, APIs and dependencies
are unchanged. Ten native and ten instrumented binary repetitions with
distinct TEST_SEED values pass, as do three musl repetitions and final
common checks. The binary has 65 ordinary cases and five ignored cases.

Three GNU and three musl container repetitions each pass all 65 ordinary
cases, the dedicated namespace case, and capability reporting with all
capabilities dropped. Privileged and capability-dropped fixtures supply
independent expectations for the three required capability bits. Warnings
must name each missing capability and its consequence exactly once at
warning level. The store fixture verifies datagram order, transferred
Unix-stream data, descriptor release, and the exact successful completion ID.

Three additional namespace repetitions for each target start the enclosing
container at bindv6only=1. The inner namespace is cleared to zero; after
restoration the enclosing namespace still holds 1. Seven production
controls fail: fabricated capability bits, inverted warning selection,
false withdrawal acknowledgement, omitted storage, a leaked duplicate,
a refused allowed write and an unnecessary write. A separate fixture
control omits unshare and fails the enclosing-value assertion with 0
instead of 1. All controls are isolated and uninstrumented; their sources
are restored and no control profiles enter the collector.

The initial combined-container run passes every test but its collection
guard expects two one-case result lines and finds three, including an
existing nested case. The corrected runner records separate case logs and
checks each result. Initial logs and initial-source.patch remain; the initial
combined-container raw profiles are outside the accepted collector. Final source.patch also
adds the independent capability-mask expectation.

All 4,320 complete production mappings remain identical. Coverage reaches
8,434/8,671 lines (97.27%) and 1,679/1,850 branches (90.76%), leaving
237 lines and 171 branches. There are no production exclusions, profile
mismatches or saturated regions. caps.rs has complete line/branch coverage;
fdstore.rs has complete line coverage and one missing branch; tunable.rs
has complete branch coverage and one missing line.

Live scope is Ubuntu 6.8.0-147-generic with GNU/musl in disposable
networkless containers. The matrix frozen at fb0620d is running separately
and excludes these later declarations. Complete clause/history/resource/
event-cost proof and 100% coverage remain open.
