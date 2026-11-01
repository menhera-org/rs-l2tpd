# Complete barrier retry and tunable warning coverage

The existing barrier fault fixture now returns EAGAIN from read and requires
a timeout, preserved descriptor counts and a valid profile, just as it does
for interrupted reads. This proves the retry branch for WouldBlock. The
isolated tunable case enables the production logger; its container guard
requires exactly one warning for the 1-to-0 correction and none for the
already-correct value.

`revision` identifies signed b81bd40; `source.patch` changes only existing
test fixtures in fdstore.rs and tunable.rs. Production code, APIs and
dependencies are unchanged. Ten native and ten instrumented binary
repetitions, three musl repetitions and final common checks pass. The binary
still has 65 ordinary cases and five ignored cases.

Three GNU and three musl container repetitions pass all 65 ordinary cases,
the isolated tunable case, and capability reporting with all capabilities
dropped. Each ordinary log must contain exactly one verified marker for
each of seven barrier faults. Three further namespace cases per target
preserve the enclosing container's bindv6only=1 while clearing the inner
namespace. Each requires exactly one warning naming the previous value 1.

The WouldBlock-as-permanent-error control fails its Rust assertion. The
muted-warning control's Rust case passes, but the required output guard
fails: zero warnings instead of one. Its initial incomplete command did
not enforce the count and is retained separately, never counted as a
rejected control. Both final controls are isolated and uninstrumented;
the sources are restored and no control profiles enter the collector.

All 4,320 complete production mappings remain identical. Coverage reaches
8,435/8,671 lines (97.28%) and 1,680/1,850 branches (90.81%), leaving
236 lines and 170 branches. caps.rs, fdstore.rs and tunable.rs each reach
100% of production lines and branches. There are no production exclusions,
profile mismatches or saturated regions.

Live scope remains Ubuntu 6.8.0-147-generic with GNU/musl. The matrix frozen
at fb0620d is running separately and excludes these later fixture changes.
Complete clause/history/resource/event-cost proof and 100% coverage remain
open.
