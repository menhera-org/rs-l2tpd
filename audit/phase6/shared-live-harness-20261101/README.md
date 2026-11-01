# Shared live-kernel coverage harness

The instrumented library compiles the same 24 Linux declarations as the
external kernel-linux target. This lets live successes and private refusal
cases exercise the same compiled library instance. Both declaration lists
compare exactly; the external target still runs. Production code, public
APIs and dependencies are unchanged.

`revision` identifies signed 77a7f4f; `source.patch` reconstructs the seven-line
test-only inclusion. The module exists only in the nightly coverage build,
its test bodies are excluded from instrumentation, and all its cases remain
in the serial ignored profile. No assertion or production exclusion changes.

The all-target native run and common checks pass. Ten instrumented library
runs with distinct TEST_SEED values and three musl library runs pass. The
full GNU live collection passes 46 serial library cases, 24 external Linux
cases, five review cases, three privileged binary cases, 29 process cases
and 27 normal scenarios. Two additional serial library repetitions pass
all 46 cases. The shared cases run on Ubuntu 6.8.0-147-generic in networkless
disposable containers. The completed required matrix at production 584062d
retains its separate scope; this inclusion does not claim another matrix run.

Coverage reaches 8,429/8,671 lines (97.21%) and 1,676/1,850 branches (90.59%),
leaving 242 lines and 174 branches. There are no production exclusions,
profile mismatches or saturated regions. Constructor counter snapshots
show both successful creation and socket refusal in the same cfg(test)
library instance, whereas the preceding snapshot separates them.

All 4,302 common mappings are identical. Two placeholder dump_links names
become concrete LinuxKernel names with identical source regions. Sixteen
other function instances are added. The executable line and branch
denominators are unchanged; the record does not claim identical catalogs.

Complete clause/history/resource/event-cost proof and 100% coverage remain
open. This change reuses existing tests; it adds no production behavior or
new fault fixture.
