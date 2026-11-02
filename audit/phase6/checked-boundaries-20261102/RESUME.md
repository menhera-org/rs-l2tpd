# Resume after the requested 10:00 UTC pause

The implementation checkpoint is signed `2c9995c`. The subsequent evidence
update changes no Rust code. Phase 6 remains incomplete.

Coverage is 8,634/8,705 lines (99.18%) and 1,780/1,840 outcomes (96.74%):
71 lines and 60 outcomes remain. The collector is
`target/phase6-coverage-checked-boundaries-20261102`. Import no profiles
from older production implementations. If production bodies change again,
start a new collector and qualify the changed code.

All thirteen required profiles pass, as do fresh GNU live/Incus,
three shipped-musl scenario/Incus pairs, manager/task-limit repetitions,
the unmodified root unit and three GNU buffer-force guests. The five
mutation controls are restored. The fork-limit fixture is deferred after
its setup failed; its retained source is evidence, not a shipping test.

First check the implementation commit's
[CI run](https://github.com/menhera-org/rs-l2tpd/actions/runs/41423332510) and
[CodeQL run](https://github.com/menhera-org/rs-l2tpd/actions/runs/41423332486).
A running workflow is not a passing gate. Recheck publications if required
targets change.

Use the missing-line report and exported branch coordinates to prepare
another substantial batch. Remaining areas include lifetime-reader
stop/reopen/timeout and generation races, foreign session filtering,
readiness/reload shutdown ordering and defensive reconciler states.
Validate the actual condition and column before writing a fixture;
an aggregate line alone can obscure the missing outcome.

The complete clause/history/resource/event-cost proof and final 100%
enforcement in CI remain separate obligations. Do not turn source-map
citations, synthetic faults or an unsuccessful fixture into a broader
live-kernel claim.
