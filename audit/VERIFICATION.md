# Verification

The final qualification run is pending on the current refactor. Earlier
checkpoint source `2ce54d2` passed the required matrix, coverage and container
gates; [signed records](https://github.com/menhera-org/rs-l2tpd/blob/3130f0fb24ebce016824224d04ca622743777210/audit/phase6/qlty-src-refactor/README.md)
retain its exact scope. They do not qualify subsequent changes.

The preliminary runs on `0301123` and `f5a2e7b` were deliberately stopped
when the requested scope and documentation paths changed. They are not passes
or regression findings. A fresh unchanged-source run must cover the common
gates, required and optional kernels, merged coverage, three scenario/Incus
pairs and the unmodified root systemd unit.

Current gating code lives in `tests/`, `tools/` and the repository root.
Historical evidence remains in Git before removal from the main tree.
Fetched kernel.org HTML is never committed. The [developer guide](../docs/developer.md)
defines acceptance and evidence scope.
