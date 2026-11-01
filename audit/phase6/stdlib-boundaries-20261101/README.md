# Standard primitives at policy boundaries: local qualification

Request completion now uses AtomicUsize::fetch_update with checked subtraction,
replacing the manual weak-CAS retry loop. Ordering stays AcqRel/Acquire.
A method-scoped deprecation annotation preserves the Rust 1.89 MSRV:
that compiler rejects the newer try_update API. The initial common gate
caught this compatibility issue; its failure log is retained separately.
Each successful decrement releases one admission permit; a zero count does
nothing. The characterization test passes before and after the change:
four threads complete all admitted requests, then 1,000 extra completions
must leave both the zero count and capacity unchanged.

Check-mode output now passes through a private writer boundary. Rendering
errors leave the writer untouched, successful output preserves exact bytes,
and write errors retain their diagnostic context. The CLI still reports the
error and returns failure. Tests use a real TOML serialization error and a
standard slice writer with no remaining capacity.

Four controls fail: lost permits, permit over-release, swallowed rendering
errors and swallowed write errors. They run outside the coverage collector
and are restored before qualification. Each control patch applies after
`source.patch`.

`revision` identifies 0ea073d and `source.patch` contains these changes.
The complete tested tree also integrates released iphost 0.4.4 and its live
regression; `../iphost044-integration-20261101/` records that full source
and the passing repeated/native/musl/common/GNU-live qualification.
Three musl scenario/Incus repetitions and the required matrix remain open.

No public API, dependency or specification change is part of these boundary
refactors. The fresh collector reports 97.06% line / 90.05% branch
coverage; the earlier source's coverage totals remain historical.
