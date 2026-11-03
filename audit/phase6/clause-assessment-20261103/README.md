# Phase 6 clause assessment

This assessment is for signed commit
`9e6aae63ec43166941a14fed8883547ead7dc4f0`. Its source patch is empty.
The strict map reports 343 numbered rules, 333 active rules, all 333 linked to
test declarations. The source-link map reports 43 kernel facts, 37 with Linux
production citations, six with the approved delegated/source-only evidence,
and no uncited `kernel::linux` function. The retained logs are the executed
strict commands, rather than summaries copied from an earlier revision.

The review compared each active specification row and each independent clause
with the assertions in its cited tests, then checked that the required suite
containing those tests appears in the final CI, matrix or host records. A
lexical citation was not accepted as proof. Multi-clause rules use the
following evidence families:

| Contract family | Independent evidence |
|---|---|
| Configuration and diagnostics | parser and merge cases, retained-value reloads, process `--check` cases, malformed and unreadable file fault cases |
| Kernel boundary | shared fake/live conformance, Linux adapter unit cases, ignored live cases executed explicitly, source classifications and the five-kernel matrix |
| Reconciliation and ownership | rule cases, seeded properties, lifetime generation and capture cases, event-loss and full-inventory cases |
| Process and library | service/runtime cases, syscall fault children, process cases in every normal matrix profile, descriptor-store and restart scenarios |
| Host promises | 27 scenarios on each required kernel, special boot profiles, three unprivileged Incus repetitions and the root-systemd guest |
| Cost and retention bounds | allocation fixture on GNU and musl, source-work cases, event-cost cases, the 300-entry scale scenario and mutation controls |

The review found the S8 creation-name capture race recorded in
`../creation-capture-ordering-20261103/`. Commit `f744335` fixes the ordering;
commit `9e6aae6` adds the missing failure-path coverage. The final CI, complete
kernel matrix, three host repetitions and root-unit profile all use that
source. No later clause defect remained open.

Several rules require combined evidence and deserve explicit treatment:

- **S16/O5:** `cookies_are_never_formatted` proves that valid configuration
  cookies expose only their length. `reported_cookies_preserve_foreign_lengths`
  and `every_foreign_cookie_length_is_read_without_relaxing_configuration`
  do the same for every kernel-reported length. The process configuration
  cases prove that invalid TOML and omitted-entry diagnostics redact source
  values. The production coverage report executes every remaining report and
  log construction path. No path formats cookie bytes.
- **R16/V15:** the retained-answer rule case covers negative and reordered
  replies. Worker cases exhaust the eight system slots, retain permits for
  stalled calls, admit configured DNS from its separate budget, and release
  permits after spawn errors. Process and service cases separately establish
  readiness and bounded shutdown.
- **G23/M16:** the allocation and source-work fixtures measure retained
  configuration/dependency state and per-event work. Their fault controls
  reject full temporary inventories, global scans, disabled peak accounting
  and missing deallocation. Scale and event-loss scenarios exercise the same
  paths with the live kernel.
- **H6:** virtual-clock cases assert the exact one-second retry deadline. Live
  cases assert completion within their fixture bound and record the observed
  scheduling delay, following the approved deadline/completion distinction.
- **H11/S12/G4:** the Incus cases separately cover concurrent udev/networkd,
  ordered persistent assignment, and configured MAC authority through an
  explicit `MACAddressPolicy=none`. Later manager assignments stay
  authoritative; the daemon never lowers an active link to overwrite them.
- **K26/K34:** Ubuntu kernels return `EADDRNOTAVAIL` for the empty-VRF IPv6
  connect tested here; vanilla 6.8.12 returns `ENETUNREACH`. Both precise
  refusals enter the same transient disconnected state, as documented and
  asserted per target.

The ten-seed fake/live CI qualification in
`../strict-gates-20261031/` passed before strict enforcement was enabled.
Regular CI retains one complete guest per change. The final exact-source run
is retained in `../ci-coverage-9e6aae6-20261103/`; the required matrix is in
`../matrix-20261103T090121Z-983779/`; the final host repetitions are in
`../final-hosts-9e6aae6-20261103/`.

Earlier failed collectors, coverage attempts and parallel clock experiments
remain failures in their original records. Desired Debian/RHEL-family and
intermediate-vanilla coverage was not run and is not part of the required
Phase 6 exit set.
