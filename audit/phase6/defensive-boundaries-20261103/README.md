# Defensive boundaries and merged-source coverage

Base: signed `6735dd6`. The accompanying source patch records this batch.
Phase 6 remains open.

The calibrated checker reports **8,441/8,441 merged source lines and
1,834/1,840 condition outcomes**. It exits **1**, with six outcomes missing.
The retained raw LLVM report is **8,655/8,707 lines (99.40%) and
1,800/1,840 outcomes (97.83%)**. These are different measurements; the raw
summary is not replaced or described as complete.

`merged-source-coverage.log` identifies every missing condition, including
its function owner and repeated-span occurrence. The compressed full LLVM
export retains per-instantiation counters; the compressed inventory retains
source blob IDs and mappings. `coverage-digests.log` identifies both inputs.
This inventory was captured after collection, with the known source patch;
it does not retroactively establish a before-build snapshot. Future
collections must capture and preserve an unchanged build's inventory before
adding profiles. No production exclusion is added.

## Changes and their scope

- A real netlink socket filter preserves ACKs and drops family data. Two
  requests return EPROTO without populating the cache; unfiltered controls
  resolve the family before and after. This tests the missing-data path,
  not the request transport-error path.
- A separate expired uncached request returns ETIMEDOUT twice and keeps an
  empty cache. A restored fault control that swallows the transport error
  fails this test with EPROTO.
- Private malformed-state fixtures cover a link-local resolver without a
  scope and a session without its cached current name. They explicitly
  bypass private invariants; they are not valid public configurations.
- The shared exec-worker panic conversion returns the original error kind
  and message and drops a real joined thread's socket-owning panic payload.
  This tests the shared handler directly; it does not force the daemon's
  private exec worker to panic.
- The instrumented library reuses the 36 public service tests, retaining
  the existing integration target.

The only production change extracts the existing exec panic conversion
into a shared private function without changing its result or payload drop.
The fresh collector does not import profiles from the preceding production
mapping.

## Executed evidence

| Collection | Result and scope |
|---|---|
| `final-common.log` | Mandatory common gates pass, including strict rule/source maps and warning-denied docs; eight checker tests pass on GNU and musl |
| `instrumented-21.log` through `instrumented-30.log` | Ten complete instrumented ordinary suites pass: 349 library cases, 81 binary cases and the integration targets |
| `instrumented-cold-family.log` | Complete instrumented ordinary suites pass after the final uncached-family test: 350 library cases |
| `instrumented-live-{1,2,3}.log` | Three GNU collections each pass 349 ordinary plus 58 ignored library cases, 81 ordinary binary cases and all 37 process cases |
| `container-TARGET-{1,2,3}.log` | Three collections per stable libc each pass 313 ordinary plus 30 ignored library cases, 81 binary cases and all 37 process cases |
| `final-common.log`, `final-musl-library.log` | Final stable ordinary library count is 314 after the uncached-family test; both libcs execute it |
| `external-live.log` | GNU: 24 Linux cases, 5 review cases, 3 binary filesystem cases and 27 scenarios pass |
| `gnu-incus.log` | Fresh unprivileged GNU system-container scenario and buffer fallback pass; seven daemon profiles imported after success and container deletion |
| `manager-{1,2,3}.log`, `thread-limits-{1,2,3}.log` | Three GNU manager and task/fork-limit collections pass |
| `request-force-{1,2,3}.log` | Three instrumented GNU buffer-force guests pass |
| `inventory-resolute.log` | Instrumented Ubuntu 7.0 inventory guard passes three times |
| `root-systemd.log` | Shipping runner's unmodified root system-unit profile passes on Ubuntu 6.8 |
| `library-no-default.log`, `library-serde.log`, `msrv.log`, `cross-*.log` | Optional library configurations, Rust 1.89 and three additional musl architectures check successfully |

Six initial restored controls reject ACK-filter bypass, invented family
data, removed scope validation, invented swap ownership, leaked panic payload
and a panicking error converter. The final uncached-family control also
fails its intended assertion. `commands-*.txt` retain the collection drivers.
Profile transport stages outside the collector and imports only after success.

The initial common check rejected an uncited socket-filter helper; its K10
citation is corrected. The first cached-name selector ran zero tests; the
corrected exact selector executes one passing test. The first Incus controller
used an invalid name and created no container; the final controller fixes
the expansion and passes. Those attempts remain recorded.

This batch does not replace the earlier full required-kernel matrix or settle
its retained clock/emulator failures. The complete claim/history/resource/
event-cost audit and the production 100% CI job remain unfinished.
