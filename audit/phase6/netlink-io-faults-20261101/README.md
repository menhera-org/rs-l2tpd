# Netlink I/O faults and receive-buffer authority

Production code is unchanged from the signed revision in `revision`.
`source.patch`, `pre-guest-source.patch` and `final-source.patch` agree.
The final report covers **156/156 request.rs lines and 34/34 branches**.
The overall collector reaches **8,462/8,687 lines (97.41%) and 1,692/1,852
branches (91.36%)**, leaving 225 lines and 160 branches. All 4,311 production
mappings match the preceding checked-reply report. No production exclusion,
profile mismatch or saturated region is present. This is not the global
coverage gate.

The isolated request test denies receive or poll syscalls with seccomp,
checks interrupted polling, verifies ordinary receive-buffer fallback, and
requires exactly one warning when both buffer-setting calls fail. These
EIO/EINTR cases are injected failures, not observed natural kernel failures.
Three focused GNU, musl and instrumented repetitions pass. Ten native and
instrumented model/rule/service/startup repetitions and three musl model
runs pass. Three serial instrumented startup runs execute the existing
resource-failure cases. Common gates, Rust 1.89 and ARM64/RISC-V64/PowerPC64LE
musl compile checks pass; the latter are compile checks only.

Four independent uninstrumented controls fail when they discard receive
errors, discard poll errors, propagate interrupted polling, or suppress the
buffer warning. The shared capability helper copies the existing live
test's effective-only CAP_NET_ADMIN reduction. All 24 external Linux cases
pass three GNU and three musl runs; controls retaining that capability fail
on both targets. The full GNU live suite also passes. Local live scope is
Ubuntu 6.8.0-147-generic.

`run-qemu.sh` uses the existing GNU-compatible coverage image and the exact
instrumented library executable. Three fresh Ubuntu 6.8.0-147 guests pass
in `guest-final-1` through `guest-final-3`. Each guest limits only its own
ordinary receive-buffer maximum to 262,144 bytes, verifies the full doubled
8 MiB subscription request, and exports seven nonempty profiles through
9p. Accepted profiles are copied into the collector with distinct run names.
The reduced-buffer control fails with 8,388,608 versus 16,777,216 bytes.
Its uninstrumented output is not merged. The fixture requires successful
transport, both test results, the force marker, a zero guest result and all
seven profiles. There is no synthetic successful setsockopt result.

K36 explains the split: ordinary SO_RCVBUF is capped and doubled; FORCE
needs CAP_NET_ADMIN in the initial user namespace. `kernel-source.log`
records the relevant vanilla 6.8.12, 7.0.14 and 7.3 source excerpts and
hashes. The force probe's live result applies to the stated Ubuntu guest;
it does not add per-distribution manager or system-container results.

Three qualification corrections remain recorded:

- `witness-musl-error-wording.log`: musl renders EIO differently from glibc;
  the corrected assertion uses the target's own error text.
- `witness-test-logger-srclink.log`: generic test logging moved into the
  shared fault helper rather than acquiring false kernel citations.
- `guest-1`, `witness-marker-prefix.log` and `fixture-marker-fix.patch`:
  both guest tests passed, but the initial host wrapper rejected Rust's
  line prefix. That attempt's profiles remain outside the collector and
  do not count toward the three accepted runs.

`commands.log` and each guest's command/artifact log record reproduction.
The required-kernel matrix of the unchanged production source is sealed
separately. Full clause/history/resource/event-cost proof remains open.
