# Probe I/O and event boundaries

This batch extends signed `449c751`. Production function bodies remain
unchanged. The merged collector covers **8,581/8,687 lines (98.78%)** and
**1,748/1,852 branch outcomes (94.38%)**. That adds 18 covered lines and
11 outcomes. All 4,331 production mappings remain unchanged; no production
exclusion was added. **106 lines and 104 outcomes remain uncovered.**

Seven isolated cases refuse nonblocking setup, probe reads (EIO, EINTR and
EAGAIN), wait, SIGPIPE installation and PID-file reads. Each asserts the
result before handover and checks that a caller descriptor remains usable.
The SIGPIPE refusal can occur while starting the compatibility probe; it
does not establish coverage of the later exec hook's separate error arm.

The existing syscall barrier forces a probe to finish between its first
read and its exit check. A split compatible version succeeds; oversized
remaining output is refused before another read. Read counts and release
markers ensure the fixture observed both paths. A five-second timeout also
bounds the disposable writer if its tracing parent fails.

Further cases check collector-error shutdown, logging after failed PID
inspection, a reload during an outstanding tunable write, a manager rename
before first publication, repeated address removal and loss of an unusable
VRF member. Connect EPERM/EAFNOSUPPORT diagnostics retain their errno and
retry on the same socket.

The final common gates, Rust 1.89 check and aarch64/riscv64gc/powerpc64le
musl compile checks pass. Ten instrumented fake repetitions and three musl
model repetitions pass. The first instrumented run also runs ordinary
suites; the final daemon source is separately qualified by three further
instrumented binary repetitions. Existing startup resource cases execute
separately in the serial instrumented profile.

Three GNU and three musl networkless containers each pass all 72 ordinary
daemon unit cases; five declarations remain ignored there. Every required
kernel also passes those 72 cases and the three selected filesystem cases:
Ubuntu 6.8.0-147.147 and 7.0.0-42.42, vanilla 6.8.12 and 7.0.14, and mainline
7.4-rc1. These binary profiles do not replace the full thirteen-profile
matrix or establish new scenario, Incus or root-unit scope. Guest source
starts at `guest-base-revision` plus `guest-source.patch`; it was compared
against every shipping Rust/test file before execution. `source.patch`
records this batch against `revision`.

Three isolated mutations fail at their intended runtime assertions:
removing the final probe-drain limit, omitting collector-error shutdown
and treating a staging rename as an authoritative published-name override.
Each mutation is restored. The control checkout's base and complete
candidate source patch are retained separately.

Rejected calibration records remain visible. The first diagnostic case
lacked a source address, so recovery could not connect; the corrected
fixture supplies one. The first musl/guest selector also matched an exact
F_SETFL flags value that libc changes. The final selector matches the
F_SETFL command, preserving unrelated fcntl operations. These failures are
not counted as determinism passes. Fake source was unchanged by that
selector correction. The collector retains diagnostic executions of the
same production implementation; earlier production implementations are
not merged.

Affected synthetic-path logs encode NUL as `<NUL>` for readable diffs.
The marker was absent from each original and every encoding was checked by
reconstructing the original bytes. `nul-encoding.log` records original Git
blob identities, byte counts and replacement counts; other bytes are
unchanged. Cargo build durations are removed.

Signed `449c751` passes [push CI](https://github.com/menhera-org/rs-l2tpd/actions/runs/41392740303)
and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41392740327).
Both CI jobs complete successfully; no timeout occurred. The structured
job records are retained here. This batch's own push CI is checked after
publication. The 100% gate and complete clause proof remain open.
