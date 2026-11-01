# PID-file inspection and creation refusals

Existing PID-file fixtures now add four controlled cases:

- EIO while opening a temporary inode must preserve the pre-created file's
  inode and contents; it must not use the permission-error overwrite fallback.
- An uninspectable parent directory or PID entry must leave the file untouched,
  report one cleanup warning and allow shutdown to continue.
- A metadata failure in `matches()` must preserve EIO.

The parent checks inode identity, contents and temporary-name cleanup.
Captured child output also rejects LLVM profile diagnostics. The existing
handwritten open filter now selects the flags word using the target's byte
order. No production code or dependency changes.

Ten native and instrumented model/rule/service/startup/ordinary-CLI repetitions,
three musl repetitions, common gates, Rust 1.89 and ARM64/RISC-V64/PowerPC64LE
musl compile checks pass. Five independent controls fail: treating creation
EIO as a permission fallback, making either cleanup inspection failure fatal,
swallowing the `matches()` error, and muting cleanup warnings.

## Per-kernel CLI qualification

The added `binary` guest profile runs ordinary CLI unit tests and requires
both `BINARY_UNIT_RESULT=0` and `MATRIX_GUEST_RESULT=0`. All five targets from
the completed required matrix pass 65 ordinary tests with five explicitly
ignored cases. The complete thirteen-profile matrix retains its separate
frozen 2d5ae45 source and publication snapshot.

| Kernel | Ordinary CLI tests | Privileged cases in this profile |
|---|---|---|
| Ubuntu 6.8.0-147-generic | 65 pass | five ignored |
| Vanilla 6.8.12 | 65 pass | five ignored |
| Ubuntu 7.0.0-42-generic | 65 pass | five ignored |
| Vanilla 7.0.14 | 65 pass | five ignored |
| Mainline 7.3.0 | 65 pass | five ignored |

The marker tests execute the runner's actual marker-checking block. Four
complete profiles are accepted; omitting any required marker is rejected.
An invalid mode returns status 2. POSIX syntax and ShellCheck pass.
These CLI-only boots add no scenario, manager or Incus result.

The first musl attempt exposed a missing `lstat` denial: the fixture incorrectly
expected its metadata call to fail. That attempt and its source patch are
retained under `rejected-missing-lstat/`; its profiles were moved outside
the collector before final qualification. The corrected denial set covers
legacy `lstat` as well as `statx` and `fstatat`. New metadata cases are scoped
to 64-bit targets. No live non-x86 or big-endian execution is claimed.

An initial Ubuntu 7.0 wrapper assumed a `lib/modules` directory. The corrected
wrapper uses the package manifest's reported module path. The preflight error
is retained and is not counted as a guest result.

Coverage reaches **8,510/8,687 lines (97.96%) and 1,703/1,852 branches
(91.95%)**, leaving 177 lines and 149 branches. All 4,327 production mappings
remain identical; source patches agree. There are no production exclusions,
profile mismatches or saturated regions. `commands.sh` records positive
commands; control patches/logs identify deliberate defects. P4 and complete
clause proof remain open.
