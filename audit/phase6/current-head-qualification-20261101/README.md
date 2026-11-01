# Host qualification and independent coverage collections

Frozen code revision `1b3d876102e51b348d13b657d2247808cebf8382` passes
the full GNU live suite and unprivileged GNU Incus scenario. The live suite
runs 50 serial library, 24 Linux, five review, three privileged binary,
29 process and 27 normal scenario cases. Normal GNU scenarios take 158.11 s;
GNU Incus takes 17.19 s and exports seven daemon profiles. The native log
identifies the instrumented executables.

Three stable-musl scenario/Incus pairs also pass:

| Repetition | Normal scenarios | Incus scenario | Raw records |
|---|---:|---:|---|
| 1 | 27 pass, 159.75 s | pass, 24.81 s | `../scenarios-20261101T212510Z-3133226/`, `../incus-20261101T212800Z-3142229/` |
| 2 | 27 pass, 163.30 s | pass, 17.88 s | `../scenarios-20261101T212832Z-3143681/`, `../incus-20261101T213120Z-3151083/` |
| 3 | 27 pass, 164.15 s | pass, 16.02 s | `../scenarios-20261101T213146Z-3152753/`, `../incus-20261101T213430Z-3159114/` |

All live results here use Ubuntu 6.8.0-147-generic; system-container userspace
is Ubuntu 24.04. The source patches are empty and agree. The final Incus
list is empty. These runs provide no other distribution, kernel or architecture
result. This source also passes [both GitHub CI jobs](https://github.com/menhera-org/rs-l2tpd/actions/runs/41351254086).

## Profile transport correction

The first live attempt reused a transport directory. Container PID reuse
made an updated test executable write into earlier raw-profile filenames.
LLVM rejected incompatible profile layouts; two child tests correctly
rejected those unexpected diagnostics. The failed log is retained as
`rejected-shared-profile-directory.log`. That attempt is not qualification,
and its transport files were moved outside the collector before retrying.

The reusable GNU live runner now creates a fresh directory and includes its
unique name in each exported filename. The Incus collector includes the
unique container name in each destination filename. Thus copying profiles
back cannot overwrite earlier collections. `tooling.patch` and its identical
final copy record these changes. POSIX shell syntax and ShellCheck pass;
the successful live and Incus runs exercise the changed transport.

All 274 previously exported profiles retain their SHA-256 digests.
`existing-profile-hashes` and `existing-profile-check.log` retain the check.
The merged report stays at **8,487/8,687 lines (97.70%) and 1,699/1,852
branches (91.74%)**, with no profile mismatch or saturated region. There
are no production changes or exclusions. P4 remains open with 200 lines
and 153 branches uncovered.

`commands.sh` records the collection commands. Later test-only changes and
the required-kernel matrix have separate source and execution scopes.
