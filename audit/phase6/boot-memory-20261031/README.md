# Ubuntu 26.04 cold-boot OOM: KHO scratch reservation

Scope: stock Ubuntu package 7.0.0-42.42, guest release
7.0.0-42-generic; 2 GiB QEMU TCG, the Phase 6 ramfs initramfs containing
all-feature musl test binaries. These eight boots run only memory-init.sh,
not conformance or scenarios. They do not count as daemon test passes.
Per-run command.log, kernel-config.log, image/artifact hashes and run.log
record the exact inputs. All eight config copies were byte-compared and
are identical; kernel.config retains their shared contents and each
per-run record retains its digest. results.log records helper exit statuses.

The earlier failed full-profile boot is retained in
[../qemu-resolute-ready-fix-20261031/run.log](../qemu-resolute-ready-fix-20261031/run.log).
It panicked during unpack_to_rootfs before any test executed, with
163112K available and 1927376K reserved. Its identical successful retry
had 1702516K available and 387280K reserved. Retrying alone did not
resolve that nondeterminism.

## Source and mechanism

The stock configuration contains CONFIG_KEXEC_HANDOVER=y,
CONFIG_KEXEC_HANDOVER_ENABLE_DEFAULT=y and CONFIG_MEMBLOCK_KHO_SCRATCH=y.
The exact distribution source is
[Ubuntu-7.0.0-42.42 kernel/liveupdate/kexec_handover.c](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/resolute/plain/kernel/liveupdate/kexec_handover.c?h=Ubuntu-7.0.0-42.42).
[source-evidence.log](source-evidence.log) records its SHA256 and relevant
versioned excerpts: default enable/early parameter at 53–65; scratch
scaling and reservation at 528–733; later CMA initialization at 1374–1437.
The default scale is 200% of the relevant reserved kernel memory, with
separate low/global/per-node regions. Failed reservation frees the
scratch regions and disables handover. Successful reservation can instead
leave most RAM unavailable for unmovable ramfs/kernel allocation during
this early boot. The OOM's large free-but-CMA-only block is consistent
with that path; ordinary CmaTotal accounting alone does not establish
that this memory is usable for unpacking.

The [kernel KHO documentation](https://cdn.kernel.org/doc/html/latest/admin-guide/mm/kho.html)
explains the reserved scratch/CMA allocation model. The versioned source's
kho early parameter and Documentation/admin-guide/kernel-parameters.txt
support `kho=off`. No claim is made about the exact randomized-layout
trigger that made the original default reservation succeed in one boot
and fail in another.

## Controlled results

| Attempt | Extra arguments | Observed result |
|---|---|---|
| 1–3 | none | Scratch reservation failed, KHO automatically disabled; all three memory probes passed |
| 4 | kho=on kho_scratch=16M,512M,1024M nokaslr | Scratch reserved; 113996K available / 1976520K reserved; unpacking panicked, no result marker, helper exit 1 |
| 5 | kho=off kho_scratch=16M,512M,1024M nokaslr | Same requested sizes/layout setting, KHO disabled; 1702580K available / 387272K reserved; probe passed |
| 6–8 | kho=off | Address randomization left enabled; all three probes passed, 1702324K–1702536K available at the early memory report |

Attempts 4/5 isolate enablement while keeping the scratch-size and
nokaslr arguments the same. Attempts 6–8 show that the correction does
not depend on disabling address randomization. Each successful probe
prints MEMORY_PROBE_RESULT=0 and KHO_DEBUGFS_PRESENT=0; the expected
failed control has neither marker. A successful QEMU process exit alone
is never counted.

## Reproduction and harness correction

In a disposable checkout of the corrected helper, apply memory-probe.patch
for the diagnostic PID 1 and controlled command-line variants. Do not
apply it to a checkout while its conformance matrix is running. With
IMAGE, MODULES and CONFIG naming the fetched stock artifacts:

```sh
git --no-pager apply audit/phase6/boot-memory-20261031/memory-probe.patch
attempt=0
for probe_mode in default default default controlled-on controlled-off off off off; do
    attempt=$((attempt + 1))
    MEMORY_PROBE_MODE=$probe_mode tests/kernel/run-guest.sh \
        "$IMAGE" "$MODULES" "$CONFIG" normal "$RECORD/$attempt-$probe_mode"
done
```

The fourth command is expected to fail; the executed lab loop captured
its status and continued through the remaining controls (results.log).
The diagnostic patch changes no artifact-building step; its temporary
helper's location is irrelevant to the guest. It is retained for
reproduction, not part of the normal test runner.

The normal run-guest.sh now appends `kho=off` only if the supplied config
has CONFIG_KEXEC_HANDOVER_ENABLE_DEFAULT=y. It keeps the stock image,
matching modules/config, ASLR and 2048 MiB unchanged. The full-profile
validation belongs to
[../matrix-20261031T071523Z-3533819](../matrix-20261031T071523Z-3533819/command.log),
not to these diagnostic-only boots. That full-profile run passed all
conformance/process cases and 18 scenarios with no boot retry. Other
target configs did not receive the override and also passed. Shell syntax, ShellCheck and a patch-application check pass.

This calibrates cold-boot test memory; it does not prescribe production
boot parameters or test kernel-to-kernel handover. The daemon's execve
restart and socket FD inheritance are unrelated to kernel kexec/KHO.
All diagnostic guests have powered off; no host networking was changed.
