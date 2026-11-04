# Optional distribution-kernel matrix

Production source is clean signed `c599b1f`, committed and synced before
these runs. All six profiles executed serially. Initial/final source
patches are empty. [Aggregate result](result.log): `OPTIONAL_MATRIX_RESULT=1`.

| Stock kernel | Normal | Clock/pause |
|---|---|---|
| Debian 12 `6.1.0-54-amd64`, package 6.1.190-1 | [Fail](debian12-normal/run.log): 31 private live cases pass; 21 Linux cases pass, three fail; subsequent suites not reached | [Fail](debian12-clock/run.log): UP underlay rename gets EBUSY; QMP controller passes |
| Rocky 9 `5.14.0-687.61.1.el9_8.x86_64` | [Pass](rocky9-normal/run.log): 27 scenarios, 37 process cases | [Pass](rocky9-clock/run.log) |
| Rocky 10 `6.12.0-211.72.1.el10_2.x86_64` | [Pass](rocky10-normal/run.log): 27 scenarios, 37 process cases | [Pass](rocky10-clock/run.log) |

Debian refuses unchanged-MAC writes on UP session devices and UP-device
renaming. The required-range assertions were not relaxed, and production
behavior is unchanged. Upstream
[v6.1.190 dev.c](https://github.com/gregkh/linux/blob/v6.1.190/net/core/dev.c#L1222)
contains the corresponding older guards; this is not a full Debian patch
audit. Both Rocky guests observe empty-VRF errno 99 and foreign K41 notices
while keeping local objects intact.

The fetch logs and package records retain official metadata, SHA256 checks
and extraction-image identities. Images/configurations/modules are stock;
no packages were installed on the host. These kernel-only guests do not
qualify distribution userspace, SELinux, managers or packages.

The original invocation was:

```sh
sh audit/phase6/optional-kernels-20261104/run.sh audit/phase6/optional-kernels-20261104
```

The wrapper and fetch helper now live at `tests/kernel/run-optional.sh`
and `tests/kernel/fetch-optional.sh`; the runner README gives the fresh-record
recipe. The wrapper's source was renamed while its open execution continued;
only its usage label was updated afterward. Kernel and test inputs remained
unchanged throughout. Download progress is omitted from the checksum logs.
