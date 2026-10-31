# Bounded CI determinism qualification

CI now has ten matrix jobs with seeds 1 through 10. Each runs the ordinary
library, fake-conformance, rule and service suites, then boots a fresh stock
Ubuntu 24.04 kernel guest for the live kernel/process suites and the same
scenario executable used by `tests/docker/run.sh scenarios`. This gives the
scenario suite ten CI repetitions without loading modules or changing
networking on the runner host. Incus and root-systemd remain separate profiles.
The required five-kernel matrix also remains separate.

Each qualification job has 40 minutes. Tool installation, image preparation
and kernel downloads each have six minutes; fake-suite execution and the
separate guest/baseline build each have ten minutes. The live-suite step has
20 minutes, while QEMU retains its 900-second limit. Artifact upload has five
minutes. At most two jobs run at once, and fail-fast is disabled so that all
repetitions can report their results. There is no retry that could hide a
flake. The ordinary build job has 30 minutes, with 15-minute common checks
and ten-minute coverage generation.

`actions/upload-artifact` is pinned to its official v4 commit
`ea165f8d65b6e75b540449e92b4886f43607fa02`. Each job retains its own logs for
14 days, including on failure. A timed-out step or nonzero suite result fails
the job. Strict map flags are still off; all ten required repetitions must
pass before they are enabled. A workflow definition alone does not prove CI
qualification.

## Networkless image preparation

`tests/kernel/build-review-image.sh` replaces the online Docker build command.
Host curl downloads Alpine v3.22 indexes. A networkless amd64 Alpine container
uses `apk fetch --recursive --url --simulate` to resolve the existing four
requested packages and their dependencies against those local indexes. Host
curl fetches those archives, and Docker builds with `--network none` using
`apk --no-network`. Signature verification stays enabled. The helper rejects
unexpected package locations and empty resolution output.

The [apk-tools command documentation](https://git-old.alpinelinux.org/apk-tools/tree/doc/apk-fetch.8.scd)
describes the recursive URL simulation. No Rust dependency or daemon behavior
changes. The existing review image's package set is unchanged.

## Local evidence

```sh
tests/kernel/build-review-image.sh
docker run --rm --network none rs-l2tpd-audit-vm:local apk info -e linux-virt iproute2 util-linux kmod
./test-ci-gates.sh
```

[image-build.log](image-build.log) records the successful offline build;
[image.log](image.log) identifies the result, and
[image-packages.log](image-packages.log) checks all four requested packages.
[ci-gates.log](ci-gates.log) records the passing common checks, whose map
invocations still run leniently. Build durations are omitted. `revision` and
`source.patch` identify the tested tree. The remote workflow has yet to run
this package; no ten-run or strict-enforcement pass is claimed here.
