# Allocation and dispatch checks in the normal paths

The final common gate script passes after both tests are registered.
It runs the production coverage checker's ten tests and the new work
parser's four tests on GNU and musl, warning-denied Clippy, all ordinary
suites, strict maps, musl process/startup/allocation tests and documentation.
The earlier common pass before startup-peak expansion remains separate.

The integrated source-work runner passes all 240 processes: ten repetitions
of eight workloads at three configuration sizes. It records one fixed
fixture binary and final matching source/binary hashes. Full compressed
LLVM exports and each actual test result remain under source-work/.
The [cost record](../source-work-20261103/README.md) explains the metric,
calibration, negative controls and limits. This is GNU profiling; no musl
profiling run is claimed.

The [allocation record](../resource-peak-20261103/README.md) adds startup
peaks to the resync and failed-resync measurements. The final expanded
fixture passes ten GNU and ten musl repetitions, each checking 18 startup
and 18 resync measurements. A deliberate temporary full inventory fails
the startup bound. Other controls reject a broader resync inventory,
disabled peak accounting and forgotten deallocation. All are restored.

The permanent work runner rejects missing arguments and reuse of an old
record. The fixture rejects zero/301 bindings and an unknown workload
before creating snapshots; the refusal logs retain the intentional failed
test results. No such refusal is counted as a successful workload.

The workflow has a separate 20-minute work-measurement step, a 60-minute
build-job limit and failure artifacts. Actionlint and offline Zizmor pass.
The separate P4 production job retains its existing limits. A GitHub run
of this new workflow revision remains required; local checks are not a
remote CI result.

Production src/ is unchanged from signed e29c6f3. The compiled shipped-musl
daemon's Git blob ID is identical to the daemon used in the completed
thirteen-profile matrix and three fresh scenario/Incus pairs plus the
root systemd guest. These pure model/tool additions do not change that
live binary. The initial/final selected source patches match; new file
patches reconstruct the fixtures and runner. Later prose updates do not
change the frozen production/test/tool code.

This batch strengthens transient-allocation and event-work evidence. It
adds no daemon dependency or production exclusion. It does not turn source
coverage or rule tags into proof of every specification clause; the final
clause assessment and the new workflow's actual result remain separate.
Cargo build-duration fields alone are normalized in retained logs.
