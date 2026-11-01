# Phase 6 handoff for the requested 23:30 UTC pause

Phase 6 remains incomplete. This record preserves the state prepared before
its requested pause on 2026-11-01; it does not declare any pending gate passed.

The latest tested source is signed commit `498edd8`, including the
[foreign PID-directory owner test](../pid-directory-owner-20261101/README.md)
and [mainline RC tooling correction](../mainline-rc-20261101/README.md).
Production Rust behavior is unchanged by these two commits.

The current required selection is **6.8.0-147.147, 6.8.12,
7.0.0-42.42, 7.0.14 and 7.4-rc1**. Publication documents, Ubuntu package
metadata and the resolved list are retained in `publication-current/`.
The original publication check rejected the RC because the parser only
accepted final releases; `publication/` preserves those inputs.
`publication-check.log` records the changed target against the preceding
matrix. Download progress was omitted from that comparison log.

P3 reopened when mainline changed from 7.3 to 7.4-rc1. The RC archive has
been fetched and its compression, Makefile version and digest checked.
Its build, source review and live guest runs remain pending. The
[thirteen-profile matrix](../matrix-20261101T205406Z-3041229/README.md)
passed for the preceding five-kernel selection with mainline 7.3;
those results remain historical evidence. The later CLI permission tests
also passed on all five kernels of that preceding selection. Neither run
qualifies 7.4-rc1.

P4 remains **8,514/8,687 production lines (98.01%)** and
**1,704/1,852 branches (92.01%)**: 173 lines and 148 branches remain.
The owner-test record retains the report and confirms identical production
mappings. No new production coverage exclusion was introduced. Complete
clause, history, resource-bound and event-cost proof also remains open.
The [Phase 6 plan](../../../docs/phase6.md) and
[verification record](../../PHASE6_VERIFICATION_2026-11-01.md) retain the
full gate state and earlier maintainer decisions.

Resume by checking the publication targets again, building and reviewing
7.4-rc1, and running its normal, clock and both IPv6-absent profiles.
Use `tests/docker/run.sh matrix required` for a complete required-set run;
its initial and final publication selections must agree. Continue closing
production coverage and the remaining proof obligations. Preserve the
existing evidence and do not treat the old mainline results as current.

CI for `93d70f3` passed. At handoff preparation, CI for `498edd8` was
[still running](https://github.com/menhera-org/rs-l2tpd/actions/runs/41361624431).
Its result must be checked when work resumes if it is still pending at
pause time. No kernel build or local guest test was left running during
handoff preparation.
