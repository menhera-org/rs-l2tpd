# Remaining condition witnesses

Base: signed `db7c1d2`. After separate-checkout qualification, the batch
is imported and passes the full common checks in `common.log`. The preceding
signed source passes all thirteen required kernel profiles in repository
record `audit/phase6/matrix-20261103T021525Z-400861/`.

The batch adds a readiness decision test, non-VRF master address handling,
lost-event parent-cache recovery, private malformed global-zone handling,
stale background events after shutdown and reload completion during shutdown.
One resync predicate is removed because the VRF map was just constructed
from the configured-device index; its second membership check is redundant.
The readiness predicate is shared with a private unit test. That unit test
does not force the daemon's private service worker to fail.

Ten native ordinary suites (seeds 51–60) and three musl library/binary/service
collections pass. The new logging subprocess case passes separately three
times per libc; it is deliberately ignored in parallel ordinary suites.
The proposed common-check change runs it serially on both libcs and requires
one actual passing test. Six independent restored controls reject their
intended faults: post-shutdown polling, invalid zone use, non-VRF member
reconnect, ignored monitor loss, premature readiness and reload completion
after shutdown.

The first parallel qualification, seed 41, fails an immediate fake-socket
deletion assertion in another service test while the new subprocess test
runs. Subprocess launches can temporarily inherit concurrent fake descriptor
owners. Serial execution avoids that exposure; the failed run remains
recorded and is not counted as a pass. A proposed broader-inventory mutation
survived the first cache witness. The strengthened witness changes a parent
without delivering its event, requires loss recovery and rejects disabling
that recovery. It proves the final retained cache, not intermediate scan cost.

The initial fixture attempts also retain their failures: a private
configuration insert was incorrectly expected to revalidate an already-built
value; a runtime fixture lacked an entered Tokio context; a TOML fixture
first omitted its required peer and then used a mismatched address family.
The corrected witnesses execute and pass.

The task-limit helper also used `$-` (shell flags) in container names and
profile patterns where it intended `$$` (PID). The name-recording sentinel
reproduces identical names from two old-helper invocations and distinct
numeric-PID names from the correction. Concurrent real GNU/musl runs then
pass both thread-creation failures and both fork failures, with cleanup.

The imported batch passes the full common checks, including the serial
subprocess case on both libcs and all ten coverage-checker tests.
It has not yet been measured in a fresh production collector or run
through a full new kernel matrix. It does not pass P4 or complete Phase 6.
