# H15: missing kernel support, netlink and individual capabilities

This package exercises real degraded daemon processes. It adds four
container scenarios and a separately scoped stock-kernel guest case;
none changes host networking or host module state. No dependency was
added. The shared DNS/RA wire helpers moved from the library's private
tests into tests/support/discovery.rs so adapter and daemon scenarios use
the same protocol fixtures. Their DNS thread now has bounded cancellation
instead of relying on a self-addressed packet to unblock teardown.

## Cases and assertions

| Case | Actual condition | Observed contract |
|---|---|---|
| CAP_NET_ADMIN absent | Only NET_RAW and NET_BIND_SERVICE remain in CapEff | One capability warning and one EPERM creation error; alive and unready for a 2.2-second observation window; no tunnel/session created; SIGTERM cleans up |
| CAP_NET_RAW absent | Only NET_ADMIN and NET_BIND_SERVICE remain | Repeated real RDNSS advertisements yield no DNS requests while accept_ra=0. After a five-second negative window, enabling it and requesting a fresh lookup allows the netlink fallback to resolve the peer and exchange frames both ways. Adding the preferred source reconnects to source 2001:db8::3 without replacing the session index; reload does not repeat the capability warning |
| CAP_NET_BIND_SERVICE absent | Only NET_ADMIN and NET_RAW remain; the test namespace sets ip_unprivileged_port_start=1024 | Pure DHCPv6 reports the actual EACCES bind failure once as an error and stays disconnected without withholding readiness. The unified method uses real RA/DNS and carries frames; each startup warning occurs once |
| Netlink refused | All three required capabilities remain; a child-only seccomp filter refuses socket(AF_NETLINK) with EPERM | One named-errno startup error, no false readiness, no premature exit for 2.2 seconds, no kernel objects; SIGTERM exits the pre-service process with code 1 |
| Ethernet driver unavailable | Ubuntu 7.0.0-42-generic, L2TP core present, l2tp_eth absent, autoload disabled only in the guest | One EPROTONOSUPPORT error; the tunnel can exist but the session/readiness cannot. Explicitly loading the matching guest driver permits readiness within one second, frames both ways, and orderly removal |

The module case uses QEMU because a container shares the host's driver
state and may trigger host autoload. The helper's no-ethernet mode requires
a modular stock kernel, loads the core without Ethernet, disables the
guest's autoload command, and runs only the targeted boot scenario.
Manual modprobe and its effects stay inside that disposable guest.
The required matrix driver now includes this extra scoped stock-kernel
boot. Its normal and H4 profiles retain their separate scope markers.

The negative observation windows establish continued execution and absent
readiness; they do not count each kernel syscall. The exact retry policy
also has fake-clock tests; the live driver-availability transition must
recover within one second. This package does not claim a new measurement
of every timer interval, the low unprivileged-port-range DHCPv6 case,
H16 clocks/pause, or H17 resource/event-cost bounds.

## Defects found and corrected

1. Missing pseudowire support was reported as a warning. Known unsupported
   protocol/operation and permission errors during session creation now
   use the host-defect error level; transient allocation failures retain
   warning severity. The first missing-driver guest fails that severity
   assertion and is retained as a counterexample.
2. Discovery initialization errors, including the refused DHCPv6 bind,
   lost their host-defect classification when converted into an explanatory
   string. The classification is now retained through reporting. Missing
   resolver devices and unanswered lookups keep their existing policy.
3. The public propagated I/O error formatter omitted the errno name.
   It now prefixes that name while preserving the original error source
   and the original text for errors without an OS errno. The real denied
   netlink case and a source-preservation unit test cover this path.
4. A preceding transient warning could suppress the first error-level
   host-defect report for the same entry/condition. The episode records
   whether an error has been reported, permits one promotion, and retains
   that state through later transient retries. A mixed EAGAIN / missing
   protocol / EAGAIN / missing protocol test fails before this correction
   and passes afterward (severity-upgrade-before/after.log).

The fake report test checks four host errnos and three transient allocation
errnos, persistence across retries, readiness, recovery, and the resolver's
thirty-second retry. These are real assertions, not added citation labels
without behavior. Live tests separately prove the kernel refusals.

## Records and limits

The first container run consumed an earlier error line while waiting for
readiness, then exposed an unbounded DNS-fixture teardown; its container
was explicitly removed. The second three-case run passed. The four-case
run then found the startup errno-name omission. Those records remain in
scenarios-20261031T074915Z-3549649, scenarios-20261031T075230Z-3550931 and
scenarios-20261031T075850Z-3558192. None is substituted for final evidence. The first fake report fixture
injected a session lookup failure rather than a creation failure; its
readiness assertion failed, and the fixture was corrected to inject actual
creation errors after creating the tunnel (fake-first-fixture-failure.log).

The first module run is
[../qemu-no-ethernet-first-20261031](../qemu-no-ethernet-first-20261031/run.log);
its warning-level assertion fails as intended before the fix. Subsequent
scoped successes are retained separately. The final module record is
[../qemu-no-ethernet-input-validation-20261031](../qemu-no-ethernet-input-validation-20261031/run.log).
The host kernel is 6.8.0-147-generic; the guest is the exact stock Ubuntu
7.0.0-42.42 image/modules with the documented cold-boot kho=off setting.

Final validation results and source identities are recorded below. Ordinary GNU checks and all-feature musl
live scenarios are distinct profiles. No merged current-source coverage,
complete current-source five-kernel rerun, strict CI result, H16 or full
H17 proof is claimed by these runs.

### Final results

After the episode-promotion fix, the final host run
[scenarios-20261031T082351Z-3584320](../scenarios-20261031T082351Z-3584320/run.log)
passes **22 scenarios**, including all four new degradation cases, H20,
G11 and the existing manager/route-table cases. SCENARIO_RESULT=0 is in
host-controller-final.log. The final stock guest passes its one scoped
module-availability case, all scoped markers zero. These are fresh results
on the final source state, not replacements for the earlier failures.

ordinary-validated.log, clippy-validated.log and srclink-validated.log pass: all-feature
ordinary tests, warning-denied all-target Clippy and the strict source-link
check. rulemap-validated.log honestly fails: **343 total / 333 active / 271
cited / 62 uncited**, exit 101. Eight rules gained actual case evidence:
H15, K3, K6, K8, R3, R4, R5 and R46. The low-range exception noted above
remains a separate clause to exercise before declaring complete spec proof.

revision plus source.patch identify the tracked source. The additional
capabilities.rs and discovery.rs files are identified, in that order,
by extra-source-hashes.log. The final snapshots are byte-identical.
The guest artifact hashes and build log identify the actual musl binaries.
All five guest config copies were compared with the already archived
stock config; their kernel-config.log files retain each digest and point
to the shared full contents. No config was altered for the driver case.

Final review added early regular-image/module-directory/config-file
validation to run-guest.sh: empty metadata must never become a root
directory copy. guest-input-checks.log tests four rejected inputs before
any guest output or Docker action. guest-input-validation.diff records
that follow-up. The pre-validation snapshots are retained separately;
the final source.patch/final-source.patch and extra-source hashes match
through the strengthened host run. The latest guest uses the guarded
helper; selected-guest-artifacts.log confirms that its executed daemon
and boot-test identities match the final artifacts.

The RA negative window now outlasts the three-second initial discovery
wait, preventing a false negative caused only by delayed DNS. Once
accept_ra is enabled, a changed hostname explicitly requests a fresh
lookup rather than waiting thirty seconds for refresh. Both phases use
the same valid advertisements and controlled DNS responder.
No probe container or guest remains running.

The earlier five-target matrix is the 18-scenario profile at the preceding
source state. It must be refreshed with the expanded suite and current
production reports before the complete Phase 6 gate can pass. H16, full
H17, the remaining promise/rule clauses, current merged 100% coverage,
final Incus/root-unit refreshes and strict CI remain open.
