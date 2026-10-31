# Enable reload/restart signals before publishing readiness

The corrected Ubuntu 26.04 driver run reached readiness in H8 and then
timed out waiting for the immediately requested reload. See
../qemu-resolute-driver-fix-20261031/run.log: 17 scenarios passed and
`large_default_free_tables_do_not_add_daemon_route_queries` failed.

The binary called `daemon::ready` and logged readiness before calling
`signals.ready`. The signal collector explicitly ignores SIGHUP until
that flag is set (P9). An observer could therefore see readiness and
send a reload that the collector discarded. The code now enables signal
acceptance after successful convergence and before publishing readiness.
Requests still run through the same control queue. No contract changes.

Verification on the fixed code:

- ordinary all-feature tests: pass (ordinary.log);
- all-target/all-feature Clippy, warnings denied: pass (clippy.log);
- formatting: cargo fmt --all --check passed;
- all 26 ordinary/privileged process cases: pass (process.log), including
  pre-readiness signal handling and reload/re-exec;
- H8 host case: one passed, including immediate reload after readiness,
  both 100,000-route tables, positive controls and no capture loss
  (routes-host.log and ../scenarios-20261031T064750Z-3522215);
- strict source link: four pass (srclink.log);
- strict rule map: fails with the existing 70 missing citations, not
  changed or hidden by this fix (rulemap.log);
- Ubuntu 7.0.0-42-generic fixed-code guest retry: 10 live library,
  16 kernel, five review, 38 ordinary binary plus three privileged
  binary, 26 process and all 18 scenarios pass, including H8/H20.
  CONFORMANCE_RESULT, SCENARIO_RESULT and MATRIX_GUEST_RESULT are zero
  (guest-retry.log and ../qemu-resolute-ready-fix-retry-20261031).

The first fixed-code guest boot did not run any tests: it panicked out
of memory while unpacking the initramfs. The identical retry passed.
Both archives report 578942 cpio blocks; the boot logs show different
reserved/available memory before unpacking. The cause is unresolved.
The failed boot remains in guest.log and
../qemu-resolute-ready-fix-20261031. A successful retry does not establish
the deterministic matrix gate. No boot knob, RAM size or kernel option
was changed to hide it.

All guest/container processes from these checks have exited. The required
matrix still needs the K26/K34 maintainer decision, explanation of the
boot failure, completion of P2 and a consistent final-code rerun.
