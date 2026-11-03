# Remaining paths, November 3

This batch starts from signed `f0b666f`, which passes [both CI jobs](https://github.com/menhera-org/rs-l2tpd/actions/runs/41549176297)
and [CodeQL](https://github.com/menhera-org/rs-l2tpd/actions/runs/41549176350).
The raw collector now covers **8,648/8,705 production lines (99.35%)**
and **1,799/1,840 branch outcomes (97.77%)**. That adds three lines and
seven outcomes; **57 lines and 41 outcomes remain**. Phase 6 remains open.

All **4,389 production-source function mappings** compare equal to the
preceding collector. Across all exported files, 5,889 records become
5,895: existing process-test locations shift, and six test mappings are
added. Those test-only differences do not change production mappings.
Profiles from the event/lifetime and scoped-inventory collector remain
compatible; no production exclusion is added.

## What the cases check

- Failed kernel startup preserves an inherited socket until shutdown.
  A live store processes its exact withdrawal name and barrier; the
  daemon still exits 1 because kernel absence cannot be confirmed.
- A real daemon receives EIO from capget, reports it once, reaches empty
  readiness and shuts down successfully.
- The lifetime reader treats an injected ETIMEDOUT quietly and retains
  its generation. Ordered send, reopen and quiet-reader controls remain.
  The timeout is syscall fault injection, not a claim that a natural
  poll call returned ETIMEDOUT.
- Removing a VRF member distinguishes tunnels bound directly to the
  member from tunnels bound to its parent.
- Removing a duplicate IPv4, global IPv6 or link-local source on another
  device leaves a bound tunnel unchanged and makes no kernel request.
- Reloading a zoned literal to an unanswered IPv6 hostname clears the
  previous zone while preserving the socket and configured binding.
- Instrumented GNU execution on Ubuntu 7.0 rejects the existing session
  returned for a query naming the wrong tunnel. Three repetitions
  export three nonempty profiles. A separate faulty ID-pair guard fails
  in that guest.

## Executed scope

Ten initial instrumented ordinary suites pass. Three instrumented GNU
live collections and three stable GNU plus three stable musl collections
each pass 308 ordinary library cases, all 57 ignored library cases,
80 ordinary binary cases and all 37 process cases. Required ignored
binary filesystem/task-limit cases retain their separate guest scope.

The three additional model cases then pass ten complete instrumented
library repetitions and three stable GNU plus three stable musl library
repetitions: **311 ordinary cases**, with the same 57 live declarations
ignored in that ordinary pass. Their existing live fixtures did not change.

All five focused required-kernel profiles pass the inventory case, all
four lifetime-ordering modes, the three new event/binding models, both
new process cases, ordinary binary cases, selected filesystem cases and
signal task limits. These focused profiles do not replace the preceding
full normal/boot/clock matrix. The shipping guest runner is unchanged.
The private checkout's base, source patch and exact dispatch are retained.

Seven restored fault controls fail their intended assertions: omit
startup withdrawal, panic on capget failure, log a quiet timeout, accept
a foreign session, miss direct-member removal, reverse the address-device
comparison, or retain the previous zone. The foreign-session control is
executed on Ubuntu 7.0; the others run in disposable GNU containers.

The common CI script passes, including strict declarations for 333 active
rules and classified evidence for 43 kernel facts. The November 3
publication recheck selects the same five targets: Ubuntu 6.8.0-147.147,
vanilla 6.8.12, Ubuntu 7.0.0-42.42, vanilla 7.0.14 and mainline 7.4-rc1.

## Rejected attempts and remaining work

The first GNU guest host validator expected a marker at column one;
libtest prefixes it with the test name. All three guest cases passed.
The corrected validator checks the saved successful run, all three
foreign-tunnel observations and three nonempty profile files before import.

The first hostname-reload fixture omitted the required IP version. Its
failed log remains; its raw profile was removed from the collector.
The corrected fixture supplies V6 before and after reload and passes the
repetitions and five focused guests above.

A first mapping comparison included integration-test locations and
therefore differed. The corrected comparison checks every exported
production-source mapping, preserves the test-only differences and fails
on a production mismatch. No claim of identical whole exports is made.

[Coverage measurement](coverage-measurement.md) records a separate LLVM
summary/merged-source discrepancy and a small calibrated reproducer.
It changes no gate. Complete clause/history/resource/event-cost proof,
the raw 100% coverage gate, its CI enforcement and resolution or bounding
of the retained clock/emulator failures remain open. Incus and root-unit
results retain their earlier execution scope; this batch does not rerun them.
