# Phase 6 T5 socket contract and H20 fragmentation — 2026-10-30

T5's new socket-option contract exposed a production gap: the daemon left
path-MTU modes at their kernel defaults. The live read-back regression
failed before the fix (IPv4 IP_MTU_DISCOVER was WANT=1), then passed:
IPv4 sockets have IP_MTU_DISCOVER=DONT; IPv6 sockets have both IPv4 and
IPv6 MTU-discovery modes DONT and IPV6_DONTFRAG=0. The production adapter
sets them at creation before the first connect. Failures are reported
once per option in a process and leave the tunnel usable.

The existing l2tp API covers the native-family mode and IPV6_DONTFRAG.
L2's explicitly authorized bounded exception covers the missing IPv4
option on IPv6 sockets: one function, one setsockopt, borrowed live
descriptor, local integer with its size, errno returned unchanged.
This is the only allow(unsafe_code) in the library. It uses nix::libc,
already available; no new dependency or upstream release was introduced.
The raw function's refused-option errno/socket-liveness path also has
an ordinary unit test.

The process scenario installs a seccomp filter only in the child
daemon through setpriv. It refuses each of the three options in turn
with EPERM, across mapped and native IPv4 cases, multiple tunnels and
repeated reloads. Each option's case requires exactly one error report,
no unrelated option report, readiness, bidirectional traffic on all
three sessions, and clean shutdown. This tests actual failed syscalls
and logs rather than a mock logging flag.

H20/K43 uses two namespaces joined by a 1500-byte veth, with and without
VRF binding. Each IPv4/IPv6 outer tunnel is exercised with session MTU
1500 and 9000: eight combinations, each with full-size ping payload
MTU-28 and verified 1 MiB TCP transfers in both directions. The test
requires session RX bytes/packets to grow by whole MTU frames, sender
fragment counters to grow, unchanged TX drop counters, no daemon log
during MTU changes/traffic, and clean shutdown. Reassembly counters
are deliberately not used, as the approved P2 instructions explain:
netfilter can reassemble before IPv6's ordinary reassembly accounting.

Executed on 6.8.0-147-generic, all features / musl:

- [Read-back before fix: failed](entry/pmtu-before.log).
- [Read-back after fix: passed](entry/pmtu-after.log).
- [Library-only build and initial error-path test](entry/pmtu-ordinary.log).
- [Initial H20 run](entry/fragmentation-scenario.log).
- [Three isolated H20 repetitions](entry/fragmentation-repeat-1.log),
  [second](entry/fragmentation-repeat-2.log), [third](entry/fragmentation-repeat-3.log).
- [Initial actual option-refusal process case](entry/fragmentation-refusal.log).
- [Final ordinary tests, format and clippy with warnings denied](entry/fragmentation-ordinary-checks.log).
- [Strict source-link check: 43 facts, 37 production-cited, six classified,
  zero uncited functions; four tests passed](entry/fragmentation-srclink.log).

The expanded ignored-only container subset, including all three refusal
options, passed three times: 18 passed / zero failed / two filtered,
72.92 s, 73.85 s and 74.49 s. The filtered tests are the separately run
Incus case and ordinary capture-parser self-check.

- [Expanded run 1](entry/scenarios-fragmentation-1.log).
- [Expanded run 2](entry/scenarios-fragmentation-2.log).
- [Expanded run 3](entry/scenarios-fragmentation-3.log).

The final formatting correction replaces a compile-time architecture
assertion in the seccomp fixture with explicit audit architecture
selection; final ordinary checks passed afterward. The container
repetitions exercised the same x86_64 filter instructions.

These are host-kernel results, not the required kernel matrix. The
maintainer now names Ubuntu 6.8.0-148.148 and 7.0.0-42.42 as today's
stock targets, with imminent security updates expected; 6.8.0-147 host
results cannot pass the updated required stock-kernel target.
H20 still must pass every required kernel. The complete P2 suite,
kernel matrix, merged 100% coverage and root sandbox remain open.
