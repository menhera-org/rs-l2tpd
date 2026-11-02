# Resolver, dispatch and host-request boundaries

This package was qualified in an isolated checkout of signed `455eef7`,
then integrated after the required matrix finished. Production function
bodies are unchanged. `proposed-tests.patch` preserves the integrated tests.

The static-server case checks an ordered IPv6/IPv4 server list with distinct
ports, both bound and unbound. A global IPv6 server must retain scope zero;
a bind device does not turn that address into a link-local server.

The live discovery case refuses only `setsockopt(IPPROTO_ICMPV6,
ICMP6_FILTER)` with EIO in a fresh subprocess. The existing shared seccomp
helper now supports that precise option match. DHCPv6 socket setup and
multicast transmission remain allowed. The unified adapter must retain
DHCPv6, report its missing RA source as partial and receive an actual DNS
server Reply. Its one-source lookup budget remains 33 seconds.
This is an injected RA setup failure, not a claim that the kernel naturally
returns EIO or that a DNS lookup was performed after the fault.

Three final GNU and three musl repetitions pass. Six failure controls
fail at their intended assertions: applying a scope to a global server,
ignoring a missing RA source, dropping resolver-answer dispatch,
acknowledging an undelivered host request, dispatching an unrelated event
with host forwarding disabled, and panicking when joining a failed startup.
The host-request test checks both full and closed channels, preserves the
original tunable deadline and accepts its original completion. The blocking
test deliberately panics inside its private startup callback; the caller
receives the closed-channel error. No production panic was added. Final
common gates, ten native and three musl model runs, Rust 1.89 and three
additional musl architecture compile checks pass. The targeted live case
also passes on all five required kernels, including 7.4-rc1. Three GNU
instrumented live repetitions pass after integration. The merged collector
now covers 8,518/8,687 lines (98.05%) and 1,706/1,852 branches (92.12%):
four additional lines and two additional branch outcomes. All 4,327 old
production mappings remain unchanged; four test-induced instantiations
were added. The 169 uncovered lines and 146 uncovered branch outcomes
remain required. No production exclusion was added.

The rejected broad setsockopt filter also blocked DHCPv6 multicast setup;
its receive timeout is retained. A missing test-only unsafe allowance and
a duplicate helper inclusion were caught by compilation/Clippy. The final
candidate reuses the already-permitted kernel test helper module rather
than including it twice. No production unsafe-code allowance is added.

GNU/musl live work runs in disposable networkless containers. Five targeted
musl guest boots additionally execute 65 ordinary CLI cases, three selected
filesystem cases and the one DHCP-only case. `guest-source.patch` identifies
their exact candidate and audit-only boot fixture; `guest-fixture.patch`
shows the added command and result marker. The fixture was restored after
the five passes and is absent from the proposed shipping patch.
The completed full matrix retains its separate, unchanged source and
result scope; these targeted boots do not replace its full profiles.
