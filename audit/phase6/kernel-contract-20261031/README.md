# K26/K34: approved empty-VRF errno distinction

The original full matrix's vanilla 6.8.12 conformance run failed the shared
`no_ipv6_source_is_eaddrnotavail` case: connect in an empty, up VRF with
no IPv6 source or route returns errno 101 (ENETUNREACH), while the test
then required 99 (EADDRNOTAVAIL). The corresponding Ubuntu 6.8.0-147 guest
passed. See ../matrix-20261031T062607Z-3496031/vanilla-6.8.12/run.log
and ../matrix-20261031T062607Z-3496031/noble/run.log.

This is a specification issue in K26 and K34, not permission to relax a
test silently. Their universal no-source errno statement and the T16
wording do not match a required kernel. Both errors already have the
same transient treatment in the daemon.

Source comparison of the exact built tarballs:

- v6.8.12 include/net/ip6_route.h:128-145 calls ipv6_dev_get_saddr
  without the socket's L3 master. net/ipv6/ip6_output.c:1097-1151 first
  obtains a route, tries source selection, then returns any route error.
- v7.0.14 net/ipv6/ip6_output.c:1124-1136 passes flowi6_l3mdev to
  ip6_route_get_saddr, as does v7.3:1156-1168.
- v7.3 include/net/ip6_route.h:156-184 uses that L3 master for source
  selection even when no route supplied a device. Earlier verified
  Ubuntu 6.8.0-147, vanilla 6.12.114/6.18.59 and 7.3 runs pass the
  stricter assertion; no first-fix version is claimed by this comparison.

The maintainer approved the documented kernel distinction on 2026-10-31.
`proposed.patch` is retained as the reviewed proposal and has now been
applied to the specification and shared conformance test. It makes
K26/K34 describe the observed kernel-dependent empty-VRF refusal,
corrects T16's explanation, and renames the shared case so it accepts
only EADDRNOTAVAIL or ENETUNREACH while recording the actual errno.
The fake continues to exercise EADDRNOTAVAIL; the required live matrix
exercises each observed real-kernel branch. No daemon behavior changes.

Phase 6's instruction “Never weaken a rule to make a gate pass” required
the maintainer's decision before application. That decision is resolved.
The fresh required matrix in ../matrix-20261031T071523Z-3533819 tests the
applied correction. Its final outcome and per-target errnos are recorded
in [required-kernel behavior](../../../docs/kernel-behavior.md). Coverage
and other packages remain open. Native all-feature tests, strict source
links and warning-denied Clippy pass after application (approved-*.log);
approved-kernel.log records their native kernel. The live matrix records
the real 99/101 distinction separately from the fake's errno 99.
