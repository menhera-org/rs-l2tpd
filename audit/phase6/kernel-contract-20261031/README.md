# Required vanilla 6.8.12 contradicts the universal source-error fact

The full matrix's vanilla 6.8.12 conformance run fails the shared
`no_ipv6_source_is_eaddrnotavail` case: connect in an empty, up VRF with
no IPv6 source or route returns errno 101 (ENETUNREACH), while the test
requires 99 (EADDRNOTAVAIL). The corresponding Ubuntu 6.8.0-147 guest
passes. See ../matrix-20261031T062607Z-3496031/vanilla-6.8.12/run.log
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

`proposed.patch` is a review proposal, not applied or tested. It makes
K26/K34 describe the observed kernel-dependent empty-VRF refusal,
corrects T16's explanation, and renames the shared case so it accepts
only EADDRNOTAVAIL or ENETUNREACH while recording the actual errno.
The fake continues to exercise EADDRNOTAVAIL; the required live matrix
exercises each observed real-kernel branch. No daemon behavior changes.

Phase 6's instruction “Never weaken a rule to make a gate pass” requires
the maintainer's decision before applying this proposal. P3 cannot be
called green while this mismatch remains. Other targets continue with
the original assertion, and coverage/other packages remain open.
