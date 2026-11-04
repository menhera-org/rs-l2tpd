# Resolver integration

[Documentation index](README.md) · [Dependencies](dependencies.md#upstream-needs)

The daemon uses released `iphost` 0.4.4 with `custom`, `ra` and `dhcpv6`.
The library owns DNS/discovery protocols; rs-l2tpd owns scheduling, device
validation, answer selection and retention. There is no pending upstream
resolver implementation gate for v0.2.0.

## Upstream contracts used here

- RDNSS updates apply per address. Omitted live entries survive refreshes
  and unrelated advertisements. Lifetime-zero withdrawal removes live and
  stale copies. The repository is bounded at 64 addresses; discovered
  query lists remain independently bounded at three servers.
- The unified IPv6 resolver enables
  `Ipv6ResolverConfig::with_failure_fallback(true)`. Per family, DHCPv6
  servers are tried first; absence or exhausted failures permits RA.
  Positive and definitive negative answers are final. The bound is
  63 seconds with both sources, 33 seconds with one. Upstream's default
  selection-only policy is unchanged.
- DHCPv6 listeners are scoped by interface and network namespace.
  Dropped receivers release subscriptions; each client's pending FIFO
  holds at most 64 datagrams. Overflow drops incoming datagrams for that
  client without blocking others.
- Anonymous DHCPv6 clients reject Replies containing any Client Identifier,
  including an empty one. Identified clients accept matching identifiers
  and retain the documented tolerance for a missing Reply identifier.
- `Resolver::System.max_lookup_time()` is `None`: libc lookup cannot be
  canceled by dropping interest or timing out a caller's wait.

The daemon validates a resolver bind interface as a non-VRF device and uses
`BindDevice::Interface`; upstream's general-purpose VRF support is unaffected.
The daemon selects usable answers and retains them according to V5/V6,
rather than relying on upstream stale-answer policy. Configuration generations
prevent obsolete results from updating current state.

## Downstream execution

Separate process-wide budgets admit eight system and eight configured
lookups. Permits remain occupied until their calls return, even after the
configuration changes. Current jobs/results coalesce, dispatch preserves the
instance's network namespace, and shutdown does not join blocked libc calls.
Unused discovery and dispatcher state is released. No automatic upstream
resolver executor is used.

The live adapter cases exchange RA, DHCPv6 and DNS traffic with controlled
peers. Wire-identity and anonymous-Reply cases run in every normal kernel
profile; they do not establish every upstream parser refusal on every
kernel. [Testing](testing.md#contract-correction-acceptance-cases) and the
[kernel evidence map](kernel-evidence.md) retain that distinction.

## Further upstream work

Reproduce a discrepancy against upstream's own documented protocol/API
contract before changing it. Fix protocol defects in the normal path with
regressions; introduce new policy as compatible, explicit options when
appropriate. Keep general-purpose code portable and independently testable.
Do not move daemon worker budgets, readiness, device ownership or answer
retention into `iphost`.

A required missing upstream capability stops the dependent implementation
until a release supplies it. Run upstream feature, protocol, lint and
documentation checks, then the downstream adapter and Phase 6 gates against
the registry release. Historical development instructions, counterexamples
and publication records remain in Git history.
