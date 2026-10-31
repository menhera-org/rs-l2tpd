# Upstream iphost work: protocol fixes and optional failure fallback

**Done:** `iphost` 0.4.1, published 2026-10-29 and pinned by this
repository, carries both items (`74c6338` the RDNSS and deadline fixes,
`34b6e2c` `Ipv6ResolverConfig::with_failure_fallback`). The daemon
enables the fallback; downstream adapter checks and the released crate's
regressions are recorded in the
Phase 2–3 verification (repository file `audit/PHASE23_VERIFICATION_2026-10-29.md`).
The text below is the instruction as given.

The Phase 6 shared-discovery regression later exposed DHCPv6 listener
reuse across equally named interfaces in different network namespaces.
`iphost` 0.4.2, published 2026-10-31 and pinned, fixes that cache key and
releases dead listener records. The compatible release preserves public
APIs, features and DNS policy. Namespace cookies require no procfs or extra
privilege; older Linux kernels without that option use the namespace inode
from `/proc/thread-self/ns/net`. Repository record
`audit/phase6/upstream-netns-20261031/` retains the failing counterexamples,
upstream checks and downstream integration results.

The subsequent resource check found cached closed subscribers and unbounded
pending datagrams. `iphost` 0.4.3, published 2026-10-31 and pinned, removes
subscriptions when their receivers drop and caps each client's FIFO at
64 datagrams. Overflow drops incoming datagrams for that client without
blocking other clients; retransmission and validation are unchanged.
Repository record `audit/phase6/upstream-dhcp-queues-20261031/` retains the
counterexamples, nine live probes repeated three times and integration scope.

This is an implementation instruction for the general-purpose `iphost`
crate, based on its published 0.4.0 behavior and the source inspected on
2026-10-29. Recheck the current upstream tree before editing: a correction
may already have landed. The downstream caller is rs-l2tpd, but its
specification does not redefine iphost's public contract.

Fix real bugs against iphost's own README, rustdoc and stated protocols
directly. Prefer compatible releases and additive APIs; compatibility is
not a reason to preserve a protocol defect behind an opt-in flag.
Separate those corrections from new policy features. Keep changes in
iphost independently useful and testable without an L2TP daemon.

## Scope and classification

| Item | Existing iphost contract | Work |
|---|---|---|
| RDNSS updates | `src/ra.rs` identifies the module as RDNSS/RFC 8106; public configs discover DNS servers on an interface. The private `State::apply` clears all servers on most updates. | Protocol bug: update individual addresses and preserve omitted live entries. Fix the normal path. |
| Stale RDNSS servers | `RaResolverConfig::nameservers` explicitly returns expired servers when none are live. | Preserve this documented policy. It is an availability extension to RFC expiry behavior, not a bug to remove silently. Explicit lifetime-zero withdrawal must remove stale copies too. |
| Unified IPv6 selection | README and `Ipv6ResolverConfig::nameservers` prefer a nonempty DHCPv6 list; otherwise use RA. Existing lookup bounds cover one list. | Failure-driven fallback is an additive capability, not an established violation of the current selection-only contract. Add an explicit option; preserve existing selection-only defaults and bounds. |
| System lookup deadline | `Resolver::max_lookup_time` returns `None` for `System`; resolution uses libc. | This is documented, not an iphost bug. Keep the truthful bound. Clarify worker/drop implications where needed; daemon scheduling belongs downstream. |
| Any further discrepancy found while implementing | Compare the actual public contract, implementation and a focused counterexample. | Fix a demonstrated bug with a regression. Do not expand the work into a speculative rewrite. |

Primary protocol source: [RFC 8106 §6.2](https://www.rfc-editor.org/rfc/rfc8106.html#section-6.2).
Relevant files: `src/ra.rs`, `src/ipv6.rs`, `src/custom.rs`,
`src/resolver.rs`, their tests, README and rustdoc.

## 1. Correct RDNSS repository updates

Reproduce this first using a virtual clock and parsed updates:

1. Receive A and B with positive lifetimes.
2. Receive an option withdrawing A alone (lifetime zero).
3. B must remain available until its own expiry. The current full-list
   replacement incorrectly removes B.

Key entries by IPv6 server address within the listener's interface.
Insert or refresh each advertised nonzero-lifetime address. Remove only
the address explicitly withdrawn by a zero lifetime. An omitted address,
an RA without RDNSS, or an update from a second router must not flush the
repository. Malformed input must not partially erase previously valid
state. Repeated addresses must not create duplicates.

Apply identical semantics to a whole raw RA and individual kernel
ND_USEROPT messages. Stop reconstructing replacement snapshots through
the one-second `MERGE_WINDOW`: incremental updates need no assumption
about message spacing or router interleaving. Preserve raw RA validation,
interface scoping, solicitation, the Linux netlink fallback and existing
platform behavior.

Preserve `nameservers()`' documented stale-server fallback. A zero-lifetime
withdrawal removes a server from both live and stale candidates; it must
never return through stale fallback. Refreshing a previously expired
entry makes it live again. Prefer refreshed addresses in advertised
order, retaining omitted entries behind them.

Incremental storage must be finite even with many infinite-lifetime
advertisements. Use a documented finite repository limit; rs-l2tpd's
target is 64 distinct addresses, including stale ones. A default of 64
is sufficient; if upstream selects another default, an additive capacity
builder can let callers select 64. Evict expired entries first, then the
earliest finite expiry, infinite lifetimes last, with address byte order
as a deterministic tie-breaker. Process withdrawals even when full.
Keep the existing limit of three queried discovered servers distinct
from the repository's capacity.

Required focused tests:

- A+B followed by withdrawal of A; B survives.
- A+B followed by refresh of A; B keeps its old expiry.
- A later RA with no RDNSS; no change.
- Multiple options, delayed netlink messages and two interleaved routers
  produce the same repository as their equivalent raw updates.
- Zero, finite and infinite lifetimes; stale fallback; withdrawn stale
  entries never resurrect; no duplicate entries.
- More than the capacity with infinite lifetimes; deterministic bounded
  eviction without losing the ability to withdraw.
- Existing public constructors, clone sharing, feature/platform branches
  and valid packet validation continue to work.

## 2. Add optional per-family failure fallback

Add a builder-style option on `Ipv6ResolverConfig` for failure fallback.
A name such as `with_failure_fallback(bool)` is illustrative, not a
required spelling. Its default is the existing selection-only policy.
Do not change constructor signatures, require Tokio, or add daemon types.

When enabled:

- Wait up to three seconds once for the first discovery result, then take
  bounded lists of up to three servers per source.
- Resolve A and AAAA independently, with DHCPv6-provided servers first.
  A positive answer or definitive negative answer for a family is final.
  In particular, do not consult RA to override NXDOMAIN or NOERROR/NODATA.
- Only an absent list or exhausted failures (timeout, transport error,
  SERVFAIL, REFUSED, malformed responses) advances that family to RA.
  Preserve the other family's completed result and do not query it again.
- After both sources fail, report that family's failure through the
  existing internal outcome/cache rules. Preserve `use_cached_on_error`,
  `retain_stale_values`, stable address selection and generation
  invalidation. Do not make fallback silently redefine cache behavior.
- Start with DHCPv6 again on the next lookup; fallback does not erase
  discovered servers or change discovery lifetimes.
- Keep binding and link-local scope unchanged across both sources.
  General-purpose iphost VRF/routing-domain support stays supported;
  rs-l2tpd's ban on resolver VRF devices belongs only in its caller.

Keep `nameservers()`' documented preferred-list meaning; document that a
fallback-enabled lookup can subsequently consult the other source.
Callers needing source lists already have the source accessors.

The worst case with both sources enabled is 3 + 30 + 30 = 63 seconds,
with the families in parallel. A single-source or legacy selection-only
configuration retains its 33-second bound. Update `max_lookup_time()`
according to the configured policy and compiled sources. Do not retain
a 33-second advertised bound while allowing 63 seconds of network work.
Per-attempt deadlines include TCP fallback and unrelated/malformed
traffic; no receive loop may reset the absolute deadline.

Required tests, with injected source lists/transport and virtual time:

- Default policy still selects only a nonempty DHCPv6 list.
- Opt-in: dead DHCPv6 DNS followed by working RA DNS succeeds.
- DHCPv6 positive and negative answers never fall through for that family.
- One family succeeds through DHCPv6 while the other falls back.
- Both sources fail; existing cache options behave as documented.
- The next refresh retries recovered DHCPv6 first.
- One source cannot start, has no servers, or only one feature is enabled.
- Exact upper bounds, including discovery wait, UDP/TCP truncation,
  repeated errors and partial-family results; no new wait per source.
- Clone/equality behavior and the new builder are documented and tested.

If current upstream already promises failure fallback by default,
treat a violation of that promise as a bug and fix the default. Record
the public text establishing that classification. Do not retain broken
documented behavior merely to preserve the inspected 0.4.0 implementation.

## 3. Keep system DNS and caller scheduling honest

Leave `Resolver::System.max_lookup_time() == None`. Do not wrap libc
in a detached thread per timeout and call that bounded resolution:
it leaves the work running and can exhaust process resources.

Document that an automatic resolver whose worker is inside libc cannot
necessarily stop until that call returns. Dropping interest, timing out
a caller's wait or replacing a hostname does not cancel libc execution.
Keep existing generation checks so obsolete results cannot update the
new hostname's cache.

Do not impose rs-l2tpd's worker limits, refresh interval, tunnel
readiness, device ownership or answer-retention policy on iphost.
The daemon implements its own separate process-wide budgets, fair
admission, coalesced results and non-blocking shutdown (V3, V15).
No new upstream executor is requested.

## Compatibility and completion

Prefer a compatible 0.4.x release if working on that line; follow
upstream's current versioning policy if it has advanced. Protocol bug
fixes should update the normal behavior with a release note. New fallback
policy should be additive unless newer public documentation already
makes it mandatory. Preserve existing public signatures, constructors,
features, defaults unrelated to the bugs, and general-purpose platform
support. Use Rust tests and helpers; no interpreter dependency or
Linux-only assumptions in portable DNS code.

Run the upstream format, unit, feature-matrix, lint and documentation
checks. Include no-default, custom-only, RA-only, DHCPv6-only and combined
feature builds where supported; exercise portable DNS logic on the
project's supported targets. Linux discovery needs its existing live
tests too. Run version-appropriate API compatibility checks and compile
an existing-API consumer. No dependency is justified merely for test
convenience.

Deliver separately reviewable bug-fix and additive-feature changes,
with the old/new behavior, documented contract, regression and
compatibility impact in each description. Provide the released version,
tests actually run and remaining platform limits.

## Downstream integration gate

After the upstream release is available, update rs-l2tpd's manifest and
lockfile, enable failure fallback explicitly, and update the dependency
status. Run V10/V14 adapter cases against that released crate. Implement
V15 admission and lifecycle controls in the daemon, not upstream.
Until then, the specs describe the target, and these resolver cases remain
open phase-exit requirements. Never mark them implemented from a
documentation edit or an upstream API that is only proposed.
