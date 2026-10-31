# Current host state exceeds the configuration-only cache bound

Two deterministic witnesses keep the configuration at one tunnel and vary
only current host state. They measure the reconciler's own collections,
separately from the fake kernel and its notification queues.

| Current host state | 100 | 1,000 | 10,000 |
|---|---|---|---|
| Addresses on one bound device | 100 retained addresses | 1,000 retained addresses | 10,000 retained addresses |
| Members of one bound VRF | 100 retained master/member records | 1,000 retained master/member records | 10,000 retained master/member records |

Both cases start fresh; no reload history accumulates. Configuration remains
one tunnel throughout. Shutdown succeeds. The passing witness assertions
establish this growth; **they are not G23 acceptance tests**.

The address cache deduplicates notifications. The master/member indexes let
address events be matched to a bound VRF without querying unrelated devices.
All tested records belong to current configured dependencies; earlier
history-release tests therefore do not expose this dimension. No byte/RSS
bound or live-kernel performance result is claimed by these fake-only cases.

## Source and reproduction

`revision` identifies the archived daemon source. `source.patch` adds the
configuration-correction production change; `witness.patch` appends the
isolated test module. No dependency override or shipping cache change is
made. Only these two declarations execute in the isolated checkout;
`witness.log` retains both results.

```sh
# In a disposable checkout of the recorded revision:
patch -p1 < source.patch
patch -p1 < witness.patch
cargo test --locked --all-features --lib reconciler::address_bound_witness:: -- --test-threads=1 --nocapture
```

## Remaining G23 work

The written G23 bound names current configuration, monitor buffers, bounded
discovery state and fixed lookup/retirement budgets. This collection also
scales with current addresses and VRF members. A configuration-only bound
has not been established. G23 stays open; no specification is changed and
no fixed cache cap or silent eviction is introduced.

A correction must preserve E4/E6/E7 matching, M16's restriction on unrelated
kernel queries, event-cost bounds and history cleanup. Transient full
link/address dump vectors also need inclusion in the resource proof.
The H11 decision and upstream nix release are separate pending requirements.

## Prepared contract choice

`proposed.patch` is unapplied. It counts current link/address state needed by
configured dependencies in G23's bound, while requiring streamed temporary
inventories and release when the final configured dependency disappears.
It preserves M16's restriction on querying unrelated events. This changes
the written resource contract and needs a maintainer decision under Phase 6's
rule against weakening a gate. Existing full-namespace dump vectors still
need work even if the proposal is accepted; the patch declares no gate green.
