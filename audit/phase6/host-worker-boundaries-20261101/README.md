# Host-worker refusal and completion boundaries

This test-only addition exercises the binary's real host-worker thread over
its bounded request channel and a Runtime backed by FakeKernel. It sends
an unsupported tunable, invalid store/withdrawal names and an irrelevant
restart observation, both with and without a descriptor store.

Assertions require the original completion IDs, a refused tunable, a
refused withdrawal when a store exists, and successful withdrawal when no
store exists. Two copies of one completion cannot satisfy both outcomes.
An actual Unix stream duplicate must close; the store listener must receive
no invalid datagram. No host tunable is written and no network namespace,
route or interface is changed.

`revision` identifies signed downstream 584062d; `source.patch` contains
only the appended test module. No production code or specification changes.
`focused.log` records the initial focused case; final qualification follows
the added duplicate-completion assertions.

Ten full native binary repetitions, ten instrumented repetitions, three
musl binary repetitions and the common gate pass. Each binary run has 63
ordinary passing cases and four ignored privileged cases. Those privileged
cases retain the preceding successful GNU live/manager qualification.

Five isolated controls fail: changed tunable ID, changed withdrawal ID,
inverted withdrawal result, a leaked duplicate, and a duplicate tunable
completion substituted for withdrawal. Each patch applies after source.patch;
controls are restored and never contribute profiles.

The merged report reaches **8,420/8,671 lines (97.11%)** and
**1,667/1,850 branches (90.11%)**, leaving 251 lines and 183 branches.
It extends the fresh released-0.4.4 collector; no production exclusion,
profile mismatch or saturated region is present. All 4,302 source-region
mappings remain unchanged. Of the complete entries, 4,301 are identical;
one previously uncalled worker instance now exposes its three branch
records. No function is added or removed from that catalog.

The required-kernel matrix runs separately from frozen 584062d. It does
not include this later test declaration. Three normal musl scenario/Incus
repetitions and the root sandbox qualify that same production source in
[the integration record](../iphost044-integration-20261101/README.md).
The 100% coverage and complete clause/history/resource gates remain open.
