# Required matrix on db7c1d2

All thirteen required profiles pass on signed
`db7c1d2da830b8180d266a64334a8266fb1f69ec`.
`result.log` records `MATRIX_RESULT=0`. Initial and final target selections
agree; both tracked Rust/test source patches are empty.

| Target | Normal | Clock/pause |
|---|---|---|
| Ubuntu 6.8.0-147.147 / 6.8.0-147-generic | pass | pass |
| Vanilla 6.8.12 | pass | pass |
| Ubuntu 7.0.0-42.42 / 7.0.0-42-generic | pass | pass |
| Vanilla 7.0.14 | pass | pass |
| Mainline 7.4-rc1 / 7.4.0-rc1 | pass | pass |

Each normal profile passes the live unit, Linux and review suites,
81 ordinary binary cases, three filesystem cases, both signal-thread
resource refusals, all 37 process cases and all 27 normal scenarios.
The extra profiles pass IPv6 disabled at boot, IPv6 absent from the build
and missing-Ethernet-driver recovery.

Every target also runs the ACK-only family-data witness: two real ACKs
without family data return EPROTO and leave the family cache empty.
Wrong-tunnel session queries retain the observed distinction: both 6.8
targets return no record; the three newer targets return the other
tunnel's session, which the adapter rejects.

This is a complete serial run with the shipping runner and existing timing
assertions. It does not erase earlier parallel clock failures or establish
ten-run determinism. The later readiness/resync and model-test batch has
separate qualification; this result applies to the signed source above.
