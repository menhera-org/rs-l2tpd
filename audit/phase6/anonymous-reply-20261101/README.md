# Anonymous DHCPv6 Reply validation: released correction

iphost **0.4.4 is published** from signed upstream commit
[e064cc0](https://github.com/metastable-void/iphost/commit/e064cc07db13e813ead92dca07f98c8d44ae0bc9).
The downloaded package's checksum matches Cargo.lock; its VCS metadata names
that commit and its DHCPv6 source matches the tested correction.
Publication, signature, package and VCS records are retained here.

Released 0.4.3 accepts a Reply containing a Client Identifier when its
request was anonymous. After accepting that Reply, it closes the exchange
and ignores the valid Reply that follows. The live witness sends two
same-transaction Replies from one controlled server: first a Client
Identifier and DNS server 2001:db8::53, then no Client Identifier and server
2001:db8::54. Both include a Server Identifier. Three baseline musl runs
select ::53 and fail the expected ::54 assertion in 0.25 s each.

This contradicts V12 and
[RFC 8415 §16.10](https://www.rfc-editor.org/rfc/rfc8415.html#section-16.10):
a Reply to a request without a Client Identifier must omit that option.
The specification is unchanged.

## Correction and qualification

The parser now accepts a supplied Reply identifier only when the local
client has the same DUID. Anonymous clients reject any Client Identifier,
including an empty one. Matching identifiers remain accepted. The existing
documented tolerance for an identified client's Reply without an identifier
is preserved. Public signatures, dependencies and other DNS policies are unchanged.

The focused upstream regression fails on 91fd9f8 and passes with the fix.
Ten all-feature unit runs, three musl unit runs, no-default/custom/RA/DHCPv6/
combined-feature suites, Clippy, warning-denied docs, Rust 1.89 and package
verification pass. Nine all-target compile checks pass: three additional
Linux musl architectures, Windows MSVC, Intel/ARM macOS, FreeBSD, NetBSD and
illumos. Those other operating systems are not executed.

Three live upstream repetitions each pass nine listener/queue probes,
eighteen privileged binding/discovery cases and two unprivileged fallback
cases. The existing fixture uses the recorded pre-provisioned image with
its apk-installation line omitted; every container has network none.

An isolated candidate checkout passes the downstream witness three times.
It uses a temporary local path only to test the proposal before publication;
that is not released-dependency acceptance. Three subsequent runs against
the downloaded 0.4.4 registry release also pass in 0.25 s each. The shipping
manifest and lockfile use the registry release, with no path override.

## Sources and remaining integration

`revision` identifies downstream 0bc668b; `witness.patch` adds the regression.
`upstream-regression.patch` and `upstream-fix.patch` identify the upstream
counterexample and correction. `candidate-source.patch` records the isolated
proposal's source. Failed witnesses never enter production coverage.

The required matrix on production 11bef84 retains its iphost 0.4.3 scope.
The new matrix on frozen 584062d with registry 0.4.4 passes all thirteen
profiles; this anonymous Reply case and the positive client-ID/binding
case pass on all five required kernels. Native/common, GNU/musl live,
Incus, root-systemd and a fresh coverage collection also pass in
`../iphost044-integration-20261101/`. Later test-only packages retain their
separate source and execution records; 100% coverage remains open.
The preceding 97.01% line / 89.89% branch report remains historical;
complete clause/history/resource proof and 100% coverage remain open.
