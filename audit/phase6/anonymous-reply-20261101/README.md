# Anonymous DHCPv6 Reply validation: upstream correction required

Released iphost 0.4.3 accepts a Reply containing a Client Identifier when
the request was anonymous. Its parser checks a supplied Reply identifier
only when the local client has a DUID. After accepting the invalid Reply,
the client closes that exchange and ignores the valid Reply that follows.

The live witness sends two same-transaction Replies from one controlled
server: first a Client Identifier and DNS server 2001:db8::53, then the
correct anonymous Reply with no Client Identifier and server 2001:db8::54.
Both include a Server Identifier. Three musl container runs select ::53
and fail the expected ::54 assertion in 0.25 s each. The test uses the
existing namespace fixture; no host networking is changed.

`revision` identifies downstream 0bc668b; `witness.patch` adds the failing
ignored regression. The witness is restored out of shipping source after
the baseline runs. Its failed profiles are not part of coverage.

This contradicts V12's matching-or-absent Client Identifier condition and
[RFC 8415 §16.10](https://www.rfc-editor.org/rfc/rfc8415.html#section-16.10):
a Reply to a request without a Client Identifier must omit that option.
The spec is not being relaxed to accept the observed result.

Fresh upstream main is 91fd9f881a76c7700583ce8720587c0060f6a61b, the same
revision as the released crate. The upstream correction, regression,
compatibility checks, release and downstream integration remain required
under `docs/upstream-iphost.md` and `CONTRIBUTING.md`.
The existing identified-client tolerance for an absent Reply identifier
is separate documented behavior and must be preserved.

The required matrix continues on frozen production source 11bef84.
Its positive profiles do not prove this previously missing validation case.
Current passing-source coverage remains 97.01% lines / 89.89% branches;
that percentage does not establish V12 conformance.
