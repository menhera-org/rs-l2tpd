# `iphost` 0.4.0 against the resolver specification — 2026-10-27

| Detail | Value |
|---|---|
| Crate | `/home/dev/iphost`, `main` at `eaac342` ("fix (correctness): consistency for one-family failures"), version 0.4.0, unreleased, edition 2024, `rust-version = 1.89` (rs-l2tpd: 1.89 too). First checked at `ff030eb`; the two follow-up commits are reviewed in the last sections. |
| Compared with | `docs/spec/resolvers.md` V1–V15, `configuration.md` C7/C16, `kernel.md` K13/K14/K39, and rs-l2tpd's current use of `iphost` 0.3.3 |
| Verdict | **Compatible, release-ready.** Every rule the specification states can be met with the crate as it is. Eight rules were written more precisely than the crate behaves at `ff030eb` and the crate's behaviour was the better one in each case, so the specification was changed to match. The follow-up commit `971e1eb` removes hickory-resolver, adds the two additions asked for below and changes the lookup timing; the specification was aligned to it too. No change to the crate is required. |

## What the crate provides, mapped to the specification

| Specification | Crate | Notes |
|---|---|---|
| Resolver kinds: address, `ra`, `dhcpv6`, `ipv6`, system (V1, V2) | `Resolver::{System, Static, Ra, Dhcpv6, Ipv6}` | Non-exhaustive enum; `Ipv6` uses only the sources compiled in (`ra`, `dhcpv6` features), so rs-l2tpd must enable both. |
| `addresses` with optional ports, port 53 default (C16) | `StaticResolverConfig::new(impl IntoIterator<Item = SocketAddr>)` | Per-server ports supported. Since `971e1eb` the queries are made by a built-in stub client (RFC 1035 over std sockets): UDP first, TCP when the answer was truncated (verified with a 200-record answer in the container suite). Neither the hosts file nor the `localhost` special case applies; the configured servers are asked directly. |
| Bind interface for queries (V9) | `StaticResolverConfig::with_bind_device(BindDevice::Interface(name) | BindDevice::Vrf(name))` | On Linux both are `SO_BINDTODEVICE` by name, set on a fresh socket per query, so the kernel resolves the name inside the bind and no capability is needed (K22). `Interface` also supplies the scope of link-local servers; `Vrf` does not, so a link-local server behind a VRF needs a zone in its address. |
| System resolver = the libc's (V3) | `Resolver::System` → `getaddrinfo` | As specified. |
| Router advertisements (V10) | `RaResolverConfig::new(interface)`; raw ICMPv6 socket with `ICMP6_FILTER`, `IPV6_RECVHOPLIMIT`; RA validated (type 134, code 0, hop limit 255, link-local source, arrival interface); RDNSS parsed; solicits up to 3 times 4 s apart until the first RA, again whenever the interface is (re)created | Without `CAP_NET_RAW` (`EPERM` on the raw socket) it falls back to `RTNLGRP_ND_USEROPT` on Linux; the two are alternatives, not simultaneous. `RaResolverConfig::source()` reports which (`RaSource::{RawSocket, Netlink}`). Tested in the crate's own privileged-container suite with `accept_ra=0` (raw path) and as `nobody` with `accept_ra=2` (netlink path), and on a VRF member with `raw_l3mdev_accept=0`. |
| RA server lifetimes (V10) | A new RA replaces the previous list; lifetime 0 withdraws; `u32::MAX` is infinite; expired servers are still returned while no unexpired one exists | The specification said expired servers are forgotten; it now says they are used as a last resort, which is what keeps a tunnel resolving through a router outage. |
| DHCPv6 Information-Request (V12) | `Dhcpv6ResolverConfig::new(interface, ClientId)`; UDP 546 with `IPV6_V6ONLY` and `SO_REUSEADDR`, wildcard-bound and tied to the interface; one socket per interface shared by every config on it; RFC 8415 retransmission with jitter (IRT 1 s, MRT 3600 s); Reply checked for transaction id, echoed Client Identifier and status; options 23 and 32; refresh at the Information Refresh Time (default 86400 s, minimum 600 s); servers kept until the next Reply | Tested with dnsmasq, with several clients on one interface and on a VRF member with `udp_l3mdev_accept=0`. The wildcard bind means an address-bound client such as systemd-networkd wins the Replies, which is the behaviour the specification wanted (never steal from the system client). |
| Client identifier (C16 `dhcpv6_identity`, V12) | `ClientId::{DuidLl([u8; 6]), None, RandomDuidLl, Raw(Vec<u8>)}` | `DuidLl` takes the plain six-byte MAC and builds `00:03:00:01` + MAC itself, exactly the "real MAC, not a DUID, always Ethernet" rule. `None` is the RFC 7844 anonymity profile (no Client Identifier at all); `RandomDuidLl` is a random locally administered MAC; `Raw` an exact DUID. The specification's `"anonymous"` now maps to `None`; `"random"` and a raw DUID are added as values the configuration may expose. |
| Unified `ipv6` (V14) | `Ipv6ResolverConfig::new(interface, ClientId)`: starts both; fails only if neither starts; `nameservers()` = DHCPv6's if it has any, else RA's | Precedence is per source, not a merged list: when DHCPv6 has servers only they are queried. The specification said "DHCPv6 first, then RDNSS"; it now says what the crate does, which also matches the tests `ipv6_prefers_dhcpv6` and `ipv6_ra_fallback`. |
| Answer selection and retention (V5, V6) | `IpHostResolver`: one IPv4 and one IPv6 address kept; `stable_pick` keeps the previously selected address while the answer still contains it, else the first; `use_cached_on_error` keeps the cache on failure; `retain_stale_values` keeps a family's address when an answer has no record of that family | The specification's "first usable address" is replaced by the crate's stable rule, which avoids a reconnect whenever answer order changes. V6's "a negative answer keeps the previous answer" needs `retain_stale_values = true`, which is **not the default**; rs-l2tpd must construct with `IpHostResolver::new_with_config(host, true, true)`. Since `eaac342` a family whose query failed with anything but NXDOMAIN keeps its cached address whatever the option says, and `use_cached_on_error` returns that address with the answer; only a negative answer (NODATA or NXDOMAIN) settles a family. |
| Refresh, change notification and lookup bound (V4, A9) | `AutoIpHostResolver::new(host, interval)` or `from_resolver`; `subscribe_changes()` with the `broadcast` feature; `Resolver::max_lookup_time()` | 30 s is the daemon's choice; the broadcast subscriber replaces polling. The worker is sequential: a lookup, then `interval`, so lookups never overlap and the period is the interval plus the lookup's duration. A lookup blocks for at most `max_lookup_time`: `None` for the system resolver; servers × 2 attempts × 5 s for `Static`; 3 s + 30 s (three discovered servers at most) for `Ra`, `Dhcpv6` and `Ipv6`. `spawn_blocking` is fine. |
| Runtime changes (V7, V13) | `set_resolver`, `replace_ip_host`: reset the cache and bump a generation so in-flight lookups for the old configuration are discarded | As specified. |
| Resources (G23, V15) | One thread per RA config, one per DHCPv6 config plus one receive thread per interface, one raw socket per RA config, one UDP socket per DHCPv6 interface; per lookup one helper thread (the A query) and one or two short-lived sockets per server tried | Bounded by the number of configured resolvers; no shared runtime since `971e1eb`. |

## Changes made to the specification

- V4: both families are queried at once; the family `ip_version` names is used; lookups of one host name are sequential; each is bounded per kind (ten seconds per configured server for the address kind, thirty-three seconds for the discovery kinds); the next refresh follows thirty seconds after the previous lookup returned; the address kind consults neither the hosts file nor special names.
- V5: the selected address is the previously selected one while the answer still contains it, else the first usable one.
- V6: the retention of a family's last address through a negative answer is a constructor option of the crate and MUST be enabled.
- V9: binding is by name on a fresh socket per query (the kernel resolves the name inside the bind); for `ra`, `dhcpv6` and `ipv6` the bind interface MUST be a link, not a VRF; a VRF member is fine; a link-local name server behind a VRF needs a zone.
- V10: the netlink group is the fallback when the raw socket cannot be opened, not a second source; a new advertisement replaces the list; lifetime 0 withdraws; expired servers are used only while no unexpired one exists; solicitation is bounded (three, four seconds apart) and restarts when the interface is re-created.
- V11: the daemon's notification loss does not touch the resolvers, which own their sockets.
- V12: one socket per interface shared by all its resolvers; wildcard bind so an address-bound system client wins; `"anonymous"` is "no Client Identifier"; `"random"` and `dhcpv6_duid` (an exact DUID, 3 to 130 bytes) are added.
- V14: precedence is per source; a lookup waits up to three seconds for the first servers from any source.
- V15 (new): resources per resolver; one helper thread per lookup, no shared runtime.
- C16: the identity values above; the link requirement for the discovery methods.
- K14: "fallback" instead of "additional source".
- M14's interval table, A9 and the convergence table in `promises.md`: the refresh is thirty seconds after the previous lookup returned, and the bound to notice a changed answer includes the lookup's own bound.

## For rs-l2tpd (roadmap step 5, not changed now)

- Dependency: `iphost = { version = "0.4", default-features = false, features = ["broadcast", "ra", "dhcpv6"] }`, with `"iphost/serde"` under the `serde` feature; `tracing` stays off because the daemon logs through `log`, so the crate's own diagnostics are silent and the daemon reports from `nameservers()`, `Ipv6ResolverConfig::{dhcpv6, ra}()` returning `None`, `RaResolverConfig::source()` (to say "`CAP_NET_RAW` missing, advertisements are learned only where `accept_ra` is enabled", R4), and lookup errors.
- With those features the crate's tree is six crates besides itself (`fqdn`, `punycode`, `libc`, `socket2`, `tokio` with only `sync`, `pin-project-lite`), down from 162 with hickory-resolver; the supply-chain concern of the first check is gone.
- The existing uses (`IpHost`, `FQDN`, `IpHostResolver::new`, `AutoIpHostResolver::new`, `ipv4_addr`, `ipv6_addr`, `resolve_v4`, `resolve_v6`) still exist unchanged. `Resolver::Static` no longer answers `localhost` locally; nothing in rs-l2tpd relies on that.
- rs-l2tpd's own edition moves from 2021 to 2024 with this work (the maintainer's decision, independent of the crate); the MSRV of 1.89 already allows it.

## Review of `971e1eb` (hickory dropped, stub client added)

What was run, all on this host:

| Check | Result |
|---|---|
| `cargo build --no-default-features` with features `[]`, `custom`, `ra`, `dhcpv6`, `ra,dhcpv6`, `ra,dhcpv6,broadcast,serde,tracing` | all build |
| `cargo test --all-features` | 34 unit tests and 2 doctests pass; the 19 container tests are ignored without the suite |
| `cargo clippy --all-features --all-targets -- -D warnings` | clean |
| `cargo doc --all-features --no-deps` with `RUSTDOCFLAGS=-D warnings` | clean |
| `cargo check --all-features --target` for `x86_64-unknown-freebsd`, `x86_64-unknown-illumos`, `x86_64-apple-darwin`, `x86_64-unknown-netbsd`, `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-musl` | all check (OpenBSD: no target installed, not checked) |
| `tests/linux-bind.sh` (privileged Alpine container, dnsmasq, radvd) | 18 of 18 as root on the raw-socket path, 2 of 2 as `nobody` on the netlink path |

What was read: the whole of `src/custom.rs` and the diffs of the other files. The wire handling is correct where it matters: the header flags (QR, opcode, TC, RCODE) are the right bits; a response is accepted only when id, QR, opcode, `QDCOUNT = 1`, question name (case-insensitive), type and class all match (RFC 5452 section 9.1), and anything else on the connected socket is ignored until the deadline; compression pointers are stepped over and never followed, so no loop is possible; every read is bounds-checked and `ANCOUNT` cannot run past the message; NXDOMAIN ends the lookup, any other failure moves to the next server; truncation retries over TCP within the same five-second deadline, with the device binding applied to the TCP socket too (the two TCP-fallback cases of the suite confirm it); each query uses a fresh unbound socket, so the kernel picks a random ephemeral port, and the id is a SipHash of the clock under per-thread random keys; sockets are close-on-exec by socket2's and std's defaults, which matters for the daemon's descriptor hand-over (T6). The A and AAAA queries run in parallel on a scoped thread, so the bound is per family, not their sum. `random_u32` moved into `custom.rs` without changing its definition.

Findings, none blocking:

1. The bound of a `Static` lookup grows with the configured list (ten seconds per server), while discovered lists are cut to three. The specification states it in V4; an operator who lists many servers accepts the longer bound. The crate could cap static lists too, but that is a policy choice, not a defect.
2. A response that carries no question section (`QDCOUNT = 0`, as some servers send for FORMERR or REFUSED) is ignored rather than ending the query early, so that server costs one five-second timeout. glibc behaves the same; no change needed.
3. When both families fail, the AAAA error is the one reported, even if the A query got the definitive NXDOMAIN. Cosmetic.
4. README's "no dependencies beyond `socket2` and `libc`" omits `windows-sys` on Windows and the pre-existing `fqdn`. Cosmetic.
5. `BindDevice::Interface` is a documented no-op on Windows and NetBSD ("elsewhere: sockets are not bound"). Irrelevant to rs-l2tpd, which is Linux-only, but a consumer there gets unbound queries without an error.

Both additions asked for in the first check exist now: `RaResolverConfig::source()` with `RaSource`, and `Resolver::max_lookup_time()` with a unit test of the arithmetic.

## Review of `eaac342` (one-family failures)

The defect it fixes: at `971e1eb` a lookup whose AAAA query succeeded (even with no records) while its A query timed out or got SERVFAIL returned only the IPv6 addresses as a success, and `IpHostResolver` then treated the missing family as a negative answer, clearing its cached address unless `retain_stale_values` was on, and reporting a change. The fix threads a `Lookup { addrs, v4_failed, v6_failed }` through every resolver kind: a family is "failed" when its query returned an error other than NXDOMAIN. In `resolve()`, a failed family's cache is left exactly as it was, whatever `retain_stale_values` says, and with `use_cached_on_error` its cached address is appended to the returned list. The six combinations were checked by reading: both families answer; one answers and the other is NXDOMAIN (settled, cleared unless retained); one answers and the other fails (kept, returned with `use_cached_on_error`); one is NODATA and the other fails (empty success with the failed flag, not the "no address records" error, so the NODATA family is settled and the failed one kept); both NODATA (the "no address records" error, cache kept by the error path); both fail (the AAAA error is returned, cache kept). `AutoIpHostResolver` reads the cache after each lookup, so a failed family no longer produces a spurious change event. The system resolver has no per-family information and marks nothing, as before.

Checks on this commit: the six feature builds; `cargo test --all-features` with 38 unit tests (four new ones cover the marked family, failure beside NODATA, and the cache with and without `use_cached_on_error`) and 2 doctests; clippy and rustdoc with warnings denied; `cargo check` on the same six targets; `tests/linux-bind.sh` 18 of 18 and 2 of 2. All pass.

Two notes, neither blocking:

1. The doc comment of `IpHostResolver::new_with_config` still describes `retain_stale_values` as "keep the cached address when a resolution returns no address of that family"; since this commit that applies to settled families only, and a failed family is kept regardless. The README does not describe the flags, so nothing else is stale.
2. On Windows only, `if_index` reports a missing interface as `NotFound`, which the new rule reads as "settled" rather than "failed" when a link-local server is scoped by `BindDevice::Interface`. On Linux `if_nametoindex` fails with `ENODEV`, which std leaves uncategorised, so the family is correctly marked failed. Irrelevant to rs-l2tpd.

The specification's V6 now states the per-family rule.

## Not checked

OpenBSD compilation (no rustup target installed here; the FreeBSD build exercises the same `rtable` module with the FreeBSD constants). Behaviour under a flood of mismatched datagrams was reasoned from the code (bounded by the deadline), not measured.
