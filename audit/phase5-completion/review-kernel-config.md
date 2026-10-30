# Review: kernel boundary (src/kernel/linux, src/kernel/mod.rs) and configuration layer (src/config)

Scope: security and spec conformance. Kernel facts verified in the Ubuntu 6.8 tree at
`/tmp/claude-1001/-home-dev-rs-l2tpd/c965bace-0e3f-4e30-bfa8-e90ff03ba9a1/scratchpad/kernels/ubuntu-6.8`
(that tree has no `lib/`, so the one `lib/ctype.c` fact below is from memory and marked so).
Upstream crates read: `l2tp` 0.5.0 (`/home/dev/l2tp-rs`), `netlink-packet-l2tp` 0.4.0,
`netlink-packet-core` 0.9.0, `netlink-sys` 0.9.0 (cargo registry).

No High-severity finding. Nothing panics on kernel input, no sender/port confusion, no cookie leak.

## Findings (ranked)

### 1. Medium — Spec deviation (C7, C10): all-numeric labels are accepted as host names
`src/config/text.rs:56-67` (`host_name`). A label of 1–63 `[A-Za-z0-9-]` passes, so
`remote_addr = "300.1.1.1"`, `"1.2.3"`, `"01.2.3.4"` (Rust rejects leading zeros as an
IPv4 literal) and `"1"` are all classified as host names. Effect: an operator's mistyped
IPv4 literal becomes a DNS lookup of that string (with `ip_version` required); with
`ip_version` absent the warning is "ip_version: required for a host name", which points the
operator at the wrong field. C7's text ("labels of ... letters, digits and hyphens") permits
this literally, but RFC 1123 §2.1 / RFC 3696 §2 reserve an all-digit final label for IPv4
syntax. Recommend: `host_name` rejects a name whose last label is all digits, and C7 says so.
`tests.rs:243` (`/// spec: C7`) has no such case.

### 2. Low — Spec ambiguity (C12 two-pass text vs. code): a colliding new entry that exists in the accepted configuration is retained, not left out
`src/config/partial.rs:293-313`. In pass 1 a new valid entry whose `fits()` fails because an
earlier (by name) new valid entry took its identifier is a hard mistake; if `previous` has the
name, the code pushes `KeptPrevious` and re-inserts the old values in pass 2. C12 says "a new
valid entry that collides with another new valid entry is left out as the later one", then
defines retained entries as "a hard mistake with values in force". Input: accepted `a=10,b=20`;
reload `a=30,b=30` → code yields `a=30`, `b=20` (retained) with a warning; the first-pass
sentence of C12 says `b` is left out (removed from the kernel). The behaviour is the safer one
but the spec and the code disagree; `tests.rs:900` (`/// spec: C12`,
`new_valid_entries_collide_among_themselves_first`) only covers `b` absent from `previous`,
so the tag does not exercise this branch. Decide, then fix the spec or the code and add the test.

### 3. Low — Spec deviation (C10/C11/C13, O8): a host-name tunnel without `ip_version` loses its `resolver_name`
`src/config/partial.rs:399-407` with `src/config/mod.rs:369-371, 398-405`. Host name +
missing/invalid `ip_version` → tolerated → `make_peerless` → `remote_addr = None`; the loop in
`tolerate` re-checks, `resolver_name` is now "used only with a host name" → second tolerated
mistake and `resolver_name = None`. Input:
`remote_addr = "peer.example"\nresolver_name = "r"` (no `ip_version`) → two warnings, the
second misleading (the operator did give a host name), and the accepted configuration and
`--check` output (O8) no longer carry `resolver_name`. C10's "resolver_name on a literal
address" row does not apply here. Suggest tolerating `resolver_name` only when the configured
`remote_addr` parsed as a literal (use `hint`/the original text, not the corrected entry).

### 4. Low — Spec deviation (R10, E20 vs. K36): buffer size and count
`src/kernel/linux/request.rs:31, 88-99`. `SUBSCRIPTION_BUFFER = 8 MiB` is requested with
`SO_RCVBUFFORCE`; K36 itself notes the kernel doubles it (`net/core/sock.c` `sk_rcvbuf =
max(val*2, ...)`), so each socket gets 16 MiB, and there are three subscriptions
(`monitor.rs:146`, `lifetime.rs:151`, `l2tp.rs:396`), not the "two netlink monitors" of R10.
Either request 4 MiB or amend R10/E20 ("three sockets, 16 MiB effective"). Order
(RCVBUFFORCE then RCVBUF fallback with a warning) matches R10.

### 5. Low — Robustness (P19/G1 spirit): `getrandom` failure panics the reconciler
`src/kernel/linux/mod.rs:81-85`: `getrandom::fill(&mut bytes).expect(...)`. `getrandom(2)`
can fail under a seccomp policy (ENOSYS/EPERM) in an unprivileged container; the comment's
"does not fail otherwise" assumes an unfiltered kernel. The trait returns `[u8; 3]` so there
is no error path; a panic here takes the reconciler thread down. Suggest `io::Result` or a
fallback (e.g. a monotonic counter mixed with the pid).

### 6. Low — Robustness: dumps silently drop undecodable links/addresses
`src/kernel/linux/rtnl.rs:196, 214`: `links.extend(parse_link(payload).map(..))` and
`addrs.extend(parse_addr(payload))`. `parse_link` returns `None` for any NLA iterator error
or an `IFLA_MASTER` of unexpected size (`rtnl.rs:44, 50`), so one odd foreign device makes
the device invisible to an E20 resync with no log line, and a configured bind device named
like it would never be found by `dump_links`. Kernel NLAs are well-formed today; add a
`log::debug!` so the condition is diagnosable.

### 7. Low — Hygiene (O5): `Debug` bound on request payloads that carry cookies
`src/kernel/linux/request.rs:146, 175`: `I: NetlinkSerializable + Debug`. The payload for
`create_session` is `GenlMessage<L2tpMessage>` whose `L2tpAttribute::Cookie(Vec<u8>)` derives
`Debug` with the bytes. Nothing formats it today (checked every `{..:?}` in `src/`), but the
bound exists only to be printable and invites a future `log::debug!("{payload:?}")`. Drop the
bound if `NetlinkMessage` does not require it, or add a `// O5` comment.

### 8. Low — Spec precedence (C10): a hard mistake is masked by an earlier tolerated one
`src/config/mod.rs:373-396`: for `remote_addr = "fe80::1"`, no `bind_interface`,
`ip_version = "V4"`, the family mismatch (tolerated) is checked before the link-local-without-
zone rule (hard, T27/R47); `make_peerless` then removes the address, so the tunnel is applied
peerless with a warning instead of being left out. C10 lists both rows without precedence;
harmless in effect (no peer either way) but worth a sentence in C10.

### 9. Info — Test weaknesses in `src/config/tests.rs`
- `tunnel_host_names` (`/// spec: C7`, l.243): no non-ASCII/IDN case (e.g. `bücher.example`),
  no all-numeric case (finding 1), no 253-bytes-plus-trailing-dot case.
- `tunnel_literals` (l.199): no `::ffff:192.0.2.1` with `ip_version = "V6"` (must be a
  tolerated family mismatch since the literal is IPv4).
- `new_valid_entries_collide_among_themselves_first` (l.900): see finding 2.
- `merging` (l.917): C2's "a key cannot be removed by a later document" is only implied
  (`[host]` empty keeps `fix_bindv6only = false`); an explicit `[tunnels.a]` empty-table case
  would pin it.

### 10. Info — K31 nuance (verified)
`dev_set_mac_address` (`net/core/dev.c:9020-9044`) calls `ndo_set_mac_address` (`eth_mac_addr`,
`l2tp_eth.c:100`, EBUSY via `eth_prepare_mac_addr_change` while running) only when
`memcmp(dev->dev_addr, sa->sa_data)` differs: setting the address a device already has
succeeds while up. `rtnl.rs:162-185` passes EBUSY through and `reconciler/sessions.rs:565-569`
re-applies only when the address differs, so behaviour is consistent; K31 could say "an
unchanged address is accepted while up".

## Checked and found clean

- **Netlink parsing (P19/G1)**: `request.rs:56-71` `messages()` relies on
  `NetlinkBuffer::new_checked` (netlink-packet-core 0.9.0 `buffer.rs:165-187`), which rejects
  `len < 16`, `nlmsg_len > buffer` and `nlmsg_len < 16`, so `&rest[16..len]` cannot panic;
  padding uses `get(..).unwrap_or_default()`. `ErrorBuffer::new_checked` (`error.rs:193-205`)
  guards the 20-byte `nlmsgerr`; `DoneBuffer` failure maps to code 0. `parse_link`/`parse_addr`
  use `get(..)?` and `NlasIterator` (`nla.rs:58-72` checks `len >= 4` and bounds). Lifetime's
  `payload.get(..4)` (`lifetime.rs:108`). `netlink-sys` `recv_from_full` asserts peek==recv
  length, safe for a single reader per socket (true for all four sockets).
- **E22 sender check**: `request.rs:207`, `monitor.rs:125`, `lifetime.rs:94` accept port 0 only.
  Kernel-originated skbs have `NETLINK_CB.portid == 0` (zeroed cb), user sends set it to the
  bound port, port 0 cannot be bound (`netlink_bind` → autobind). Multicast vs reply: request
  sockets join no groups; `Feed` sockets never send; the lifetime socket distinguishes by
  `nl_groups == 0` (`af_netlink.c:1122`, `netlink_group_mask(dst_group)`, RTNLGRP_LINK=1).
  Replies are matched by sequence, and a transport failure drops the socket so stale replies
  cannot be mistaken for new ones (`request.rs:153-167`).
- **BPF filter (K10)**: header layout (`nlmsg_type` at 4, `ifi_family` at 16) correct;
  `loaded()` byte-swaps for the big-endian `LD_H` on a host-order header; jump offsets verified
  (1→5, 2→5, 3→8, 4→8/7, 6→8/7); last instruction is `RET`. It runs on broadcast
  (`af_netlink.c:1481`), unicast (`:1347`) and dump (`:2278, :2299`) skbs with `skb->data` at
  the nlmsghdr. Passes exactly `RTM_{NEW,DEL}LINK` with `AF_UNSPEC` and `RTM_{NEW,DEL}ADDR`;
  `decode()` re-applies the family rule when the filter is refused; attach failure falls
  open with a warning (R6).
- **Deadlines / uncertain mutations (A14, E21)**: absolute deadline covers family resolution,
  send, replies and ACK; every transport failure returns `ETIMEDOUT` and reopens;
  `create_session` arms the lifetime capture before the request and resolves an `ETIMEDOUT`
  from the broadcast (`mod.rs:176-187`); `prove` ends the generation on an unanswered lookup.
- **unsafe / fds (T6)**: `lib.rs:25` `#![deny(unsafe_code)]`; no `unsafe` under `src/kernel`
  or `src/config` (all hits are in `src/bin`). Sockets: netlink-sys `SOCK_CLOEXEC`
  (`socket.rs:97-104`), l2tp `socket()` adds `SOCK_CLOEXEC` (`l2tp-rs/src/socket.rs:1058`),
  `try_clone_fd` is `OwnedFd::try_clone` (`F_DUPFD_CLOEXEC`), socket2 sets CLOEXEC.
- **K32 vs `text::ifname`**: `netlink-packet-l2tp` `ifname.rs:109-136` rejects empty, ≥16,
  `.`/`..`, NUL, `/`, `:`, 0x09–0x0d, 0x20 and 0xa0; `dev_valid_name` (`dev.c:1119-1134`)
  is identical given the kernel `_ctype` table marks 160 as `_S|_SP` (`lib/ctype.c`, from
  memory). `text.rs:11-19` adds the `%` rule of C7.
- **Cookies (O5)**: `Cookie`, `ReportedCookie`, `KernelCookie` print length only;
  `PartialConfig` has no `Debug`; `text::cookie` errors print a character count; TOML
  diagnostics are reduced to a byte offset in `src/bin/rs-l2tpd/files.rs:94-99`;
  `KernelCookie` TryFrom error carries the length only (`l2tp-rs/src/types.rs:264-278`).
- **K35**: `KernelMessage::parse_with_param` (`l2tp-rs/src/netlink.rs:95-116`) accepts any
  cookie ≤ 8 bytes; `ReportedCookie::configured` refuses non-4/8 lengths so foreign sessions
  match no entry.
- **Host names (C7)**: 253-byte cap after stripping one trailing dot, labels 1–63, no
  leading/trailing hyphen, ASCII only (IDN rejected), empty label rejected. IPv4-mapped
  literals canonicalised to IPv4 everywhere (`text.rs:29`, `mod.rs:168-172, 574`); zones
  valid only on link-local; link-local without zone or `bind_interface` is hard.
- **Merge (C2), unknown keys (C6)**: field-wise replace, tables merged, `labeled` paths at
  top level, `host`, each entry (`partial.rs:150-240`); wrong types fail the document via
  serde. **C9** order is `BTreeMap<String>` byte order; the later entry is at fault.
  **C12** two passes in dependency order (resolvers, tunnels, sessions) with refusal naming
  the retained entry; the spec example passes (`tests.rs:827`).
- **Zone handling**: `IpEndpoint::v6_scoped` resolves the zone at connect with `SIOCGIFINDEX`
  on the socket itself (namespace-correct), errno passes through; `require_scope` mirrors K27
  (`l2tp-rs/src/socket.rs:1316-1329`), `disconnect` clears `pinned` like the kernel clears the
  binding (K22).

## What I did not check
Reconciler policy around these boundaries beyond the K31 grep; the binary's file loading
(C1, C3, C4) except the TOML-diagnostic line; live-kernel runs of the `#[ignore]` tests.
