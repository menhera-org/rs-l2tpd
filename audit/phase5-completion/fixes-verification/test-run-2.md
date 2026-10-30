# rs-l2tpd verification run 2 — commit 6075fde

Host: workspace1, Linux 6.8.0-147-generic (Ubuntu 26.04.1), user `dev`, no sudo. Tree clean at 6075fde, nothing edited.
All commands via rexec; logs in `/tmp/claude-1001/-home-dev-rs-l2tpd/a5262b72-9b33-48ea-8c09-db4f8a9a44fe/scratchpad/logs2/`, scenario outputs in `.../scratchpad/reconnect2/`.
Native `CARGO_TARGET_DIR=/home/dev/rs-l2tpd/target`, musl `.../target-musl` (both warm from the earlier run, so build times are incremental).

## 1–4. Gates, native tests, determinism, strict traceability

| # | Command | Exit | Result | Dur | Log |
|---|---------|------|--------|-----|-----|
| 1 | `cargo fmt --check` | 0 | clean | 0s | fmt.log |
| 1 | `cargo clippy --locked --all-features --all-targets -- -D warnings` | 0 | no warnings | 1s | clippy.log |
| 1 | `cargo build --locked --no-default-features` | 0 | ok | 2s | build-nodef.log |
| 1 | `cargo build --locked --no-default-features --features serde` | 0 | ok | 1s | build-serde.log |
| 1 | `RUSTDOCFLAGS=-D warnings cargo doc --no-deps --all-features` | 0 | ok | 1s | doc.log |
| 2 | `cargo test --locked --all-features` | 0 | all pass, see per-binary table | 10s | test-native.log |
| 3 | `cargo test --locked --features fake-kernel,serde --test rules --test kernel-fake --test service` ×3 | 0/0/0 | identical counts each run (kernel-fake 1; rules 1+73; service 23) | 10s,1s,1s | determinism-{1,2,3}.log |
| 4 | `RULEMAP_STRICT=1 SRCLINK_STRICT=1 cargo test --locked --all-features --test rulemap --test srclink` | 101 | rulemap: 2 pass, 1 FAIL (`every_rule_has_a_test_citation`); srclink not reached (cargo stops) | 1s | strict.log |
| 4 | same env, `--test srclink` alone | 101 | 1 pass, 1 FAIL (`kernel_code_cites_the_facts`) | 1s | strict-srclink.log |

Native per-binary counts (step 2):

| Test binary | passed | failed | ignored | note |
|---|---|---|---|---|
| lib unittests (`rs_l2tpd-fadb2bfd8f730164`) | 74 | 0 | 9 | |
| bin unittests (`rs_l2tpd-9efdeacd5b52e729`) | 1 then 38 | 0 | 4 | harness re-execs itself once (first pass "1 passed; 41 filtered out") |
| kernel-fake | 1 | 0 | 0 | |
| kernel-linux | 0 | 0 | 13 | privileged only |
| process | 8 | 0 | 18 | |
| review-kernel | 0 | 0 | 5 | privileged only |
| rulemap (lenient) | 3 | 0 | 0 | |
| rules | 1 then 73 | 0 | 0 | same self-re-exec pattern |
| service | 23 | 0 | 0 | |
| srclink (lenient) | 2 | 0 | 0 | |
| store-kernel | 0 | 0 | 2 | privileged/systemd only |
| doc-tests | 4 + 2 | 0 | 0 | |

No failures in steps 1–3.

### Strict traceability gaps (informational; lenient gates pass, strict gates fail as expected pre-phase-6)

rulemap: "340 rules (330 active), 229 linked to test declarations, 101 without citations". Panic at `tests/tools/rulemap.rs:138:9`. Uncited rules:

A1 A2 A3 A4 A8 A9 A10 A11 A12 A15 A16 A17 A18 A19 A20 A21 E26 G2 G4 G8 G9 G10 G11 G12 G14 G15 G16 G20 G21 H1–H19 (all nineteen) K1 K3 K6 K8 K13 K21 K33 K36 K38 O4 O9 R1 R3 R4 R5 R6 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R21 R22 R23 R24 R25 R26 R27 R28 R29 R30 R31 R34 R35 R36 R37 R38 R39 R40 R41 R42 R43 R44 R45 R46 R48

srclink: "41 facts, 36 cited, 0 functions without a citation"; facts never cited: K13 K14 K33 K38 K40. Panic at `tests/tools/srclink.rs:124:9` (`assertion failed: uncited.is_empty() && missing.is_empty()`).

## 5. Privileged live suites (host kernel 6.8.0-147-generic, inside `docker run --rm --privileged --network none`)

musl build: `cargo test --locked --all-features --target x86_64-unknown-linux-musl --no-run` exit 0, 16s (build-musl.log). Static-pie binary `target-musl/x86_64-unknown-linux-musl/debug/rs-l2tpd`.

| Suite | Image / userspace | Exit | Result | Dur | Log |
|---|---|---|---|---|---|
| `/kernel-unit --ignored` (lib) | rs-l2tpd-audit-vm:local (musl) | 0 | 9 passed, 0 failed (74 filtered) | 11s total | kernel-musl.log |
| `/kernel-linux --ignored` | same | 0 | 13 passed, 0 failed | | kernel-musl.log |
| `/review-kernel --ignored` | same | 0 | 5 passed, 0 failed ("identifier reuse: 0 EEXIST retries over 32 deletions") | | kernel-musl.log |
| binary-unit 3 fixtures + `/process-test --ignored --test-threads=1` | audit-vm (musl) | 0 | fixtures 3/3 ok (each re-exec child ok); process 18 passed, 0 failed (8 filtered) | 21s | process-musl.log |
| same, glibc | ubuntu:26.04 (GLIBC 2.43), native target binaries | 0 | fixtures 3/3 ok; process 18 passed, 0 failed | 27s | process-glibc.log |
| procfs hidden (`mount -t tmpfs tmpfs /proc`): `foreground_reload_and_clean_shutdown_without_network --ignored` | audit-vm (musl) | 0 | 1 passed | 14s | process-noprocfs.log |
| procfs hidden: `setup_prefix_preserves_configuration` | audit-vm (musl) | 0 | 1 passed (it is not `#[ignore]`d, so it was run without `--ignored`; README's wording implies `--ignored`, under which it is filtered to 0 — see noprocfs log) | 11s | process-noprocfs-setup.log |
| store-kernel: `manager_bridge` via `systemd-run --user` (Type=notify, FileDescriptorStoreMax=1) + `kernel_reference` in container | host user systemd + audit-vm | 0 / 0 | both halves `ok` (journal: "test result: ok. 1 passed" after 10.18s; container: 1 passed) | 17s | store.log |
| fdstore `actual_manager_processing_and_address_family_filter` via `systemd-run --user --wait --pipe` (unit rs-l2tpd-phase5-notify-v2) | host user systemd (musl BINARY_UNIT) | 0 | 1 passed; "Finished with result: success" | <1s | fdstore.log |

All privileged suites passed. Not run: QEMU alternative-kernel matrix (not requested; Phase 6).

## 6. Live reconnection scenarios, NEW binary (musl static, mounted read-only at /bin-new)

Scripts copied unchanged from `audit/phase5-completion/reconnect/` to `.../scratchpad/reconnect2/scripts/` (they already reference `/bin-new`; no `old` runs made). Output: `.../scratchpad/reconnect2/out/new-<s>/{result.txt,a.log,b.log}` and `.../reconnect2/run-new-<s>.txt`. Verdict = no unexpected MISSING/CHANGED, every `ping FAIL` only at a step where the script intentionally breaks connectivity, and identical outcome lines to the previous audit's `new-<s>/result.txt`.

| Scenario | Exit | Dur | MISSING | ping FAIL | CHANGED | Verdict | Notes |
|---|---|---|---|---|---|---|---|
| s1 bind device absent → appears as tmp0 → renamed | 0 | 19s | 1 | 0 | 0 | PASS | the one MISSING is the optional `\|\| true` v0.1.5-style "bound tunnel_id=1 socket" pattern (also MISSING in previous audit); t1 connected on rename, siblings t3 connected / t2 pending / t4,t5 absent all seen |
| s2 rename away / delete / re-create veth | 0 | 24s | 0 | 2 | 0 | PASS | FAILs are at "name lost" and "veth deleted" (expected); reconnects on name back and re-create seen, B reconnected ×2 |
| s3 address events (same/other family, B source reselect) | 0 | 25s | 0 | 1 | 0 | PASS | FAIL right after B drops 10.0.0.2 (A still sends to .2) — same as previous run; no reconnect on other-family add; t3 untouched |
| s4 peer unreachable, route appears/removed | 0 | 26s | 0 | 1 | 0 | PASS | connected within 1s of route; FAIL with route removed (expected, 0 log lines); "pid file (readiness) exists: no" at 1s, same as previous audit |
| s5 FQDN peer changes / disappears | 0 | 95s | 0 | 0 | 0 | PASS | new answer 10.0.0.3 applied; tunnel stays connected after name vanishes (40s) |
| s6 VRF absent/created/join/leave/replace, zoned LL peer | 0 | 48s | 0 | 4 | 0 | PASS | FAILs only while vrfA has no member / is deleted (expected); t4,t5,t1 reconnect on enslave and on H13 replacement |
| s7 reloads: bind_interface, remote_addr, family | 0 | 19s | 0 | 1 | 0 | PASS | FAIL only with bind_interface=bindX (absent); l2tp0 ifindex preserved; unchanged reload is a no-op |
| s8 bindv6only=1, fix off (AF_INET sockets) | 0 | 17s | 0 | 1 | 0 | PASS | two reconnects on addr add/del; FAIL only after T4 v6-remote-on-AF_INET reload (expected); t2 connects on route add |
| ll2 replace (zoned LL peer, zone device replaced before first success; failed before fix A2) | 0 | 10s | – | – | – | PASS | vB index 4→6; log goes pending ENETUNREACH → "the zone of its link-local peer is absent" → `connected to fe80::1 from fe80::2`; kernel record `From fe80::2 to fe80::1` |
| ll2 keep (control) | 0 | 10s | – | – | – | PASS | index unchanged 4; connects after `up` |

Previous-audit comparison: the set of MISSING/FAIL/CHANGED lines per scenario is identical to `audit/phase5-completion/reconnect/new-s*/result.txt` (only tx_dropped counters differ by ±1).

### A1 check (direct creation without `interface_hwaddr`)

Scenario configs set no `interface_hwaddr`, so every session must be created directly. In all of s1–s8 (both daemons A and B) every session log line is `session sN (...): created as l2tpN` with the configured name, never a staging name; e.g. s1 shows all ten sessions (s1..s5 on both sides) `created as l2tp0..l2tp4`. `ip -o link` in s4 shows `l2tp1` present (state DOWN) while its tunnel is still pending. Over all runs: 61 "created as l…" lines, 0 staging names.

Because the scripts contain no hwaddr session, I ran one extra ad-hoc container (`.../reconnect2/run-hwaddr.txt`, config `.../reconnect2/out/hwaddr/a.toml`: tunnel t1 with sessions `plain` (l2tp0, no hwaddr) and `mac` (l2tp1, `interface_hwaddr = "02:11:22:33:44:55"`)). Result:

```
INFO session mac (tunnel_id=1, session_id=103): created as rsl2tp-tbc50fe
INFO session plain (tunnel_id=1, session_id=101): created as l2tp0
INFO session mac (tunnel_id=1, session_id=103): published as l2tp1
ip link: 4: l2tp1 ... link/ether 02:11:22:33:44:55   5: l2tp0 ... link/ether 56:37:5d:9c:85:75
```

So the hwaddr session is staged under `rsl2tp-…` and published as l2tp1 with the configured address; the plain one is created directly. A1 confirmed.

## 7. Leftovers

`docker ps -a`: only three unrelated `node:24-alpine` containers exited 7 weeks ago (preoculus-*); no rs-l2tpd containers. `ps -eo pid,comm,args | grep rs-l2tpd`: nothing. `systemctl --user list-units 'rs-l2tpd*' --all`: 0 units (both transient units collected). Nothing killed. Temp transfer dir removed.

## Not run / caveats

- QEMU kernel matrix (6.12/6.18/7.3, Ubuntu LTS vanilla equivalents): not in scope of this request; only the host 6.8.0-147 kernel was exercised.
- Clippy/builds/doc were incremental on a warm target dir (1–2s); they are fresh invocations but not clean-cache builds.
- `setup_prefix_preserves_configuration` is not `#[ignore]`; README text that groups it with the `--ignored` procfs-hidden run is misleading (it filters to 0 under `--ignored`). I ran it without the flag; it passed.
- The scenario scripts' pass/fail is my reading of result.txt against the step intent plus equality with the previous audit's outcome lines; the scripts have no built-in verdict.
- Strict RULEMAP/SRCLINK fail (101/5 uncited) — expected until Phase 6, reported as informational.
