# rs-l2tpd fresh test run — 2026-10-30 01:3x UTC

Tree: /home/dev/rs-l2tpd @ 0cf92527b92eba490ddbbc0c69584e2780981bf7 (main, clean at start).
Host: Linux 6.8.0-147-generic (Ubuntu), cargo 1.99.1, systemd 259, docker, qemu-system-x86_64 (TCG only), user `dev` without sudo.
All commands ran through rexec; no repo file was edited by this run.
Logs: /tmp/claude-1001/-home-dev-rs-l2tpd/a5262b72-9b33-48ea-8c09-db4f8a9a44fe/scratchpad/logs/

## Results table

| # | Command | Exit | Pass / fail / ignored | Duration |
|---|---------|------|-----------------------|----------|
| 1a | `cargo fmt --check` | 0 | clean | <1 s |
| 1b | `cargo clippy --locked --all-features --all-targets -- -D warnings` | 0 | no warnings (cached build) | <1 s |
| 1c | `cargo build --locked --no-default-features` | 0 | ok | <1 s |
| 1d | `cargo build --locked --no-default-features --features serde` | 0 | ok | <1 s |
| 1e | `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features` | 0 | ok | 1 s |
| 2 | `cargo test --locked --all-features` (native) | 0 | 196 passed / 0 failed / 49 ignored (per-binary below) | 2 s |
| 3 | determinism ×3: `cargo test --locked --features fake-kernel,serde --test rules --test kernel-fake --test service` | 0,0,0 | each run: kernel-fake 1/0, rules 63/0, service 23/0; identical all 3 runs, no flake | 3 s, 1 s, 1 s |
| 4a | `RULEMAP_STRICT=1 SRCLINK_STRICT=1 cargo test --locked --all-features --test rulemap --test srclink` | 101 | rulemap: 2 passed, 1 FAILED (`every_rule_has_a_test_citation`); srclink not reached (fail-fast) | <1 s |
| 4b | `SRCLINK_STRICT=1 cargo test --locked --all-features --test srclink` | 101 | 1 passed, 1 FAILED (`kernel_code_cites_the_facts`) | <1 s |
| 5a | `cargo test --locked --all-features --target x86_64-unknown-linux-musl --no-run` (CARGO_TARGET_DIR=target-musl) | 0 | built 11 executables | 34 s |
| 5b | Docker privileged (rs-l2tpd-audit-vm:local, host kernel 6.8.0-147): `/kernel-unit`, `/kernel-linux`, `/review-kernel` `--ignored --test-threads=1` | 0 | kernel-unit 9/0, kernel-linux 12/0, review-kernel 5/0 | 8 s |
| 5c | Docker cap-add variant (NET_ADMIN, NET_RAW, SYS_ADMIN, seccomp=unconfined) `/review-kernel --ignored` | 0 | 5/0 | 3 s |
| 5d | Docker privileged, musl: 3 `/binary-unit` ignored fixtures + `/process-test --ignored --test-threads=1` (repo mounted ro at same path) | 0 | fixtures 3×1/0 (+ their 3 child halves 1/0 each), process 17/0 | 31 s |
| 5e | `cargo test --locked --all-features --target x86_64-unknown-linux-gnu --bin rs-l2tpd --test process` (CARGO_TARGET_DIR=target-gnu) | 0 | bin unit 27/0/4 ignored, process 7/0/17 ignored | 26 s |
| 5f | Docker privileged, glibc (ubuntu:26.04): same 3 fixtures + `/process-test --ignored` | 0 | fixtures 3×1/0, process 17/0 | 19 s |
| 5g | Docker privileged, `mount -t tmpfs tmpfs /proc` then `/process-test --ignored --exact foreground_reload_and_clean_shutdown_without_network` | 0 | 1/0 | 7 s |
| 5h | same container setup, `/process-test --exact setup_prefix_preserves_configuration` (not an ignored test, so run without `--ignored`) | 0 | 1/0 | 3 s |
| 5i | store-kernel real manager: `systemd-run --user ... store_kernel --exact manager_bridge --ignored` + Docker privileged `--exact kernel_reference --ignored` + journalctl | 0 / 0 | manager_bridge 1/0 (journal), kernel_reference 1/0 | 17 s |
| 5j | `systemd-run --user --wait --pipe ... rs_l2tpd(bin unit) --ignored --exact fdstore::manager_tests::actual_manager_processing_and_address_family_filter` | 0 | 1/0, "Finished with result: success" | <1 s |
| 5k | `LC_ALL=C sh tests/kernel/notify.sh` | 0 | allowed unit: success (store count 1 then 0); denied unit: "Address family not supported by protocol" exit 1 as the check expects | <1 s |
| 5l | QEMU 6.12.114-0-virt (Alpine kernel from rs-l2tpd-audit-vm:local, image sha256:24e77fbc…), initramfs with kernel-unit, kernel-linux, review-kernel + init.sh, `-m 2048` | 0 | kernel-unit 9/0, kernel-linux 12/0, review-kernel 5/0, `REVIEW_RESULT=0` | 17 s |

Step 2 per-binary counts (native, --all-features):

| Binary | passed | failed | ignored |
|--------|--------|--------|---------|
| lib unittests (src/lib.rs) | 64 | 0 | 9 |
| bin unittests (src/bin/rs-l2tpd/main.rs) | 27 | 0 | 4 |
| kernel-fake | 1 | 0 | 0 |
| kernel-linux | 0 | 0 | 12 |
| process | 7 | 0 | 17 |
| review-kernel | 0 | 0 | 5 |
| rulemap (non-strict) | 3 | 0 | 0 |
| rules (includes tests/properties/planner.rs via `#[path]`) | 63 | 0 | 0 |
| service | 23 | 0 | 0 |
| srclink (non-strict) | 2 | 0 | 0 |
| store-kernel | 0 | 0 | 2 |
| doc-tests lib | 4 | 0 | 0 |
| doc-tests (compile-fail, 2) | 2 | 0 | 0 |

## Failures (full text)

Only the two strict-mode traceability gates failed; every functional suite passed.

### rulemap strict (tests/tools/rulemap.rs)

```
rule map: 340 rules (330 active), 224 linked to test declarations, 106 without citations
thread 'every_rule_has_a_test_citation' (2812881) panicked at tests/tools/rulemap.rs:138:9:
106 rules without a test citation
test every_rule_has_a_test_citation ... FAILED
test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
```

Spec rules with no test citation (106):

- A (16): A1 A2 A3 A4 A8 A9 A10 A11 A12 A15 A16 A17 A18 A19 A20 A21
- E (1): E26
- G (16): G1 G2 G4 G8 G9 G10 G11 G12 G13 G14 G15 G16 G17 G19 G20 G21
- H (19, all): H1–H19
- K (9): K1 K3 K6 K8 K13 K21 K33 K36 K38
- O (3): O2 O4 O9
- R (42): R1 R3 R4 R5 R6 R8 R9 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R21 R22 R23 R24 R25 R26 R27 R28 R29 R30 R31 R34 R35 R36 R37 R38 R39 R40 R41 R42 R43 R44 R45 R46 R48

### srclink strict (tests/tools/srclink.rs)

```
source links: 41 facts, 36 cited, 0 functions without a citation
fact never cited: K13
fact never cited: K14
fact never cited: K33
fact never cited: K38
fact never cited: K40
thread 'kernel_code_cites_the_facts' (2814188) panicked at tests/tools/srclink.rs:124:9:
assertion failed: uncited.is_empty() && missing.is_empty()
test kernel_code_cites_the_facts ... FAILED
test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Note: with both env vars set in one `cargo test` call, cargo stops after rulemap fails, so srclink strict was run separately (4b). Non-strict both tools pass (step 2).

## Deviations from the READMEs / things not run

- QEMU: the README's `-m 512` boot failed with "Initramfs unpacking failed: write error" then "Unable to mount root fs" because the initramfs with the three unstripped debug test executables is 265 MB (> half of 512 MB RAM). Re-ran with `-m 2048`; everything else per README. Only the Alpine 6.12.114 kernel bundled in the image was run; the 6.18.x / 7.3 / Ubuntu-kernel matrix the docs mention (Phase 6 gate) was not built or run here.
- `setup_prefix_preserves_configuration` is an ordinary (not `#[ignore]`) test, so `--ignored --exact` selected 0 tests; it was re-run without `--ignored` inside the no-procfs container (5h). My first attempt also wrongly passed `--exact` twice (libtest rejects it); corrected in 5g/5h.
- Docker tests use the host kernel 6.8.0-147-generic (Ubuntu 24.04 LTS kernel); the Ubuntu 22.04 kernel was not tested.
- Nothing was impossible on this host; no result is fabricated.

## Host state after the run (step 6)

- `docker ps -a`: only three unrelated `node:24-alpine` containers exited 7 weeks ago (preoculus-*); nothing from this run.
- Processes: no rs-l2tpd / test / qemu processes left. There is an unrelated concurrent `cargo build --release --target x86_64-unknown-linux-musl --manifest-path .../scratchpad/v015/Cargo.toml` (pid 2819864) running in the same scratchpad — not started by this run; left alone.
- User systemd units `rs-l2tpd*`: none loaded (transient units collected). Store transfer dir removed (rmdir exit 0).
- /tmp has many pre-existing `/tmp/rs-l2tpd-*` directories/logs from earlier phases (phase23, phase5-qemu, networkd, …); none created by this run.
- Scratch QEMU dir (root.tar, initramfs) deleted.
- `git status`: `.gitignore` is modified (adds `/target-*`), mtime 01:36:52 UTC, i.e. during this run but NOT by me — I edited no repo file; a concurrent agent/human did. The new `target-musl/` and `target-gnu/` dirs I created at the repo root are covered by that line (and would otherwise show as untracked).
