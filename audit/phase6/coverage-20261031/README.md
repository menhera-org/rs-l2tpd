# First merged Phase 6 profiles (not the coverage gate)

Source snapshot: 8fd9ae8 (production sources before the subsequent
readiness/signal-order fix). All features, x86_64-unknown-linux-gnu,
cargo-llvm-cov 0.9.1, Rust nightly-2026-10-28
(rustc 1.101.0-nightly, 41089d07a, 2026-10-27). The native and container
runs use the same instrumented executables. `native.log` identifies them;
`artifacts.log` hashes them. The shipped target remains musl.

Commands from the repository root, with the pinned coverage tools on PATH:

```sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-20261031"
cargo +nightly llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
docker build --network none -f audit/phase6/coverage-20261031/Dockerfile -t rs-l2tpd-coverage:phase6 audit/phase6/coverage-20261031
sh audit/phase6/coverage-20261031/run-live.sh
cargo +nightly llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```

The coverage image adds the GNU loader, libc and libgcc from Ubuntu 24.04
to the existing review image; the Dockerfile and image IDs are recorded.
No test container has external networking. The checkout is read-only;
only the generated profile directory is writable. This is the P4 profile
transport exception to P2's ordinary read-only container mounts.

Executed profiles:

| Suite | Passed | Scope |
|---|---:|---|
| Native library | 76 | ordinary cases; ten live cases ignored here |
| Native binary | 38 | ordinary cases; live cases collected separately |
| Fake conformance | 1 | all shared operation cases |
| Native process | 8 | ordinary process cases |
| Rules/properties | 74 | all-feature fake suite |
| Services | 23 | async/blocking/runtime behavior |
| Traceability | 3 + 4 | rule map lenient, source link |
| Scenario parser | 1 | netlink decoder |
| Container library | 10 | live resolver, worker and kernel-unit cases |
| Container kernel | 16 + 5 | production adapter/conformance and review probes |
| Container binary | 3 | explicit permission/ownership cases |
| Container process | 26 | ordinary and ignored process cases |
| Container scenarios | 18 | implemented host subset; Incus case excluded |
| User systemd | 1 | actual FD store processing and template address-family filter |
| Unprivileged Incus | 1 | actual SO_RCVBUFFORCE=EPERM and production fallback |

Nested child tests print additional result lines; they are not added to
the parent suite count. Kernel release per live run is in the logs.

The first live-profile copy could not read four restrictive-umask files;
`profile-export.log` records the corrective readable export without
rerunning the already passing suites. `run-live.sh` now performs this
export. The first Incus recursive pull failed after its test passed;
`incus-buffer-final.log` records a fresh run and a successful explicit
single-file export. Both containers were deleted. The user-manager unit
uses `--collect`, and its actual store is empty at successful exit.

`merged-host-before-manager.log` was 90.64% lines / 77.02% branches.
`merged.log`, after the manager and Incus exports, is **91.03% lines
(9,101/9,998), 77.02% branches (1,374/1,784)**. It identifies 897 missing
lines and 410 missing branches. No source is excluded and no coverage
marker has been added. This is a diagnostic report, not a passing gate.

Still absent: boot-only, root-systemd sandbox and full Incus-scenario
profiles; reachable missing paths throughout src/; final-code profiles
after the readiness fix; the complete coverage job and threshold in CI.
The report also includes cfg(test) helpers/closures in src/; no helper
has been silently suppressed. Strict CI flags remain off.
