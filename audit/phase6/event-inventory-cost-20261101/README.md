# Filtered dependency inventories

One configured tunnel and one ordinary member event read every address in
the namespace. A newly recognized VRF also read every link. The witnesses
measure records delivered to the reconciler, rather than treating a fixed
request count as a CPU-cost proof.

| Unrelated records | Earlier address visits | Earlier link visits | Filtered address / link visits |
|---|---|---|---|
| 1 | 2 | 3 | 1 / 1 |
| 100 | 101 | 102 | 1 / 1 |
| 10,000 | 10,001 | 10,002 | 1 / 1 |

`revision` and `witness.patch` reproduce the original address failure.
`fix-base-revision` plus `source.patch` reconstructs the final code/tests.
`initial-source.patch` identifies the earlier test snapshot used by the
first complete collection; later test-only additions preserve production
coordinates and have separate final checks.

## Implementation and kernel boundary

The streaming methods now accept a selector: `scan_links(master, visit)`
selects members of one master, and `scan_addrs(index, visit)` selects one
interface. Zero explicitly requests the full namespace. Owned dump helpers
use zero; ordinary dependency events use their affected indexes. All address
inventories complete before staged state becomes authoritative, including
when a later selected device fails.

Linux request sockets enable NETLINK_GET_STRICT_CHK at creation and reopening.
IPv4/IPv6 address handlers otherwise ignore the index. Link dumps use
IFLA_MASTER. These use the installed safe netlink-sys API, with no dependency
or libc exception added.

An absent family handler falls back to the all-family dump; foreign protocols
need not implement index filtering. Selected inventories request IPv4 and
request IPv6 only when IFLA_AF_SPEC advertises the device's IPv6 state.
Malformed nested attributes still fail decoding. A vanished interface or
incomplete family dump returns its error. The source identities and function
locations for both exact Ubuntu tags and all three upstream releases are in
`source-links.log`; K7 and the architecture/evidence pages document this
boundary. The filters bound records delivered to the daemon, without claiming
constant CPU time for the kernel's internal traversal.

## Tests and deliberately broken controls

The fake/Linux shared case checks both families, exact master membership,
empty selections, a missing positive interface index and explicit full
inventories. Linux cases cover disabled IPv6, a device with MTU 68 and no IPv6
device state, and deletion of the selected interface between IPv4 and IPv6
dumps. The last case receives IPv4 data followed by ENODEV; it must refuse
completion. Model failures after each later inventory preserve staged-cache
integrity and permit recovery.

The lost-reply test requires strict selection after an actual socket
reopening. Isolated GNU/musl children deny setsockopt: both construction and
reopening return EIO without retaining descriptors, while generic-netlink
request construction still works.

All four controls fail as intended:

- Broad selectors reproduce both growing visit counts.
- Disabling strict checking delivers an unrelated address to the visitor.
- Omitting strict checking only on reopen loses the missing-device refusal.
- Ignoring the option-setting error defeats the isolated error test.

Control patches apply after `source.patch`; their logs are separate from
the shipping profiles. Initial live testing used u32::MAX as a missing link
index, which Linux interprets as invalid signed -1 and refuses with EINVAL.
The corrected test uses the valid positive i32::MAX and requires ENODEV.
`initial-live.log` retains that fixture failure. The first thread-limit
invocation used a GNU executable in the musl image and was correctly rejected
before execution; `thread-limits-image-refusal/` retains it. The final GNU
runs use the coverage image and export only completed production profiles.

## Verification and remaining work

Ten seeded ordinary suites and ten instrumented library/fake/rule/service
seeds pass. Final common checks pass strict maps, Clippy, feature builds,
GNU/musl ordinary tests and rustdoc. Final counts are 135 ordinary library,
58 ordinary binary, 72 shared fake plus six fake-only, 88 rules, 32 service
and three startup cases. Both map gates retain zero missing declarations.

The full GNU collection passes 14 privileged library, 22 Linux, five review,
three privileged binary, 28 process and 26 normal scenario cases; normal
scenarios take 162.60 s. After adding the no-IPv6-device-state test, all 23
Linux cases pass three GNU and three musl repetitions. The musl repetitions
also pass all 14 privileged library cases. The isolated option-refusal case
passes three times per ABI. Three GNU task-limit runs export compatible
profiles. The real user-manager case passes.

The GNU Incus case passes in 20.21 s and exports seven daemon profiles.
Three stable musl Incus cases pass in 8.99, 9.27 and 9.19 s, with every
container deleted. Three stable musl normal suites pass serially in 166.07,
166.75 and 165.78 s, after the GNU scale workload. Their original record
names are retained in `repetitions.log`. The unmodified root-systemd guest
passes in 28.13 s. Both mainline IPv6-absent boots pass with interface
binding enabled. All network changes remain inside disposable environments.

ARM64, RISC-V64 and PowerPC64LE musl all-target checks pass; these are compile
checks. Manager/container results apply to Ubuntu 24.04 userspace and kernel
6.8.0-147-generic. Cargo build durations and host-manager accounting are omitted.

Fresh production profiles use
`target/phase6-coverage-targeted-inventories-20261101`. No profiles from
the preceding production implementation are merged. Coverage is **96.01%
lines** (8,304/8,649) and **87.89% branches** (1,619/1,842), leaving **345
lines and 223 branches**. The report has no profile mismatches or saturated
regions, and no production exclusions. Test-only code remains excluded from
instrumentation while its tests execute.

A separate follow-up witness finds a stale master association when a member
moves into a newly appearing VRF before its member event is handled. The
inventory skips that already cached member. This remains a cache-correctness
fix to complete; the filtered-record counts do not establish that clause.

The full required-kernel refresh, complete clause/cache/history proof and
100% gate remain open. The earlier passing matrix uses ce6a70a and does not
qualify this production change.

```sh
TEST_SEED=1 cargo test --locked --all-features --lib --bin rs-l2tpd --test kernel-fake --test rules --test service --test startup
# Repeat seeds 2 through 10.
./test-ci-gates.sh
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/phase6-coverage-targeted-inventories-20261101"
export PHASE6_COVERAGE_RECORD="$PWD/audit/phase6/event-inventory-cost-20261101"
cargo +nightly-2026-10-28 llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report
sh audit/phase6/process-errors-20261031/run-live.sh
sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh
tests/docker/run.sh incus
tests/docker/run.sh scenarios
# Repeat each stable musl container suite three times; serialize normal runs.
cargo +nightly-2026-10-28 llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
