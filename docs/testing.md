# Testing

[Documentation index](README.md)

How roadmap step 6 is met: 100 % of code paths covered, every claim of
the specification tested, every test deterministic, every kernel-facing
function source-linked to the kernel, every kernel-relevant unit run
against a live kernel. The design that makes this possible is the
`Kernel` boundary of the [architecture](architecture.md#the-kernel-boundary):
behaviour is tested against a fake kernel that models the kernel facts,
and the fake is itself tested against the kernel.

## Layout

```
src/**            unit tests next to the code (config, planner, ladder, report)
tests/
  rules/          behavioural tests over the fake kernel, one file per spec page (tunnels.rs, sessions.rs, ...)
  properties/     property tests of the promises (G3, G5, G6, G18) over random reload sequences
  kernel/         the conformance suite: one test per K fact, run against the fake and the real kernel
  binary/         the binary's unit-level tests (args, files, check rendering, pid file, logger)
  scenarios/      the scenario suite: whole-daemon tests in containers, one per H rule and G promise
  docker/         the runner: Dockerfiles, the scenario driver, the QEMU matrix driver
  tools/
    rulemap.rs    the rule-map check
    srclink.rs    the source-link check
```

Every test names the rules it guards in its doc comment,
`/// spec: T21, K22`, which the rule map reads.

## The four suites

| Suite | Kernel | Runs where | Guards |
|---|---|---|---|
| Unit and `rules/` | fake | `cargo test`, anywhere, no privilege | C, M, T, S, V, E, O, L rules |
| `properties/` | fake | `cargo test` | G promises as invariants over random inputs |
| `kernel/` conformance | fake **and** real | `cargo test` for the fake; a privileged container and the QEMU matrix for the real one | K facts, `kernel::linux` |
| `scenarios/` | real | privileged containers; QEMU for `ipv6.disable=1` and other boot options | H rules, P rules, the unit, G15–G23 end to end |

### The conformance suite

Each K fact is one test written against the `Kernel` trait, so the same
body runs against `FakeKernel` and `LinuxKernel`. Example: K31 creates a
session, brings the device up, sets a hardware address and expects
`EBUSY`; K17 closes a socket and expects its sessions gone within the
deletion wait; K29 shrinks a subscription's buffer, floods it and expects
`Loss`. A fact that the fake gets wrong is caught here, not in a
behavioural test, which is why behavioural tests may trust the fake. The
real run also records the kernel version it ran on, and the QEMU matrix
runs it on every release from v6.8 to the newest (the verified range of
[kernel](spec/kernel.md)).

### The rules suites

One test per numbered rule, against the fake. Determinism comes from the
fake's virtual clock (a test advances it; M14 intervals are asserted
exactly), its seeded random source (S4 names are reproducible), and its
explicit notification delivery (a test says when the kernel's
notifications arrive and in which order, which is how the S27 "either
order" and the E21 loss cases are written). No test sleeps.

### Properties

Random sequences of configurations are reloaded against the fake, with
random host events between them; after each step the invariants are
checked: G3 (an index changes only by a matrix row), G5 (no socket is
connected to a peer the configuration does not name), G6 (an entry's
failure left no other entry unapplied that the fake allowed), G18 (a
converged entry received no operation on an identical reload), and that
the planner's output is a fixed point (running it twice changes nothing).

### The scenario suite

Whole-daemon tests in Docker, one per row of [hosts](spec/hosts.md)
and per conditional promise: the daemon binary, a configuration, a
container network built with iproute2, assertions on `ip l2tp`, `ip
link`, the daemon's log and frames delivered between two daemons. The
driver waits on events (a log line, a device appearing, a counter
changing), never on a fixed sleep, and each scenario has a hard timeout.
Scenarios that need a boot option (`ipv6.disable=1`, a kernel without
IPv6) run under QEMU.

## Gates

| Gate | Tool | Threshold |
|---|---|---|
| Coverage | `cargo llvm-cov` over unit, rules, properties, the fake conformance run and the container runs (profiles merged) | 100 % lines and branches of `src/`; exclusions only in `kernel::linux` for branches no kernel of the range reaches, each marked `// coverage: unreachable on <range>, <reason>` |
| Rule map | `tests/tools/rulemap.rs` reads every rule definition of `docs/spec/*.md`, which is a line starting with `X1.` or a table row starting with `\| X1 \|` (letters `A`, `C`, `D`, `E`, `G`, `H`, `K`, `L`, `M`, `O`, `P`, `R`, `S`, `T`, `V`), and every `spec:` comment of `tests/` and `src/` | every rule has at least one test; rules whose text begins with "Removed" are exempt |
| Source link | `tests/tools/srclink.rs` reads every `// kernel:` comment of `src/kernel/linux/` | every function cites a K fact; every K fact is cited |
| Determinism | CI runs the fake suites ten times with different seeds and the container suite three times | zero flakes before a gate is enabled |
| Warnings | `cargo clippy -D warnings`, `cargo doc -D warnings`, builds with no default features and with `serde` | clean |

## Running

```sh
cargo test                                   # unit, rules, properties, fake conformance
tests/docker/run.sh conformance              # real-kernel conformance in a privileged container
tests/docker/run.sh scenarios                # the scenario suite
tests/docker/run.sh matrix v6.8..v7.3        # QEMU kernel matrix (TCG, unprivileged)
cargo llvm-cov --all-features -- --include-ignored   # with the container profiles mounted back
```

The container runs need `--cap-add NET_ADMIN --cap-add NET_RAW` (and
`--privileged` for sysctls), host-kernel L2TP support, no host
networking and no writable host mounts; the QEMU runs need only a user
account and the kernel images the driver builds or fetches.

## Kernel test pitfalls

Facts that cost time once and shape how the tests are written:

- The kernel never echoes a route notification to the netlink port that
  requested the change; a test listening for its own change needs a
  second connection.
- A VRF whose table has no IPv4 `unreachable default` route falls through
  to the main table for IPv4 lookups.
- A socket bound to an ordinary device with no route to an IPv4
  destination still connects: the kernel assumes the destination is
  on-link and sends ARP out of the device (K28). A successful IPv4 connect
  proves no route.
- `ip netns exec` fails inside a Docker container (it cannot remount
  sysfs); `nsenter --net=/run/netns/<name>` works, and does not switch
  `/sys`, so read a namespace's counters with `ip -s link`.
- iproute2 6.15 parses `ip link add a type dummy` as an address; write
  `ip link add name a type dummy`.
- Classic BPF loads multi-byte fields in network byte order while netlink
  headers are in host byte order: a message type is compared byte-swapped.
- The `l2tpeth` device of a session keeps the name the kernel recorded at
  creation in `ip l2tp show session`, whatever its current name (K16);
  `ip link del` on such a device is refused `EOPNOTSUPP`, in any
  namespace, and the device can be moved to another namespace while its
  session stays in the origin one.
- Deleting a session and creating one with the same identifiers at once
  can be refused `EEXIST` for a moment (K18); tunnel deletion is
  asynchronous on every kernel (K17).
- A netlink socket whose queue is full loses kernel unicast replies and
  raises `ENOBUFS` on the next receive (K29); with `NETLINK_NO_ENOBUFS`
  the reply is simply missing. The subscriptions never set it.
- A tunnel registered on an unconnected socket drops the frames of its
  sessions (`tx_dropped` on the device) and still receives frames from
  the peer; the kernel's own router solicitations on a fresh device count
  as dropped frames before any test frame is sent.
- Two UDP sockets share a port only when both set `SO_REUSEADDR`.
