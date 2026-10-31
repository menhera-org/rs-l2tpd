# Behavior of the required kernels

[Documentation index](README.md) · [Required targets](testing.md#kernel-targets) · [Kernel specification](spec/kernel.md) · [Evidence map](kernel-evidence.md)

This page records the behavior relevant to rs-l2tpd for **each required
kernel**, resolved on 2026-10-31. The specification defines the contract;
this page distinguishes observations, source evidence and remaining tests.
An Ubuntu ABI/package version identifies a patched distribution kernel;
its behavior cannot be inferred from the corresponding vanilla version.

## Per-kernel differences

| Required target | Empty IPv6 VRF, no usable source or route (K26/K34) | Foreign-namespace L2TP deletion notification (K41) | Test boot |
|---|---|---|---|
| Ubuntu 24.04, package `6.8.0-147.147`, release `6.8.0-147-generic` | `EADDRNOTAVAIL` (99) | Delivered despite being from another namespace; local objects remain intact | Stock image and matching modules; no KHO override |
| Vanilla `6.8.12` | `ENETUNREACH` (101) | Delivered despite being from another namespace; local objects remain intact | Built-in L2TP/VRF; no KHO override |
| Ubuntu 26.04, package `7.0.0-42.42`, release `7.0.0-42-generic` | `EADDRNOTAVAIL` (99) | Delivered despite being from another namespace; local objects remain intact | Stock image/modules, `kho=off` for the cold-boot test; explanation below |
| Vanilla `7.0.14` | `EADDRNOTAVAIL` (99) | Delivered despite being from another namespace; local objects remain intact | Built-in L2TP/VRF; no KHO override |
| Mainline `v7.3`, release `7.3.0` | `EADDRNOTAVAIL` (99) | Confined to the object's namespace; foreign deletion produces no matching local event | Built-in L2TP/VRF; extra IPv6-absent boots below |

The errno distinction was approved by the maintainer on 2026-10-31.
Both precise refusals receive the existing transient policy: keep the
tunnel disconnected and retry when its dependencies change. The exception
is the tested empty-VRF/no-source/no-route case; it does not turn every
source-selection failure into `ENETUNREACH`. No daemon change is needed.
The shared test records the actual errno and rejects other errors.
[Source comparison and original failure](../audit/phase6/kernel-contract-20261031/README.md).

For K41, every notification is only a reason to check local state.
On older kernels an unrelated namespace can use the same identifiers;
even on 7.3 the notification precedes deletion completion. The daemon
checks local identity and absence before releasing an identifier or
removing its own records. The live review probe creates colliding IDs
in a second namespace and verifies that the local session survives.
The upstream source boundary is
[v7.2 `l2tp_netlink.c`](https://raw.githubusercontent.com/torvalds/linux/v7.2/net/l2tp/l2tp_netlink.c)
and [v7.3 `l2tp_netlink.c`](https://raw.githubusercontent.com/torvalds/linux/v7.3/net/l2tp/l2tp_netlink.c);
distribution backports require the live check.

All five normal profiles enable IPv6 and network namespaces. The stock
Ubuntu kernels supply L2TP/VRF as modules; the three vanilla builds
include them in the image. [Exact config flags and digests](../audit/phase6/kernel-behavior-20261031/config-features.log)
also show that only the Ubuntu 26.04 profile enables KHO by default.

## What is established for each required kernel

The following profiles summarize each target's behavior. Shared behavior
is specified fact by fact in the table below; an omitted difference does
not mean that every possible failure mode was exercised on that target.

- **Ubuntu 24.04, `6.8.0-147.147`:** empty IPv6 VRF connection refuses with
  `EADDRNOTAVAIL`; commanded L2TP deletion events can cross namespaces.
  The exact distribution source unhashes/closes sessions inline and uses
  positional session-dump traversal. The guest boots the stock image with
  matching modules. This target also has the separately executed
  denied-capability/netlink, low-port DHCPv6, 300-tunnel and unprivileged
  system-container evidence. Its udev/networkd result includes the
  concurrent MAC-assignment limitation described below.
- **Vanilla `6.8.12`:** the same empty IPv6 VRF refuses with
  `ENETUNREACH`, which receives the same transient retry policy.
  Cross-namespace deletion events, inline session deletion and positional
  dumps have the same documented limitations as the Ubuntu 6.8 target.
  L2TP/VRF are built into the test image. There is no per-target
  udev/networkd, unprivileged-container or 300-tunnel result.
- **Ubuntu 26.04, `7.0.0-42.42`:** the empty VRF refuses with
  `EADDRNOTAVAIL`; deletion events can still cross namespaces. Its exact
  distribution source queues session deletion and traverses sessions by
  identifier. The stock image and matching modules pass the normal
  profile with the documented `kho=off` cold-boot setting. A separate
  missing-Ethernet-driver case proves degradation and recovery. This does
  not establish udev/networkd or unprivileged-container behavior on this
  target.
- **Vanilla `7.0.14`:** the empty VRF refuses with `EADDRNOTAVAIL`;
  deletion events can cross namespaces. Session deletion is queued and
  dump traversal is identifier-based. L2TP/VRF are built in. Its normal
  and clock profiles pass; the additional capability, scale and
  system-container profiles have not run on this target.
- **Mainline `7.3.0`:** the empty VRF refuses with `EADDRNOTAVAIL`;
  commanded deletion events stay within the object's namespace. Session
  deletion is queued and dump traversal is identifier-based. L2TP/VRF are
  built in. In addition to the normal and clock profiles, the expanded
  23-scenario/300-tunnel profile, four capability/netlink degradation
  cases and both scoped IPv6-absent boots pass.
  These bare-kernel guests provide no udev/networkd or unprivileged
  system-container result.

### Per-target execution coverage

“Not run” is a missing test result, not a known kernel incompatibility.
The normal profile proves the shared assertions it actually executes,
including all eight H20 fragmentation combinations. The additional
profiles below use the dated source snapshots linked later on this page;
they are not a single final run of the current daemon on all targets.

| Required kernel | Normal profile and H20 | H15 additional degradation | H16 clock/pause | H17 300 tunnels | H11/unprivileged system container |
|---|---|---|---|---|---|
| Ubuntu `6.8.0-147-generic` | Pass | Four capability/netlink cases; low-port DHCPv6 positive case | Pass | Pass | Pass, with documented MAC race and buffer fallback |
| Vanilla `6.8.12` | Pass | Not run | Pass | Not run | Not run |
| Ubuntu `7.0.0-42-generic` | Pass, with cold-boot KHO override | Missing-driver/recovery case | Pass | Not run | Not run |
| Vanilla `7.0.14` | Pass | Not run | Pass | Not run | Not run |
| Mainline `7.3.0` | Pass; expanded profile also passes | Four capability/netlink cases; low-port DHCPv6 positive case | Pass | Pass | Not run |

Reproduction and transcripts: [normal/H20 matrix](../audit/phase6/matrix-20261031T071523Z-3533819/README.md),
[H15](../audit/phase6/H15-20261031/README.md),
[H16](../audit/phase6/H16-20261031/README.md),
[H17](../audit/phase6/H17-20261031/README.md), and
[Incus/H11](../audit/phase6/P5_VERIFICATION_2026-10-30.md).
The separately executed root system-unit sandbox is recorded in
[P6](../audit/phase6/P6_ROOT_SANDBOX_2026-10-30.md).

## Session deletion and dump traversal by target

The exact Ubuntu tags were checked alongside the built upstream tarballs;
these are **source observations**, separate from the live reuse probe:

| Required target | Session deletion (K18) | Session dump traversal (K16) |
|---|---|---|
| Ubuntu `6.8.0-147.147` | Unhash/close inline in `l2tp_session_delete` | Positional `l2tp_session_get_nth`; concurrent deletion can skip the next entry |
| Vanilla `6.8.12` | Unhash/close inline | Positional `l2tp_session_get_nth`; same limitation |
| Ubuntu `7.0.0-42.42` | Queue `session->del_work`; worker unhashes/closes | Identifier-based `l2tp_session_get_next` |
| Vanilla `7.0.14` | Queue `session->del_work`; worker unhashes/closes | Identifier-based `l2tp_session_get_next` |
| Mainline `7.3` | Queue `session->del_work`; worker unhashes/closes | Identifier-based `l2tp_session_get_next` |

[Versioned source URLs, hashes and excerpts](../audit/phase6/kernel-behavior-20261031/source-comparison.log)
record the actual distribution implementations rather than assuming a
backport policy. A zero-retry delete/recreate run cannot establish this
boundary: a queued worker can finish before the next request. The daemon
waits for confirmed absence on every target and treats dumps as
observations rather than an atomic identity proof. Tunnel-socket close
still queues tunnel cleanup on all five targets (K17).

## Shared behavior and the scope of the proof

The following table covers every active K fact. Detailed conditions and
kernel source locations remain in [the kernel specification](spec/kernel.md).
“Live” names what the suite actually exercises; a passing profile does
not promote a source-only or delegated fact into an executed case.
K12 was removed and carries no obligation.

| Facts | Behavior relevant to the daemon | Evidence and limits |
|---|---|---|
| K1–K4, K8, K9 | Generic-netlink L2TPv3, Ethernet sessions, IPv4/IPv6 sockets and VRFs work with namespace-local `CAP_NET_ADMIN` | Live positive socket/tunnel/session/VRF operations. H15 adds denied-capability/netlink cases on Ubuntu 6.8.0-147 and a missing-Ethernet-driver/recovery case on Ubuntu 7.0.0-42; the degraded profiles have not run separately on every target. |
| K5 | An unconnected socket can own a tunnel; outbound session frames are dropped while disconnected | Shared conformance and live frame/drop-counter checks. |
| K6, K24, K25 | Disconnect/reconnect reselects the source; bare reconnect can retain it; an IPv6 tunnel dump can retain its previous peer after disconnect | Shared and live socket/dump assertions; the daemon disconnects before reconnecting. |
| K7, K10 | Link/address monitoring works without route subscriptions; the production classic BPF filter admits required events | Live monitor/filter tests. H8 also observes daemon requests with nlmon, including a positive capture control. |
| K11, K23 | `bindv6only` affects fresh sockets; an existing L2TP/IPv6 socket cannot have V6ONLY changed; its value can be read | Live write/create/read-back and H18 opt-in/opt-out tests. An old socket is never assumed to change with the sysctl. |
| K13, K14, K38–K40 | DHCPv6 needs port 546; RA raw reception needs `CAP_NET_RAW`; the netlink RA fallback depends on `accept_ra`; competing DHCPv6 listeners can lose unicast replies | Resolver implementation/source evidence is delegated to iphost. Live adapter cases provide positive port-546/raw-RA exchange evidence. The capability scenario also proves DHCPv6 refusal at unprivileged-port start 1024 and actual port-546 traffic without CAP_NET_BIND_SERVICE at start 0, on Ubuntu 6.8.0-147. Full denied-capability/netlink fallback behavior is not proved separately on every required kernel. |
| K15 | IP-encapsulated data admission uses the namespace's session ID and cookie, independently of the receiving socket binding/source | Live matching, wrong/absent-cookie and foreign-source frame checks. Cookies are not peer authentication. |
| K16 | Stored creation names survive rename and may become ambiguous; querying by name is not an atomic name-plus-ID identity proof | Shared name/rename and live duplicate-stored-name probes. Upstream pre-6.12 positional dumps can skip an entry on concurrent deletion; newer identifier-based traversal is source evidence, not a forced concurrent-dump result on every target. |
| K17, K37 | Closing the last socket descriptor eventually deletes the tunnel and all its sessions; duplicate, transferred or exec-inherited descriptors keep them alive | Shared close, live duplicate/adoption and process tests. Real systemd descriptor-store ownership has separate manager/Incus evidence; the ordinary QEMU profile has no systemd manager. |
| K18 | Session ID/name release may complete after the delete reply; creation must wait for confirmed absence | Live 32-cycle delete/recreate probe. Zero `EEXIST` retries does not prove synchronous deletion. Upstream source is synchronous through 6.11 and workqueue-based from 6.12; Ubuntu backports are not classified by version number alone. |
| K19, K20 | Tunnel/session IDs are namespace-scoped; IP session IDs cannot collide across tunnels; a taken device name creates no partial session | Shared collision, lookup and reuse checks. |
| K21 | Autoload call sites have no namespace capability gate, but the host may restrict module loading | Source/host evidence. Stock guests explicitly load matching modules; vanilla guests build them in. Neither demonstrates unprivileged host-module autoload. |
| K22 | An initial binding and rebinding have different capability requirements; disconnect clears binding | Shared binding/VRF conformance. Live positive operations run with capabilities; denied rebinding policy is covered by the fake. |
| K26–K28, K34 | Route/source and link-local-zone rules control connect; binding an ordinary IPv4 device can succeed without an explicit route; an IPv4 socket can report source `0.0.0.0` | Shared live source/VRF/zone cases. Empty-VRF errno differs as shown above. The full route-type errno table remains source plus fake-policy evidence. |
| K29, K30 | Netlink loss can yield `ENOBUFS`; missing replies do not imply missing mutations; foreign unicast events require sender validation | Live production overflow, missing-reply/reopen and forged-removal checks; fake framing/deadline cases cover additional failures. |
| K31, K32 | A new l2tpeth gets a random MAC; changing it while UP fails `EBUSY`, setting the existing value succeeds, and renaming while UP works; names have kernel restrictions | Shared/live MAC/name checks and configuration validation. Manager consequences are detailed below. |
| K33 | Lowering a link can remove IPv6 addresses, routes and neighbors | Source-only classification; the daemon never lowers a working link. Policy/property tests preserve administrative state and child devices. |
| K35 | Kernel cookie length acceptance is broader than the configuration contract (0–8 bytes) | Live production decoder tests every length; configuration still accepts only its documented lengths. |
| K36 | `SO_RCVBUFFORCE` needs capability in the initial user namespace; otherwise use capped ordinary `SO_RCVBUF` | Production live buffer comparison. Root QEMU guests exercise FORCE success; the separately executed unprivileged Incus case proves `EPERM` and fallback. |
| K41 | Commanded deletion notifications can cross namespaces before 7.3 and precede completed deletion on all targets | Live review probe and source distinction above. Socket-close cleanup is not announced the same way. |
| K42 | A link index/name can be reused after replacement or a namespace move | Live namespace-move/index-reuse identity checks and policy lifetime-generation tests. |
| K43, K44 | Full-size session frames can fragment over a smaller underlay; socket options explicitly allow fragmentation | H20 and live option read-back; the native IPv6 limitation below remains source-dependent. |

The [evidence map](kernel-evidence.md) names the test declarations and
classifies production, delegated and source-only obligations. The
[scenario list](phase6.md#p2-the-scenario-suite) defines H1–H20 and the
remaining promises. Its incomplete cases remain incomplete on every
kernel, even when all currently implemented guest tests pass.

## Fragmentation on each target

H20 covers IPv4 and IPv6 underlays, ordinary and VRF binding, and session
MTUs 1500 and 9000 over a 1500-byte veth: eight combinations per guest.
It checks full-size delivery in both directions, bulk frames, receiving
session counters, sender fragment counters and absence of transmit drops.
The daemon's tunnel socket options are read back separately:
`IP_PMTUDISC_DONT`, `IPV6_PMTUDISC_DONT`, `IPV6_DONTFRAG=0`.
Per-target execution is recorded in the results table below.

IPv4 has the explicit socket-option contract described in K44. Native
IPv6 L2TP currently uses the kernel's `skb->ignore_df` path, which does
not consult the two IPv6 options in that transmit path. Those options
are still set, but IPv6 delivery depends on K43's implementation and
must be retested on each new kernel. This limitation applies to all
required targets, including mainline. Reassembly may happen in netfilter;
zero `Ip6ReasmReqds` is not evidence of failed delivery.

## MAC policy and unprivileged containers

K31 is a kernel restriction on **any** caller changing an UP l2tpeth MAC,
including both the daemon and udev. The daemon can apply a configured MAC
while the device is down. It defers a differing MAC on an already active
device, preserving its UP state, index, addresses and children (S12/G4).
It never lowers that device to make a change possible.

The kernel initially assigns a random locally administered unicast MAC.
Udev's [MACAddressPolicy=persistent](https://www.freedesktop.org/software/systemd/man/latest/systemd.link.html#MACAddressPolicy=)
may replace it with a generated,
locally administered unicast MAC derived from stable machine/device
identity; it is not a vendor-assigned hardware address. If networkd
raises the device first, udev can receive `EBUSY` and leave the kernel's
random address in place. Direct creation under the configured name helps
name-based matching but does not order those two managers. Persistent
generation also depends on udev obtaining stable device identity/naming
data and on the selected `.link` policy.

The approved combined H11 contract tests both outcomes under concurrent
activation, and separately orders persistent assignment while down and
checks stability across re-creation. It does not promise persistent MAC
assignment for every manager race or every staged temporary name.
[Exact manager limitations](spec/hosts.md#other-network-managers) and
[executed Incus evidence](../audit/phase6/P5_VERIFICATION_2026-10-30.md).
Manager behavior depends on the userspace image and ordering as well as
the kernel. The mainline/vanilla QEMU profile does not run udev/networkd,
so a bare-kernel pass is not per-distribution proof of H11.

Unprivileged Incus/LXD also cannot supply initial-user-namespace
capability for K36 or load host modules itself. Required modules must
already be available from the host. All five kernel targets remain
subject to those constraints. The full system-container scenario ran
with kernel `6.8.0-147-generic` and an `images:ubuntu/24.04` userspace,
including an observed FORCE `EPERM` fallback and real systemd FD store.
It has not run separately on the other four required kernels.

## Ubuntu 26.04 cold-boot memory limitation

The stock `7.0.0-42.42` configuration enables kexec handover (KHO) by
default. KHO reserves scratch memory for a future kernel transition.
In a 2 GiB QEMU guest with this test initramfs, reservation can leave too
little memory for unpacking: the guest panics before PID 1 and no daemon
test executes. Other boots fail to reserve scratch, automatically disable
KHO and boot successfully. A successful retry alone conceals this issue.

Controlled boots with the same scratch sizes and layout reproduce the
panic with KHO on and boot with it off; three further `kho=off` boots
with address randomization enabled pass the memory probe. The matrix
helper now adds `kho=off` only when the supplied config enables KHO by
default. The stock kernel image, module tree, config and 2 GiB memory
remain the same. This is a test cold-boot setting, not a required daemon
installation setting. Daemon re-exec uses `execve`, not kernel kexec.
The tests make no kernel-handover preservation claim.
[Source, commands, failed boots and controls](../audit/phase6/boot-memory-20261031/README.md).

## Recorded execution and remaining work

The fresh required matrix after the approved errno correction and boot
calibration returned **MATRIX_RESULT=0**, with unchanged published targets
and test sources between its beginning/end. All five normal guests used
identical test/daemon executable identities. Exact commands, configurations,
image/module identities, features and guest releases are in
[matrix-20261031T071523Z-3533819](../audit/phase6/matrix-20261031T071523Z-3533819/README.md).

| Required kernel | Normal implemented profile | H20, all eight combinations | Transcript |
|---|---|---|---|
| Ubuntu `6.8.0-147-generic` | Pass | Pass | [run](../audit/phase6/matrix-20261031T071523Z-3533819/noble/run.log) |
| Vanilla `6.8.12` | Pass; empty-VRF errno 101 | Pass | [run](../audit/phase6/matrix-20261031T071523Z-3533819/vanilla-6.8.12/run.log) |
| Ubuntu `7.0.0-42-generic` | Pass; KHO disabled for cold boot | Pass | [run](../audit/phase6/matrix-20261031T071523Z-3533819/resolute/run.log) |
| Vanilla `7.0.14` | Pass | Pass | [run](../audit/phase6/matrix-20261031T071523Z-3533819/vanilla-7.0.14/run.log) |
| Mainline `7.3.0` | Pass | Pass | [run](../audit/phase6/matrix-20261031T071523Z-3533819/vanilla-7.3/run.log) |

Each normal guest passed 10 library live cases, 16 kernel cases, five
review cases, 38 ordinary binary cases plus three explicit privileged
binary cases, 26 process cases and 18 scenarios. This is the implemented
profile; the missing scenarios and source/delegated limitations above
remain open. A zero driver result does not close the complete Phase 6 gate.

Earlier full implemented-profile passes exist for Ubuntu 24.04, vanilla
7.0.14 and mainline 7.3 before the readiness/signal fix, and for Ubuntu
26.04 after that fix. Vanilla 6.8.12 originally stopped at K26/K34 before
process/scenario execution. The original driver failure, failed boot,
userspace fixture corrections and retry remain in
[the P3 history](../audit/phase6/P3_MATRIX_DRIVER_2026-10-31.md).

Extra mainline boots with `ipv6.disable=1` and `CONFIG_IPV6=n` each run
only the scoped H4/T4 case: IPv4 works on AF_INET sockets while IPv6 peers
remain disconnected. Their zero markers do not mean the normal
IPv6-dependent suite ran.

A required-target run must resolve the published candidates again at
start and end; superseded versions cannot pass the final Phase 6 gate.
Ubuntu's mentioned `6.8.0-148.148` was not published in the inspected
release/updates/security indexes; proposed packages and a planned
`6.8.0-149.149` do not substitute for a fetchable required target.
[H15 degradation cases](../audit/phase6/H15-20261031/README.md) now add four
passing host scenarios and a passing scoped missing-driver guest, and fix
host-defect severity/errno reporting. They postdate the five-target
18-scenario matrix above; the expanded suite/current reports still need
a complete latest-target rerun. The low-port-range DHCPv6 exception now
has a passing positive case in the same Ubuntu 6.8 host profile.

### Clock steps and pause/resume on each target

The separate H16 clock profile passes on all five required targets:

| Required target | Forward/backward wall-clock steps and monitored VM pause |
|---|---|
| Ubuntu 6.8.0-147-generic | [Pass](../audit/phase6/qemu-clock-noble-20261031/run.log) |
| Vanilla 6.8.12 | [Pass](../audit/phase6/qemu-clock-vanilla6812-20261031/run.log) |
| Ubuntu 7.0.0-42-generic | [Pass](../audit/phase6/qemu-clock-resolute-20261031/run.log) |
| Vanilla 7.0.14 | [Pass](../audit/phase6/qemu-clock-vanilla7014-20261031/run.log) |
| Mainline 7.3.0 | [Pass, three repetitions](../audit/phase6/H16-20261031/README.md) |

On every target, one-second pending-peer retries and thirty-second wire
DNS refreshes follow monotonic time across the steps and a QMP-confirmed
three-second pause. An unchanged DNS answer preserves the connected
tunnel. After resume, route-only recovery, address changes and temporary
bind-name loss recover with real bidirectional frames and stable session
indexes. [Measurements and exact scope](../audit/phase6/H16-20261031/README.md)
include the independent host/guest pause observations. This is a separate
one-case boot, not a rerun of the normal conformance/scenario profile.
Physical S3 and subscription overflow during a stopped guest are not
injected; live overflow/resync evidence remains separate.

### Scale and resource observations

The H17 profiles on Ubuntu 6.8.0-147-generic and mainline 7.3.0 pass fresh 300-entry
readiness, bidirectional traffic through every session, and three cycles
from 300 owned tunnels down to one. Descriptors return from 314 to 15.
An identical 300-entry reload issues 600 netlink requests; unrelated link
creation/removal from the peer namespace produces zero requests, checked
with a loss-accounted observer covering route and generic netlink.

Direct allocation tests found and fixed retained socket/registration map
capacity after shrink. RSS bounds alone did not detect those allocations.
The lifetime subscriber now uses an ordered lookup by interface index
and incarnation, preserving separate old/new proofs on index reuse. Its
updated native and 32 live kernel cases plus all 23 host scenarios pass
on Ubuntu 6.8.0-147-generic. Runtime deadline selection still scans tunnel
timers after events in that source snapshot. The deadline-index package
subsequently replaces those scans with ordered indexes, passing all
23 host scenarios, 26 process cases and a fresh mainline H16 clock/pause
case. Relevant-event cache maintenance still needs its complete CPU-cost
proof; a zero-request assertion alone cannot establish it.
The subsequent [event-cache package](../audit/phase6/event-cache-20261031/README.md)
replaces global cache scans with updates for changed dependencies and
fixes stale addresses after monitor resync and accumulated unbound VRF
sibling records. Its five focused regressions and all 23 host scenarios
pass on Ubuntu 6.8.0-147-generic. This policy change has not yet had a new
five-target matrix run; the earlier guest snapshots remain dated evidence.
The fresh mainline normal profile also passes 11 live library, 16 kernel,
five review, 38 ordinary binary plus three privileged binary, 26 process
and 23 scenario cases. Fresh readiness for both 300-entry daemons takes
38.43 seconds under the recorded TCG profile. These results predate the indexed lifetime change except for its fresh
Ubuntu 6.8 host checks. They are scoped to the executed profiles; H17 has
not yet run on every required target. Repository record
`audit/phase6/H17-20261031/README.md` gives the scale commands and limits;
`audit/phase6/lifetime-index-20261031/README.md` records indexed lifetime
proofs; `audit/phase6/deadline-index-20261031/README.md` records indexed
deadlines, conflict cancellation and fresh host/mainline-clock checks.

Coverage, rule completeness, full resource/event-cost proof, the expanded
normal matrix, final manager/profile refreshes and strict CI remain open. This page does not
declare Phase 6 complete or claim behavior for unexecuted cases.

### Refused monitor filters and descriptor exhaustion

The [R6/R9 package](../audit/phase6/R6-R9-20261031/README.md) adds two
host cases on Ubuntu `6.8.0-147-generic`. Denying `SO_ATTACH_FILTER` to
the daemon child produces one warning; the unfiltered monitor still
handles address removal/recovery, preserves the session index and carries
bidirectional traffic after 100 unrelated device create/delete cycles.
The warning includes the kernel's `EPERM` name.

A second child is limited to 32 descriptors with 40 configured tunnels.
Kernel `EMFILE` withholds readiness and produces one transient warning
per missing tunnel; the already-created session keeps carrying frames.
Raising that child's limit to 256, without a reload, permits all 40
tunnels and readiness while preserving the session index. No host limit
is changed. The package also distinguishes a real kernel `EAGAIN` from
the internal tunable wait and checks both tunnel/session creation reports.

These new cases extend the host suite to 25 scenarios. They have not
run separately on the other four required targets or in Incus, and do
not extend those targets' recorded coverage automatically.

### Library ownership and missing privileges

The [library requirement package](../audit/phase6/library-requirements-20261031/README.md)
adds three live cases on Ubuntu `6.8.0-147-generic`. Missing Tokio context
returns constructor errors with adopted descriptors still owned by the caller;
the blocking service works without a caller runtime. Dropping only the test
thread's effective `CAP_NET_ADMIN` withholds readiness without preventing
shutdown. Dropping a runtime closes active and retiring L2TP tunnel sockets
while preserving a foreign tunnel, session and interface index.

The expanded live kernel suite passes all 19 cases, the process suite all 26,
and the full host suite all 25 on this target. A SIGKILL assertion also checks
that both the tunnel and its session disappear without an external socket
store. These additions and the ownership fix still need the other four targets
and current-code Incus/manager refreshes; prior target records keep their
original scope.
