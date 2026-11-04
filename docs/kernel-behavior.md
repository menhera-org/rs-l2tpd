# Kernel behavior and qualification

[Documentation index](README.md) · [Testing](testing.md#kernel-targets) ·
[Kernel evidence map](kernel-evidence.md)

Repository file `audit/VERIFICATION.md` identifies the qualified production
source, commands, publication selections and results. Normal QEMU profiles
run kernel conformance, process tests and all 28 current normal scenarios, including
300 tunnels/sessions and fragmentation. Clock/pause tests use separate boots.
A passing bare-kernel guest does not qualify that distribution's systemd,
udev, networkd, SELinux policy, installer or system-container integration.

## Per-kernel differences

| Required target | Empty IPv6 VRF, no usable source or route (K26/K34) | Foreign-namespace deletion notice (K41) | Test boot |
|---|---|---|---|
| Ubuntu 24.04 `6.8.0-147-generic` | `EADDRNOTAVAIL` (99) | Delivered; local objects survive | Stock image and matching modules |
| Vanilla `6.8.12` | `ENETUNREACH` (101) | Delivered; local objects survive | Built-in L2TP/VRF |
| Ubuntu 26.04 `7.0.0-42-generic` | `EADDRNOTAVAIL` (99) | Delivered; local objects survive | Stock image/modules, cold-boot `kho=off` |
| Vanilla `7.0.14` | `EADDRNOTAVAIL` (99) | Delivered; local objects survive | Built-in L2TP/VRF |
| Mainline `7.4.0-rc1` | `EADDRNOTAVAIL` (99) | No foreign notice in the five-second probe; local objects survive | Built-in L2TP/VRF |

The empty-VRF distinction is limited to that exact no-source/no-route case.
Both errnos receive the existing transient policy: leave the tunnel
disconnected and retry when dependencies change. The shared test records
the errno and rejects other errors. This does not reclassify all source
selection failures as `ENETUNREACH`.

K41 notices are advisory. Older kernels announce commanded deletions across
network namespaces; upstream confines them to the object's namespace from
v7.3. The source boundary is
[v7.2](https://raw.githubusercontent.com/torvalds/linux/v7.2/net/l2tp/l2tp_netlink.c)
and [v7.3](https://raw.githubusercontent.com/torvalds/linux/v7.3/net/l2tp/l2tp_netlink.c).
Distribution backports need actual observation. The daemon checks local
identity and absence before releasing names/identifiers or removing records.
Socket-close cleanup is not announced in the same way.

Matching foreign IDs can cause legitimate local verification requests on
all-namespace kernels. Request-count windows therefore run serially for
workloads sharing a kernel, or in independent QEMU kernels. Namespace
isolation alone does not isolate these notifications. A suspected deletion
remains coalesced for verification while its local session exists; mere
presence cannot distinguish queued deletion, a stale notice or a foreign
namespace. Removing/replacing the record cancels that verification task.

## Executed profiles

The required matrix below records source `c599b1f` with its 27-scenario
fixture. Fresh CI on fixture fix `69a0b42` passes the complete 28-scenario
Ubuntu 6.8 normal profile and unchanged 100% production coverage. The added
capture regression also passes ten consecutive GNU and ten musl runs.

| Required kernel | Normal / H20 / H17 | Process cases | H16 clock/pause |
|---|---|---|---|
| Ubuntu `6.8.0-147-generic` | 27 pass / pass / pass | 37 pass | Pass |
| Vanilla `6.8.12` | 27 pass / pass / pass | 37 pass | Pass |
| Ubuntu `7.0.0-42-generic` | 27 pass / pass / pass | 37 pass | Pass |
| Vanilla `7.0.14` | 27 pass / pass / pass | 37 pass | Pass |
| Mainline `7.4.0-rc1` | 27 pass / pass / pass | 37 pass | Pass |

The normal profile includes the shared source/VRF/zone checks, forced
netlink loss and recovery, lifetime-capture ordering, socket ownership,
resolver wire identities, anonymous Reply rejection, signal/fork refusal
paths, capability degradation, H20 and H17. Its 37 process cases are
separate from its 27 scenarios. Each H16 profile runs one clock/pause case
and requires the controller's successful QMP pause/resume marker.
Mainline has additional `ipv6.disable=1` and `CONFIG_IPV6=n` boots; modular
Ubuntu 7.0 has missing-Ethernet-driver degradation and recovery.

### Optional distribution kernels

| Distribution | Exact stock kernel | Normal | Clock/pause |
|---|---|---|---|
| Debian 13 | `6.12.115+deb13.1-amd64` (6.12.115-2) | Pass: 28 scenarios and 37 process cases | Pass |
| Rocky Linux 9 | `5.14.0-687.61.1.el9_8.x86_64` | Pass: 28 scenarios and 37 process cases | Pass |
| Rocky Linux 10 | `6.12.0-211.72.1.el10_2.x86_64` | Pass: 28 scenarios and 37 process cases | Pass |

Debian 13 replaces Debian 12 in the optional matrix. All six profiles pass
after signed fixture fix `69a0b42` was synced, with empty initial/final source
patches. Production executables and existing assertions are unchanged; the
scenario executable adds the capture regression. The required profiles above
retain their earlier 27-scenario results.

The earlier Debian 13 failure was a test-fixture capture race: opening an
AF_PACKET socket with ETH_P_ALL admitted foreign Ethernet before nlmon bind.
Signed fixture fix [69a0b42](https://github.com/menhera-org/rs-l2tpd/commit/69a0b42d46cf71f938a4da51503265730aab4a17)
opens with protocol zero and activates capture on bind. Parsing, request
thresholds and loss checks remain strict. The daemon uses AF_NETLINK and
needed no behavior change. The regression passes on GNU, musl and the stock
Debian kernel; restoring the old opening fails deterministically. The original
packet bytes were not retained. The
[archived investigation](https://github.com/menhera-org/rs-l2tpd/blob/9817a0d19ac89d5cc0844180022ec8b0dfa07ce5/audit/nlmon-bind-fix/README.md)
retains kernel-source references, controls and full results; the
[earlier failure](https://github.com/menhera-org/rs-l2tpd/tree/8766a43c2099a9ff71ae7ee1e30866c61777fbb4/audit/optional-kernels)
also remains in history.

These use checksum-verified stock images, configurations and matching module
packages. They run the unchanged guest suites and remain optional additions
to the required matrix. The metadata, exact package digests and extractor
identity are retained with the results. Kernel version numbers alone do not
identify distribution backports. No per-distribution userspace or complete
optional-kernel source audit is inferred from these guest results.

## Best-effort behavior on Debian 12

Debian 12 is outside the support target. Its 6.1 kernel refuses UP-device
renames and even unchanged MAC writes while UP, as recorded in the
[archived optional run](https://github.com/menhera-org/rs-l2tpd/tree/129a4e1fb02da9fab01ef61730853c2129ee9e5a/audit/phase6/optional-kernels-20261104).
The daemon defers MAC writes and retains the device, name, addresses and
children when a rename is refused; pending operations are retried. An active
rename or staged publication can remain pending until the operator lowers
the device. The daemon never lowers it to force convergence. Startup
readiness does not wait for publication; reload completion can wait for a
refused rename. Debian 12 remains unqualified.

## Session deletion and dump traversal

These are source observations, separate from live reuse timing:

| Required target | Session deletion (K18) | Session dump traversal (K16) |
|---|---|---|
| Ubuntu `6.8.0-147.147`, vanilla `6.8.12` | Unhash/close inline | Positional `l2tp_session_get_nth`; concurrent deletion can skip the next entry |
| Ubuntu `7.0.0-42.42`, vanilla `7.0.14`, mainline `7.4-rc1` | Queued deletion work | Identifier-based `l2tp_session_get_next` |

Upstream changes the deletion model at v6.12; distribution backports must be
checked rather than guessed from a release number. A zero-retry live
delete/recreate run cannot prove synchronous deletion: a worker can finish
before the next request. The daemon confirms absence on every target and
treats dumps as observations, never atomic identity proofs. Tunnel-socket
close queues tunnel cleanup on every required target (K17).

The exact distribution/upstream source comparisons remain available in the
[archived source record](https://github.com/menhera-org/rs-l2tpd/tree/c599b1f9c2343a3ffe6be315a6d77c4b68106744/audit/phase6/kernel-behavior-20261031)
and the
[mainline source qualification](https://github.com/menhera-org/rs-l2tpd/tree/c599b1f9c2343a3ffe6be315a6d77c4b68106744/audit/phase6/mainline-rc-qualification-20261102).
The current [kernel specification](spec/kernel.md) retains the relevant
versioned file/line citations.

## Fragmentation

H20 uses a 1500-byte veth underlay and session MTUs 1500 and 9000, over IPv4
and IPv6 with ordinary and VRF binding: eight combinations per normal guest.
It checks full-size delivery both ways, bulk frames, session receive counters,
sender fragment counters and no transmit drops. A separate live test reads
back `IP_PMTUDISC_DONT`, `IPV6_PMTUDISC_DONT` and `IPV6_DONTFRAG=0`.

IPv4 has K44's explicit socket-option contract. The native IPv6 L2TP output
path currently relies on `skb->ignore_df` (K43), rather than consulting those
IPv6 options. They remain set, but delivery must be retested on new kernels.
Netfilter can reassemble before the ordinary IPv6 counters; zero
`Ip6ReasmReqds` does not refute delivery proved by session receive counters.

## Managers and unprivileged containers

An UP l2tpeth device refuses a differing MAC with `EBUSY` (K31), including
when udev is the caller. The daemon defers its change and preserves the
index, UP state, addresses and children; it never lowers an active device
to force the write. Direct configured-name creation improves name matching
but does not order udev's MAC assignment against networkd's activation.

H11 accepts either persistent assignment or the documented `EBUSY` result
under concurrent managers, while requiring the active interface to survive.
A separate ordered case assigns the persistent MAC while down, then checks
activation and stability after clean re-creation. This proves the ordering
prerequisite, not unconditional persistent assignment. A later manager MAC
override remains authoritative under S12/G4. Operators requiring a configured
MAC must coordinate policy, for example `MACAddressPolicy=none` matching both
creation names. See [H11](spec/hosts.md#other-network-managers).

Three fresh unprivileged Incus runs and the unmodified root-systemd guest
pass on Ubuntu `6.8.0-147-generic` with Ubuntu 24.04 userspace. Incus proves
`SO_RCVBUFFORCE=EPERM` and the ordinary-buffer fallback, namespace-local
`bindv6only`, udev/networkd handling and real descriptor-store handover.
Root QEMU covers successful FORCE; both paths validate the production buffer.
These userspace results do not extend to the other kernel targets.
Unprivileged containers cannot load host modules or obtain capability in
the initial user namespace; the host must supply the required modules.

## Ubuntu 26.04 cold-boot setting

The stock `7.0.0-42.42` configuration enables kexec handover by default.
Its scratch reservation can prevent this test's initramfs from unpacking
in a 2 GiB guest. The helper adds `kho=off` only for configurations enabling
that default; the stock kernel, modules and memory size are otherwise
unchanged. This is a cold-boot test setting, not a daemon installation
requirement. Daemon restart uses `execve`; the suite makes no kernel-handover
preservation claim. The controlled failed/successful boots remain in the
[archived boot record](https://github.com/menhera-org/rs-l2tpd/tree/c599b1f9c2343a3ffe6be315a6d77c4b68106744/audit/phase6/boot-memory-20261031).

## Limits of the evidence

Each normal pass establishes the assertions actually executed. Source-only
facts and delegated resolver internals retain their
[evidence classifications](kernel-evidence.md); a passing profile cannot
promote them to per-target live proofs. The full route-type errno table,
host autoload policy, forced concurrent dump traversal and all malformed
resolver packet refusals are not independently exercised on every target.
Historical attempts and superseded results remain in Git history.
