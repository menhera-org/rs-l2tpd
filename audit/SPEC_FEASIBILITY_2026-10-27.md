# Feasibility tests for the untested specification claims — 2026-10-27

| Detail | Value |
|---|---|
| Date | **2026-10-27 (Asia/Tokyo)** |
| Specification | `docs/spec` as rewritten the same day (uncommitted working tree) |
| Kernel | `6.8.0-147-generic` (Ubuntu, Linux 6.8.12 plus backports), the same tree the audits read |
| Where | Disposable containers (`alpine:3.22` with iproute2, `--privileged --network none`, plus non-privileged variants for capability tests) and a disposable Rust crate under `/tmp` (the audit probe, `libc` only, 830 lines) |
| Purpose | Show that every mechanism the revised specification relies on and no existing test covers is feasible on a live kernel, and record what the kernel actually does |

Every mechanism is feasible. Two kernel facts were sharpened on the way and are corrected in `docs/spec/kernel.md` and `docs/spec/requirements.md`: `SO_RCVBUFFORCE` needs `CAP_NET_ADMIN` in the **initial** user namespace, so it is unavailable in user-namespaced containers; and Docker sets `net.ipv4.ip_unprivileged_port_start=0` in its containers, so DHCPv6's port 546 needs no capability there.

## Results

| Case | Claim tested | Result |
|---|---|---|
| F1 | [P14](../docs/spec/process.md#restart): a live tunnel's socket handed to another process over the descriptor-store protocol (`FDSTORE=1` datagram with `SCM_RIGHTS`, then `LISTEN_FDS`/`LISTEN_PID`/`LISTEN_FDNAMES`), the first process exiting, the second adopting | **Feasible.** The tunnel and its session survived the first process's exit while the stand-in store held the descriptor; the adopting process identified the tunnel from `getsockname` (connection id), read it and its session back over generic netlink, created a second session on it, connected it and transmitted a frame, then disconnected; the session interface kept its index (5) throughout; closing the adopted socket removed everything. |
| F2 | [V9](../docs/spec/resolvers.md#binding): a DNS query from a socket bound by `SO_BINDTOIFINDEX` to a VRF member, or to the VRF, against a server reachable only through the VRF's table | **Feasible.** Unbound: `ENETUNREACH` (the main table has no route). Bound to the member device: answered (`A 203.0.113.9`). Bound to the VRF: answered (`AAAA 2001:db8::9`). |
| F3 | [V10](../docs/spec/resolvers.md#router-advertisements), [K14](../docs/spec/kernel.md#requirements): RDNSS options of a router advertisement delivered to a netlink socket on `RTNLGRP_ND_USEROPT` | **Feasible.** One `RTM_NEWNDUSEROPT` (type 68) arrived for the receiving interface with `icmp_type=134` and an RDNSS option carrying both servers and the lifetime (600), after a single RA sent from a raw ICMPv6 socket in another namespace; no raw socket on the receiving side. |
| F4 | [V12](../docs/spec/resolvers.md#dhcpv6-information-request): an Information-Request from UDP port 546 on the bind interface to `ff02::1:2`, answered with options 23 and 32 | **Feasible.** The Reply carried the DNS server and an information refresh time of 1200; the server saw the request from the client's link-local address. |
| F4b/F4c | [K13](../docs/spec/kernel.md#requirements): port 546 needs `CAP_NET_BIND_SERVICE` or a lowered `ip_unprivileged_port_start` | **Confirmed, with a finding.** With the capability dropped and `ip_unprivileged_port_start=1024`, `bind` fails `EACCES`; with the capability, or with the sysctl at 0, it succeeds. Docker sets the sysctl to 0 in every container by default, so the capability is not needed there. |
| F5 | [S22](../docs/spec/sessions.md#identity-loss), [K16](../docs/spec/kernel.md#facts): deleting a session by its creation-time name after the device was renamed | **Feasible.** `L2TP_CMD_SESSION_DELETE` with `L2TP_ATTR_IFNAME=renamed0` (the current name) fails `ENODEV`; with the creation-time name `uc0` it deletes the session; a following `SESSION_GET` fails `ENODEV`. |
| F6 | [P25](../docs/spec/process.md#host-tunables), [T26](../docs/spec/tunnels.md#hosts-with-bindv6only): the process writes `net.ipv6.bindv6only=0` itself, then creates a new socket | **Feasible.** The socket created before the write kept `IPV6_V6ONLY=1`; the one created after reported 0; the sysctl read back 0. |
| F8 | [P26](../docs/spec/process.md#restart): the daemon's own restart operation, re-executing the binary on disk in the same process with the tunnel socket inherited (close-on-exec cleared for it, `LISTEN_FDS` protocol in the environment) | **Feasible.** The same PID (17) ran the new program afterwards; the tunnel and its session survived with the interface index unchanged; the new program adopted descriptor 3, read the tunnel and session back, added a session, connected and transmitted; exiting removed everything. `execv` must be given the path on disk, not `/proc/self/exe`, once the file was replaced. |
| F7 | [R10](../docs/spec/requirements.md#the-host), [K36](../docs/spec/kernel.md#facts): `SO_RCVBUFFORCE` to 8 MiB | **Not available in this environment, by a rule now recorded.** `EPERM` for a process with every capability, because `sockopt_capable` calls `capable()`, which checks the initial user namespace (`net/core/sock.c:1080-1083`, `1271-1275`); the host of this audit is itself a user-namespaced container (`/proc/sys/net/core/rmem_max` is not even visible in it). `SO_RCVBUF` works and is capped (8 MiB requested, 425,984 granted). |

## Corrections made to the specification

- `K36` now says that `SO_RCVBUFFORCE` requires `CAP_NET_ADMIN` in the initial user namespace and is therefore refused inside user-namespaced containers; `R10` says the daemon tries it and falls back to `SO_RCVBUF`, which is capped by the host's `rmem_max`, and that in such containers the cap is what the daemon gets.
- `K13` notes Docker's default of `ip_unprivileged_port_start=0`, which makes the capability unnecessary in Docker containers; the rule itself is unchanged.

## Environment caveat

The machine the tests ran on (`workspace1`) is itself a container with a user namespace: capability checks against the initial user namespace fail inside it even for a process with every capability bit set, and non-namespaced sysctls under `/proc/sys/net/core` are not visible. Every L2TP, netlink, routing and socket result of the audits is unaffected (those paths use `ns_capable`); F7 is the one result that depends on it, and it is the result a user-namespaced deployment of the daemon would see.

## Reproduction

Scripts, probe source and raw outputs are in the session scratchpad
`/tmp/claude-1001/-home-dev-rs-l2tpd/c965bace-0e3f-4e30-bfa8-e90ff03ba9a1/scratchpad/`:
`exp/f_handover.sh`, `exp/f_resolver.sh`, `exp/f_misc.sh`, `exp/f_reexec.sh`
(outputs `exp/f_*.out`), `probe/src/main.rs`; the F4b/F4c and F7b/F7c
variants are the one-line `docker run` commands recorded in the audit
transcript. They can be moved under `tests/` on request; the probe
subcommands used here are `store`, `adopt`, `notify=`, `reexec=`,
`sdelname=`, `getv6only`, `sysctl=`, `dns-server`, `dns-query`, `ra-send`,
`dhcp6-server`, `dhcp6-client`, `rcvbufforce=`.
