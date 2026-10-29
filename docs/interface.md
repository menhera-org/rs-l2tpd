# External interface

[Documentation index](README.md)

What an operator or an embedding program sees after the rewrite. Every
item is fixed by the specification; the rule numbers point at the
normative text. The current binary is a rewrite stub that exits 2;
[known gaps](spec/README.md#known-gaps) describe the historical `741117b`
implementation. 0.1.5 is the last release.

## Configuration files

The main file `/etc/rs-l2tpd.toml`, then every `*.toml` of
`/etc/rs-l2tpd.toml.d/` in byte order, merged key by key before
validation (C1, C2). Both paths can be changed at build time
(`CONFIG_FILE_PATH`, `CONFIG_DIR_PATH`) and on the command line.

```toml
[tunnels.uplink]
tunnel_id = 10
peer_tunnel_id = 10          # defaults to tunnel_id
remote_addr = "peer.example.org"   # an address, fe80::1%eth0 for link-local, or a host name
ip_version = "V6"            # required for a host name, implied by an address
bind_interface = "vrf-wan"   # optional: an interface or a VRF; it need not exist yet
resolver_name = "wan-dns"    # optional, host names only; default: the system resolver

[resolvers.wan-dns]
method = "ipv6"              # "ra", "dhcpv6" or "ipv6"; or addresses = ["192.0.2.53", "[2001:db8::53]:5353"]
bind_interface = "wan0"      # required with method: a link, not a VRF
dhcpv6_identity = "link-layer"   # or "anonymous", "random"; or dhcpv6_duid = "0003000102005e005301"

[sessions.lan]
tunnel_name = "uplink"
session_id = 100             # unique on the host, whatever the tunnel
peer_session_id = 100        # defaults to session_id
interface_name = "l2tp0"
interface_hwaddr = "02:00:5e:00:53:01"   # optional, unicast
cookie = "0011223344556677"  # optional: 8 or 16 hex digits, sent in every frame
peer_cookie = "8899aabb"     # optional, defaults to cookie

[host]
fix_bindv6only = true        # default
```

Field rules: C7 (tunnels), C8 (sessions), C16 (resolvers), C17 (host).
Mistakes and what they do at start-up and on reload: C10, C12. Entries
are matched across reloads by their kernel identity, so renaming
`[tunnels.uplink]` to `[tunnels.wan]` keeps the tunnel and its
interfaces (C14). The 0.1.5 format keeps working (G22).

## Command line

```
rs-l2tpd [--config FILE] [--config-dir DIR] [--pid-file FILE] [--verbose]
         [--check | --foreground | --restart | --adopt-version | --version
          | --setup-systemd [--prefix DIR]]
```

| Mode | Does | Exit |
|---|---|---|
| none | Starts the daemon: double fork, readiness, PID file (P4, P6, P10) | parent 0 at readiness, 1 before |
| `--check` | Prints the configuration that would be applied, in a fixed order, and every problem (P3, O8) | 0 without problems, 1 with any |
| `--foreground` | Runs in the calling process: no fork, no PID file, no readiness report (P4) | the daemon's own |
| `--restart` | Sends `SIGUSR2` to the PID in the PID file (P26) | 0 delivered, 1 not |
| `--adopt-version` | Prints `rs-l2tpd-adopt 1` (P26) | 0 |
| `--version` | Prints the crate version | 0 |
| `--setup-systemd` | Only in a binary built with the `setup-systemd` feature: installs this binary, the unit and the configuration paths on a systemd host, within the scope of [packaging](packaging.md#--setup-systemd-feature-setup-systemd) | 0 done, 1 a step failed |

Misuse exits 2 with the usage on standard error (P27); so does
`--setup-systemd` in a binary built without the feature. The daemon exits
0 after a complete shutdown, 1 when a shutdown step failed, 2 when the
reload callback panicked (O7).

## Signals

| Signal | Request |
|---|---|
| `SIGHUP` | Reload the files; several before the daemon acts cause one reload (P12, P13) |
| `SIGTERM`, `SIGINT` | Shut down: sessions, then tunnels, then the PID file; everything owned is removed (P16) |
| `SIGUSR2` | Restart onto the binary on disk in the same process, tunnels and interfaces kept (P26) |
| `SIGPIPE` | Ignored (P12) |

A `SIGTERM` is always a teardown; systemd's `stop` and `restart` are the
same to the daemon, and a restart that keeps the interfaces is `SIGUSR2`
or `rs-l2tpd --restart` (P14, P26).

## Readiness and the PID file

Readiness is that every eligible tunnel and session exists in the
kernel, connected or not, published or still under a temporary name
(P6). It waits for no name, route, source, bind device, IPv6 or deferred
hardware address (P7); at most ten seconds for identifiers held
elsewhere (P8), plus at most five seconds for a needed tunable-write
handshake before registration (L12, T26). The parent exits 0 and `/run/rs-l2tpd.pid` appears
(P10); with the supplied unit that releases `network-online.target`.

## Logging

Standard error, one line per message, `LEVEL target: message`, no
timestamp; `--verbose` adds debug (O1). Severity by condition: O2. A
lasting condition is logged once when it begins and once when it ends,
except a deferred hardware-address change, logged at every reconcile
(O3, S12). Cookies are never logged (O5); `--check` prints them.

## The systemd unit

`contrib/rs-l2tpd.service` (P21): `Type=forking` with the PID file,
`Before=network-online.target`, `RequiredBy=network-online.target`,
`TimeoutStartSec=infinity`, `Restart=on-failure`, `NotifyAccess=all`,
`FileDescriptorStoreMax=` for the tunnels; runs as root with the
bounding and ambient sets limited to `CAP_NET_ADMIN`, `CAP_NET_RAW` and
`CAP_NET_BIND_SERVICE`, `NoNewPrivileges=yes`, a read-only system
except the PID file, `ProtectHome=yes`, `PrivateTmp=yes`, address
`RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6` (`AF_UNIX`
for the descriptor-store notification socket, independent of resolver needs), and the `net.ipv6.bindv6only`
write allowed. It is one integration: the process contract (P22) is
what every init system gets, and a container entry point uses
`--foreground`.

With the store, the daemon pushes each tunnel socket into it as the
tunnel exists and withdraws it at an explicit shutdown, so that the
tunnels and interfaces survive a crash and the next instance adopts them
(P14, S28). No systemd library is linked.

## Host requirements

Linux of the verified range with `l2tp_core`, `l2tp_netlink`, `l2tp_ip`,
`l2tp_eth` and, for IPv6 peers or dual-stack sockets, `l2tp_ip6`, loaded
or loadable (R1); `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`
(R49, each missing one reported once and worked around). No `/proc`
except for the `bindv6only` write (P25), no `dummy` driver, no route, no address, no DNS, no IPv6
at start-up. Hosts without IPv6, with `disable_ipv6`, with
`ipv6.disable=1`, VRFs, routers without a default route, containers and
`bindv6only=1` are covered by [hosts](spec/hosts.md).

## Library

```toml
[dependencies]
rs-l2tpd = { version = "0.2", default-features = false }               # no TOML, no serde
# Or use this alternative instead of the line above:
# rs-l2tpd = { version = "0.2", default-features = false, features = ["serde"] }
```

- `config`: `Config` is always valid (L4); `PartialConfig` offers the
  strict and the two lenient conversions with every problem (C15).
- `service::Service` (Tokio): `new(config, adopted)`, `converge`, `run`
  with a reload callback and a restart callback, `control()` (L5–L7).
- `blocking::Service`: the same on a runtime of its own; `Drop` shuts
  down (L8).
- `runtime::Runtime`: `new`, `reconcile`, `handle_event`, `shutdown`;
  every `ControlEvent` goes to `handle_event` (L9, L10); the program
  answers `WriteTunable`, `StoreSocket` and `ForgetSocket` (L12, L13).
- `Control`: `reload`, `reload_wait`, `shutdown`, `restart`, `config`
  (L6).
- Errors: one non-exhaustive enum (L11). No unsafe code (L2). Every
  foreign type re-exported next to its use; enums non-exhaustive (L3).
- The library does no standard or file I/O, reads no environment,
  installs no handler, writes no tunable (L1).
