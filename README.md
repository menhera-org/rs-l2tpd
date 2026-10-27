# rs-l2tpd

Simple L2TPv3 daemon for Linux-based systems, written in Rust, and the
library (`rs_l2tpd`) it is built on.

## Features

- L2TPv3 over IP with Ethernet pseudowires, handled by the kernel.
- Peers by address or host name, over IPv4 or IPv6. Each tunnel uses one
  dual-stack socket, so a peer can change family without anything being
  re-created.
- Tunnel sockets bound to an interface or VRF, with the source address
  refreshed when addresses change. A bind device may appear later or be
  replaced under the same name.
- Session interfaces tracked by index, so renames by udev or networkd are
  fine.
- Optional fixed hardware (MAC) address and optional cookies per session.
- Readiness for systemd: the daemonising parent exits once the
  configuration is applied.

## Two rules

- **Run degraded gracefully rather than failing.** A configuration mistake
  never stops the daemon: what can be applied is applied, the rest is
  reported. An empty configuration, also one emptied by mistakes, is valid.
- **Never change `l2tpeth` interface identities unnecessarily.** A session
  interface is re-created only when its session must change in the kernel:
  its peer identifier or cookies, or its tunnel's identifiers or bind
  device. Nothing else, a mistake included, touches it, and a running
  interface is never taken down.

Everything below follows from these.

## Configuration

The daemon reads `/etc/rs-l2tpd.toml`, then every `*.toml` file in
`/etc/rs-l2tpd.toml.d/` in lexicographic order; later files override
individual keys. `rs-l2tpd --check` prints the merged result as it would be
applied and exits with status 1 if it found any problem.

```toml
[tunnels.uplink]
tunnel_id = 10
peer_tunnel_id = 10          # defaults to tunnel_id
remote_addr = "peer.example.org"   # an address or a host name
ip_version = "V6"            # "V4" or "V6": required for a host name, implied by an address
bind_interface = "vrf-wan"   # optional: SO_BINDTODEVICE

[sessions.lan]
tunnel_name = "uplink"
session_id = 100             # unique on the host, whatever the tunnel
peer_session_id = 100        # defaults to session_id
interface_name = "l2tp0"
interface_hwaddr = "02:00:5e:00:53:01"   # optional, unicast
cookie = "0011223344556677"  # optional: 8 or 16 hex digits, sent in every frame
peer_cookie = "8899aabb"     # optional, defaults to cookie: required in every received frame
```

Identifiers are non-zero. Tunnel identifiers, session identifiers and
interface names are each unique on the host: L2TPv3 over IP delivers
frames by session identifier alone, so a session identifier cannot repeat
even across tunnels. A literal `remote_addr` is a unicast address of the
`ip_version` family; loopback is allowed, for testing.

### Mistakes

| Mistake | At start-up | On reload |
|---|---|---|
| Unusable endpoint: `remote_addr` missing, neither an address nor a host name, not unicast or of the wrong family; `ip_version` invalid, or missing for a host name | The tunnel and its sessions are created, connected to the discard address `100::`, where frames are dropped; warning | The same; a correction reconnects the tunnel in place |
| `interface_hwaddr` not a unicast address | The session is created with the kernel's address; warning | The same; a correction applies the address in place |
| Any other mistake in an entry: a missing, zero or duplicate identifier, an invalid interface name or cookie | The entry is left out, a tunnel with its sessions; warning | The entry keeps the values in force; a new entry is left out; warning |
| A file that cannot be read or parsed | The file is skipped; warning | The previous configuration is kept as a whole |
| An entry's previous values no longer fit the rest (its identifier is now taken by another entry, say) | | The previous configuration is kept as a whole |

For comparison, 0.1.5 accepted a wrong-family literal and retried the
tunnel forever, and it ignores the cookie keys silently.

### Hardware addresses

`interface_hwaddr` is applied when the session is created, before anything
can bring the interface up, and whenever it changes. The kernel accepts a
new address only while the interface is down, and taking a running
interface down would drop its IPv6 addresses, routes and neighbours, so a
change is deferred until the interface is seen down, for example after
`ip link set <name> down`. Removing the key restores the kernel's address
under the same rule.

### Session cookies

Without cookies, anyone who can send IP protocol 115 packets to the host
and knows a session identifier can inject frames into that pseudowire: the
kernel checks neither the sender's address nor the bind device. A `cookie`
(four or eight bytes) is appended to every frame sent, and `peer_cookie` is
required in every frame received; the kernel discards the rest. This end's
`cookie` is the peer's `peer_cookie` and vice versa; with one value for
both directions, `cookie` alone suffices. Cookies are off unless
configured, which is the 0.1.5 wire format, so enable them on both ends at
once. Changing them re-creates the session. Frames stay in clear text:
cookies are not encryption. `--check` prints them; the logs do not.

## Readiness during boot

Readiness means that every tunnel and session of the applied configuration
exists in the kernel, those connected to `100::` included. The daemon
double-forks, and only then does the parent exit, the PID file (`-p`,
default `/run/rs-l2tpd.pid`) get written and `network-online.target` get
released; a failure to create any of them is retried every second until
then. Readiness does not wait for a host name to resolve or for an absent
bind device to appear.

Sockets bind to `::`, so tunnels need no address of their own. A tunnel
without a peer yet (a host name before it resolves, an unusable endpoint)
is connected to the discard address `100::`, and its frames are discarded
until it gets one. Connecting there needs a route but no reachability: when
the host routes `100::` already (through a default route, say), that route
is used; when it does not, as on an IPv4-only host or in a VRF with an
unreachable default route, the daemon creates the null device
`rsl2tpnull0`, a `dummy` link that drops whatever it transmits, and routes
`100::/128` to it in the table concerned. Blackhole and unreachable routes
cannot serve, as they refuse the connection outright, and nothing is ever
routed through loopback. The null device is created only when needed and
removed on shutdown. A literal address needs a route when the tunnel is
created, as in 0.1.5, so a literal peer without one delays readiness.

The PID file is published as a fresh inode owned by the daemon user,
replacing a legacy file atomically. Its directories must be owned by root
or the daemon user; the daemon never changes their permissions and only
warns when other users could replace the file. In a directory it cannot
write to, a precreated file is updated in place if the daemon user owns
it and it has one link and no group or other write permission, for
capability-based services with a file in `/run`.

The daemon depends on no init system and no libc. Privileged kernel and
daemon tests, including interoperability with 0.1.5, are documented in
[`tests/docker/README.md`](tests/docker/README.md).

## Library

Without default features the crate pulls in neither `clap`, `toml`,
`env_logger` nor `serde`; it does no file or terminal I/O, installs no
signal handlers and logs through the `log` facade.

```toml
[dependencies]
rs-l2tpd = { version = "0.2", default-features = false }
# or, to deserialise configurations from any serde format:
rs-l2tpd = { version = "0.2", default-features = false, features = ["serde"] }
```

- `rs_l2tpd::config` holds the configuration types, built in code or
  deserialised with serde; `PartialConfig::into_config_lenient` and
  `into_config_with_previous` implement the table above.
- `rs_l2tpd::service::Service` is the daemon minus process management, for
  Tokio programs.
- `rs_l2tpd::blocking::Service` is the same behind a blocking API, on a
  Tokio runtime of its own, usable without Tokio or inside another runtime.
- `rs_l2tpd::runtime::Runtime` is the reconciler, for programs that drive
  the event loop themselves.

Every type from another crate that appears in the API is re-exported next
to where it is used (`config::IpHost`, `config::FQDN`, `config::L2tpIfName`,
`config::L2tpIfNameExt`, `error::L2tpError` and `runtime::mpsc`), so none of
them needs a dependency of a matching version to be named.

Both services hand out a `Control` handle for requesting reloads and
shutdowns (the binary drives it from `SIGHUP`, `SIGTERM` and `SIGINT`) and
for reading the current configuration. Shutdown requests persist even when
the event queue is full; `Control::reload_wait()` waits for room, while
`reload()` fails if the queue is full.

## Building

`cargo build --release` builds the daemon (the `bin` feature is on by
default); add `--features setup` for the `--setup` installer, which installs
the binary and a sandboxed systemd unit under `/usr/local`.
