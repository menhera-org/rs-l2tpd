# rs-l2tpd

Simple L2TPv3 daemon for Linux-based systems, written in Rust, and the
library (`rs_l2tpd`) it is built on.

## Features

- L2TPv3 is handled in the kernel, so minimal overhead expected.
- Supports binding to specific VRFs or interfaces
- Supports FQDN-specified remote endpoints
- Session interfaces are renamed and configured by interface index, so a
  rename by udev or networkd after creation is handled correctly.
- Optional fixed hardware (MAC) address per session interface.

## Configuration

The daemon reads `/etc/rs-l2tpd.toml` and then every `*.toml` file in
`/etc/rs-l2tpd.toml.d/` in lexicographic order; later files override
individual keys of earlier ones. `rs-l2tpd --check` prints the merged,
validated result.

```toml
[tunnels.uplink]
tunnel_id = 10
peer_tunnel_id = 10          # defaults to tunnel_id
ip_version = "V6"            # "V4" or "V6" ("v4"/"v6" accepted)
remote_addr = "peer.example.org"   # an address or a host name
bind_interface = "vrf-wan"   # optional: SO_BINDTODEVICE

[sessions.lan]
tunnel_name = "uplink"
session_id = 100
peer_session_id = 100        # defaults to session_id
interface_name = "l2tp0"
interface_hwaddr = "02:00:5e:00:53:01"   # optional, unicast
```

`interface_hwaddr` is applied through rtnetlink when the session is created
and whenever it changes. An `l2tpeth` device only accepts a new address while
it is down, so changing the address of a running interface takes it down and
brings it back up. Removing the key restores the address the kernel assigned
at creation.

## Early readiness during boot

This daemon binds its sockets to `::`, so it does not
need any networking for L2TPv3 interfaces to exist. It
does not need interfaces it binds to exist as well, and
it just creates sockets with no bind interfaces when
they are absent, and let the sockets bind to interfaces
when the interfaces appear. This is always possible as
the bind address is `::`. It also connects its sockets
to `100::` (a discard address) initially, and then to
the resolved addresses if FQDN was configured. Concrete
destination addresses are configured upfront always.

Note that this only applies to host names. A `remote_addr`
given as a literal IP address is connected to as is, so
the kernel must have a route to it when the tunnel is
created: without one, the tunnel socket's `connect()`
fails with "Network unreachable", the daemon keeps
retrying every second, and readiness (the parent's exit,
the PID file, `network-online.target`) waits until a
route appears. This matches 0.1.5. If the route only
exists through the configured `bind_interface`, that
interface must exist too, as an absent bind interface
makes the daemon connect through the main routing table
first and move to the interface once it appears. To keep
startup independent of routing, configure the peer as a
host name (a `/etc/hosts` entry suffices).

To signal the system of `rs-l2tpd`'s readiness (socket/
L2TPv3 interface existence), it has been modified to do
a double fork (daemonizing), and the parent only exits
on readiness of every interface configured. Transient
kernel or network failures are retried before readiness.
`-p|--pidfile` option (defaults to `/run/rs-l2tpd.pid`)
is available. The startup waits until kernel operations
succeed if the syntax of the configs is correct, so
network unavailability does not fail startup. SystemD
integration files use an unlimited startup timeout and
block `network-online.target` until configuration has
converged.

PID-file directories must be owned by root or the daemon user, and an
existing PID file must belong to the daemon user. The daemon replaces legacy
PID files atomically with a fresh inode of its own. It never changes the
permissions of existing directories; a directory writable by other users
only earns a warning, since such users could then replace the PID file.

This daemon intentionally does not depend on any
specific init system nor libc.

## Library

The crate is also a library. Without default features it pulls in neither
`clap`, `toml`, `env_logger` nor `serde`; it does no file or terminal I/O,
installs no signal handlers and logs through the `log` facade.

```toml
[dependencies]
rs-l2tpd = { version = "0.2", default-features = false }
# or, to deserialise configurations from any serde format:
rs-l2tpd = { version = "0.2", default-features = false, features = ["serde"] }
```

- `rs_l2tpd::config` holds the configuration types, built in code or
  deserialised with serde.
- `rs_l2tpd::service::Service` is the daemon minus process management, for
  Tokio programs.
- `rs_l2tpd::blocking::Service` is the same behind a blocking API. It runs
  a multi-threaded Tokio runtime on a thread of its own, so it can be used
  without Tokio and even from inside another runtime.
- `rs_l2tpd::runtime::Runtime` is the reconciler for programs that want to
  drive the event loop themselves.

Both services hand out a `Control` handle for requesting reloads and
shutdowns (the binary drives it from `SIGHUP`, `SIGTERM` and `SIGINT`) and for
reading the current configuration.

Shutdown requests persist even when the event queue is full. Asynchronous
callers can use `Control::reload_wait()` to wait for room for a reload;
`reload()` returns an error if the queue is full.

## Building

`cargo build --release` builds the daemon (the `bin` feature is on by
default); add `--features setup` for the `--setup` installer, which installs
the binary and a sandboxed systemd unit under `/usr/local`.
