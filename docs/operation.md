# Operation

This guide is for users and administrators running the daemon.
Install it using [installation](installation.md), check the
[kernel requirements](kernel-support.md), then configure the local end.
The remote end must use matching tunnel/session identifiers and cookies.

## Configuration files

The daemon reads `/etc/rs-l2tpd.toml` first, followed by every `*.toml` file
in `/etc/rs-l2tpd.toml.d/` in byte order. Files merge key by key before
validation. Use `--config FILE` and `--config-dir DIR` to select other paths.

A minimal static peer and one Ethernet session:

```toml
[tunnels.uplink]
tunnel_id = 10
peer_tunnel_id = 20
remote_addr = "192.0.2.2"

[sessions.lan]
tunnel_name = "uplink"
session_id = 100
peer_session_id = 200
interface_name = "l2tp0"
```

Replace the example address and identifiers with your peer's values.
The local `tunnel_id` is the remote end's `peer_tunnel_id`, and the local
`session_id` is its `peer_session_id`. When omitted, each peer identifier
defaults to the corresponding local identifier.

Configure addresses, routes, MTU and administrative state on `l2tp0` through
your normal network manager. The daemon creates and maintains the device;
it does not bring it down to force a rename or hardware-address change.

### Peer addresses and binding

`remote_addr` accepts an IPv4/IPv6 literal, a link-local address with a zone
such as `fe80::1%eth0`, or a host name. Host names require `ip_version`:
`"V4"` or `"V6"`. A literal implies its family.

Set `bind_interface = "wan0"` to bind to an ordinary interface, or use a
VRF's name. Missing devices and addresses need not exist at startup:
the daemon waits and reconnects as dependencies become available.

For a host name, `resolver_name` chooses a configured resolver; omission
uses the system resolver. See [peer discovery](peer-discovery.md).

### Session options

Session IDs must be unique across the host's configuration, even in
different tunnels. The configured interface name must fit Linux's interface
name rules and be unique among configured sessions.

| Option | Meaning |
|---|---|
| `interface_hwaddr = "02:00:5e:00:53:01"` | Fixed unicast Ethernet address |
| `cookie = "0011223344556677"` | Cookie sent in each frame: 8 or 16 hexadecimal digits |
| `peer_cookie = "8899aabb"` | Cookie required on incoming frames; defaults to `cookie` |

Cookies identify frames; they do not encrypt or authenticate traffic.
Choose the transport network and any external protection accordingly.

A differing hardware address waits while the interface is UP.
The daemon preserves its addresses, children and administrative state.
Another network manager's changes to an already applied value are respected
until the configured value changes.

### IPv6-only host setting

```toml
[host]
fix_bindv6only = true
```

This default permits a namespace-local correction of `net.ipv6.bindv6only`
when dual-stack tunnel creation needs it. Existing sockets keep their
original setting. A refused correction is reported and supported family
fallbacks are used. The supplied systemd unit permits this specific write.

## Validate before applying

```sh
rs-l2tpd --check
```

The command prints the merged configuration in a fixed order and every
problem. It exits 0 only without problems and 1 with any problem.
It prints cookie values, so treat its output as configuration data.

At startup, valid entries can run while invalid ones are left out.
A reload keeps the last accepted state where validation requires it.
Renaming a configuration entry without changing its kernel identity
preserves the existing tunnel or session. Consult the
[configuration contract](spec/configuration.md) for exact rejection and
retention rules.

## Start and observe

With the supplied systemd unit:

```sh
systemctl start rs-l2tpd.service
systemctl status rs-l2tpd.service --no-pager
journalctl -u rs-l2tpd.service --no-pager -n 100
```

For a foreground process supervised by another manager:

```sh
rs-l2tpd --foreground --config /etc/rs-l2tpd.toml
```

With no mode argument, the daemon double-forks, writes its PID file and
returns to the caller when eligible tunnel/session objects exist.
Readiness does not promise peer connectivity, a usable source address or
publication under the final interface name. The daemon can therefore start
before the network it helps provide.

Foreground mode does not fork, write a PID file or report parent readiness.
Logs go to standard error as `LEVEL target: message`; `--verbose` adds debug
messages. Lasting conditions normally log once on entry and once on recovery.
A deferred hardware-address change is reported on reconciliation.

## Reload, restart and stop

| Action | Effect |
|---|---|
| `SIGHUP` | Reload configuration; repeated requests can coalesce |
| `SIGUSR2` | Re-execute the binary on disk, preserving tunnels and interfaces |
| `SIGTERM` or `SIGINT` | Remove owned sessions and tunnels, then exit |
| `systemctl restart rs-l2tpd` | Stop and start, re-creating owned objects |

Reload the supplied service after checking your edits:

```sh
systemctl kill --kill-whom=main --signal=HUP rs-l2tpd.service
```

To use an upgraded binary while preserving objects:

```sh
rs-l2tpd --restart --pid-file /run/rs-l2tpd/rs-l2tpd.pid
```

The supplied unit uses that PID path; standalone daemonized starts default
to `/run/rs-l2tpd.pid`. The restart command validates the file's ownership,
type, permissions and PID before sending a signal. Match any custom
`--pid-file` setting.

With systemd's descriptor store, a crash can leave tunnel sockets available
for the next instance to adopt. An explicit stop removes the owned objects.
The unit runs as root with `CAP_NET_ADMIN`, `CAP_NET_RAW` and
`CAP_NET_BIND_SERVICE`, a filesystem sandbox and a dedicated runtime directory.

## Troubleshooting

| Symptom | Check |
|---|---|
| A tunnel exists but is disconnected | Peer family, bind/zone interface, local addresses, routes and DNS |
| A session keeps a temporary name | A foreign device holds the requested name, or the kernel refuses an active-device rename |
| A hardware-address change is pending | The interface is UP; arrange a maintenance window if the configured change is required |
| DHCPv6 discovery fails | Bind interface and permission to bind UDP port 546 |
| RA discovery fails without raw-socket capability | Interface `accept_ra` and kernel user-option delivery |
| Startup reports unsupported L2TP operations | Host modules and container capabilities |
| A networkd name rule does not apply in a container | udev availability and the networkd limitation in [kernel support](kernel-support.md#operating-limits) |

The daemon leaves foreign kernel objects alone. Identifiers held elsewhere
are retried within bounded readiness handling; permanent ownership conflicts
need administrator action. A timed-out mutation can have succeeded in the
kernel, so the daemon verifies state before retrying.

## Command line

```text
rs-l2tpd [--config FILE] [--config-dir DIR] [--pid-file FILE] [--verbose]
         [--check | --foreground | --restart | --adopt-version | --version]
```

`--adopt-version` prints `rs-l2tpd-adopt 1`. `--version` prints the crate
version. Standalone binaries built with `setup-systemd` also accept
`--setup-systemd [--prefix DIR]`; see [installation](installation.md#standalone-binary-and-systemd-installer).
Packages exclude this installer mode.

Path arguments accept native nonempty byte strings, including values that
begin with `--`. Compatibility spellings are `-v`, `-c` and
`-p FILE`/`--pidfile FILE`.

Invalid command lines exit 2. A complete shutdown exits 0; a failed shutdown
exits 1. A reload callback panic exits 2. Configuration-check and restart
delivery failures exit 1.
