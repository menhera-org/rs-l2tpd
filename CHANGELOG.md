# Changelog

This file lists user-visible changes. Entries start at 0.2.0.

## 0.2.0 - 2026-11-05

A rewrite of the daemon against a written [specification](docs/spec/README.md),
split into the `rs_l2tpd` library and the `rs-l2tpd` binary. A 0.1.5
configuration keeps working, 0.1.5 peers interoperate, and the process
contract (double fork, readiness on parent exit, PID file, `SIGHUP`) is kept.

### Upgrading from 0.1.5

- A running 0.1.5 daemon needs one regular `systemctl restart rs-l2tpd`.
  Later upgrades can use `rs-l2tpd --restart`, which keeps tunnels and
  interface indexes.
- The standalone installer is now `--setup-systemd` (feature
  `setup-systemd`, formerly `--setup` and `setup`). It installs the binary
  at `/usr/local/sbin/rs-l2tpd` instead of `/usr/local/bin/rs-l2tpd`,
  replaces the unmodified 0.1.5 unit and keeps an edited one.
- The supplied unit uses `/run/rs-l2tpd/rs-l2tpd.pid`. A standalone
  daemonized start still defaults to `/run/rs-l2tpd.pid`.
- The compatibility spellings `-v`, `-c` and `-p FILE`/`--pidfile FILE`
  are accepted; the documented forms are `--verbose`, `--check` and
  `--pid-file FILE`.
- Debian 12 is outside support: its 6.1 kernel refuses to rename or
  change the address of an UP device, so such changes stay pending there.

### Added

- Configured resolvers: a `[resolvers.NAME]` table with fixed DNS
  `addresses` or discovery by `method = "ra"`, `"dhcpv6"` or `"ipv6"`
  on a bind interface, with `dhcpv6_identity` or `dhcpv6_duid`; a tunnel
  selects one with `resolver_name`. The system resolver remains the
  default.
- Session options `interface_hwaddr`, `cookie` and `peer_cookie`.
  Cookies are off unless configured, so the wire format is unchanged.
- `[host] fix_bindv6only` (default on): a namespace-local correction of
  `net.ipv6.bindv6only` when dual-stack tunnel creation needs it.
- Link-local peers with a zone (`fe80::1%eth0`). `ip_version` is
  optional for a literal address and still required for a host name.
- Command line: `--config FILE`, `--config-dir DIR`, `--foreground`,
  `--restart`, `--adopt-version` and `--version`.
- `SIGUSR2` re-executes the binary on disk in the same PID with its
  tunnel sockets, keeping tunnels and session interfaces.
- Under systemd, tunnel sockets survive a crash through the descriptor
  store and are adopted by the next instance.
- Graceful degradation: a mistaken entry is reported and left out while
  the others run; on reload an entry with a hard mistake keeps its last
  accepted values; unknown keys are reported. `--check` prints the merged
  configuration and exits 1 on any problem.
- The `rs_l2tpd` library: `service::Service` on Tokio, `blocking::Service`
  on a runtime of its own, and the program-driven `runtime::Runtime`.
  Features: `serde`, `bin` (default), `setup-systemd`, `fake-kernel`.
- Static DEB (amd64, arm64) and RPM (x86_64, aarch64) packages built by
  `musl-deb/`, and reproducible stripped musl tarballs, all with license
  notices.
- Documentation as an mdBook on GitHub Pages, with the specification.
- Qualified kernel matrix: Ubuntu 24.04 and 26.04 LTS kernels, their
  vanilla equivalents and mainline, plus Debian 13 and Rocky Linux 9/10;
  unprivileged Incus/LXD system containers; the supplied unit under root
  systemd.

### Changed

- A peer that cannot be reached yet leaves its tunnel disconnected on a
  bound, unconnected socket; the kernel drops its outbound frames. The
  discard address `100::`, the `rsl2tpnull0` dummy device and the route
  repair of 0.1.5 are gone, and the daemon never reads or installs
  routes.
- Readiness no longer waits for a route, a resolved peer or publication
  under the final interface name, so the daemon starts before the
  network it provides.
- Session interfaces are followed by identity, not name: address
  changes, late bind devices, VRF membership changes and replacements
  under the same name no longer re-create a working interface. A rename
  or hardware-address change that the kernel refuses while the device is
  UP is deferred and reported, never forced by lowering the device.
- A session is created under a temporary `rsl2tp-t…` name only when a
  foreign device holds its name or a fixed hardware address is required.
- Identifier conflicts, missing devices and transient kernel failures are
  retried without holding other entries up. A timed-out mutation is
  verified before it is retried.
- Tunnel sockets set the IPv4 path-MTU option so that frames larger than
  the underlay are fragmented rather than dropped.
- The supplied unit runs with exactly `CAP_NET_ADMIN`, `CAP_NET_RAW` and
  `CAP_NET_BIND_SERVICE`, a strict filesystem sandbox, a runtime
  directory and the descriptor store. A missing capability is reported
  once and the daemon degrades.
- Logs go to standard error as `LEVEL target: message`; cookies are
  never logged. Lasting conditions log once on entry and once on
  recovery.
- Exit codes: 2 for an invalid command line or a panicking reload
  callback, 1 for a failed shutdown, configuration check or restart
  delivery, 0 otherwise.
- Rust edition 2024 and a minimum Rust of 1.89. Dependencies: `l2tp`
  0.2.1 to 0.5, `iphost` 0.3.3 to 0.4.4; `clap`, `env_logger`,
  `async-trait`, `rtnetlink` and `futures-util` removed; `netlink-sys`,
  `netlink-packet-*`, `socket2`, `nix` and `getrandom` added; `tokio`
  reduced to `rt`, `sync`, `time` and `net`.

### Fixed

- One invalid entry no longer rejects the whole configuration at
  start-up.
- A failed kernel operation no longer aborts the rest of a reconcile.
- A `%` is no longer accepted in an interface name.
- Deleting a session whose name another entry takes over now converges.
- Configuration file names are byte strings; drop-ins need not be UTF-8,
  and names starting with `.` are ignored.
