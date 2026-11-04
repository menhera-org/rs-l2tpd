# Dependencies

The daemon is licensed under Apache-2.0 or MPL-2.0. Both license texts ship
with the source and packages. Cargo.lock records the exact Rust dependency
versions; the current all-feature graph contains 65 external packages.

The musl release binaries are static. They need Linux kernel facilities,
rather than a host Rust installation or a matching glibc version.

| Component | Purpose |
|---|---|
| `l2tp` 0.5 | Tunnel sockets, checked identifiers and kernel-message decoding |
| `iphost` 0.4.4 | DNS, Router Advertisement and DHCPv6 protocols |
| `netlink-sys` and `netlink-packet-*` | Linux requests and event decoding |
| `socket2`, `nix` and `libc` | Socket, descriptor and process interfaces |
| `tokio` | Runtime, timers and bounded channels |
| `log` | Logging interface |
| `getrandom` | Kernel-backed random temporary names |
| `serde` and `toml` | Configuration parsing; serialization is optional for library users |

The optional `setup-systemd` installer embeds the unit and invokes
`systemctl`; it adds no Rust dependency. Debian packages exclude that
feature because package installation supplies the unit and configuration.


The [developer guide](developer.md#build-tools) lists build and verification
tools. Those tools are not daemon runtime dependencies.
