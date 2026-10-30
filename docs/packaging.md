# Installation paths

[Documentation index](README.md)

The optional `--setup-systemd` installer is implemented. The `musl-deb`
package builder below is a Phase 7 design; its directory and CI packaging
checks do not exist yet. These paths have a bounded scope for hosts where
no distribution package is available.

## `--setup-systemd` (feature `setup-systemd`)

A mode of the binary, present only when it was built with the
`setup-systemd` feature (which implies `bin`). It installs *this* binary
and the supplied unit on a systemd host, from the command line, as root.

```
rs-l2tpd --setup-systemd [--prefix DIR]
```

What it does, in order, and all it does:

| Step | Action | Rule |
|---|---|---|
| 1 | Refuses unless running as root (or `--prefix` is given, for tests) | exit 1 |
| 2 | Resolves the executable from its invocation path without procfs and copies it to `<prefix>/usr/local/sbin/rs-l2tpd`: written to a temporary name in the same directory, `fsync`ed, then `rename`d over the old file, so that the path always holds a complete binary and a daemon running from the old one keeps its inode | atomic |
| 3 | Renders the embedded `contrib/rs-l2tpd.service.in` with `ExecStart=/usr/local/sbin/rs-l2tpd` and installs it at `<prefix>/usr/local/lib/systemd/system/rs-l2tpd.service` the same way: the directory systemd.unit(5) reserves for units the administrator *installed*, next to the binary under `/usr/local`, and where 0.1.5's `--setup` wrote its unit, so an unedited 0.1.5 unit is replaced in place. `/etc/systemd/system` is for units the administrator *created* and shadows ours by precedence: a unit of the same name there, or a `systemctl edit --full` copy, wins and is left alone; drop-ins under `/etc/systemd/system/rs-l2tpd.service.d/` keep working. A unit at the install path that differs byte-for-byte from every shipped installer unit embedded with this release is left alone and reported, because the operator changed it | never overwrites an edit |
| 4 | Creates `<prefix>/etc/rs-l2tpd.toml.d/` and, when no main file exists, `<prefix>/etc/rs-l2tpd.toml` containing the commented example of [interface](interface.md#configuration-files); an existing main file is never touched | never overwrites configuration |
| 5 | Runs `systemctl daemon-reload`; on a first installation (the unit was not enabled before) runs `systemctl enable --now rs-l2tpd`; on a re-run it does **not** restart or reload the service, and prints how to | the operator restarts: `rs-l2tpd --restart --pid-file /run/rs-l2tpd/rs-l2tpd.pid` keeps the tunnels (P26), `systemctl restart` re-creates them. A daemon still running 0.1.5 re-execs its own path, `/usr/local/bin/rs-l2tpd`, which the installer leaves in place, so that one upgrade needs `systemctl restart`; the installer says so |
| 6 | Prints each step's outcome on standard output; any failure exits 1 after the steps that did not depend on it | idempotent: a second run changes nothing |

Out of scope, on purpose: users and groups, sysctls, firewall rules,
log configuration, removal (the operator runs `systemctl disable --now`
and deletes the three paths), any other init system, any path outside
the three above. The daemon never depends on this mode (P23); it is an
installer, not part of the process contract.

Tests: with `--prefix` pointing at a temporary directory the mode
performs steps 2 to 4 and skips `systemctl`; the tests check the atomic
replacement (a reader holding the old file still reads it), the
untouched edited unit, the untouched main file, and idempotence. Embed
prior shipped installer unit texts alongside the current template so an
unedited old unit upgrades; unknown variants are preserved and reported.
Test an old unedited unit, an edited old unit and an unknown unit.

The installer renders the unit with `/usr/local/sbin/rs-l2tpd`. Unit tests
also render the planned package path, `/usr/sbin/rs-l2tpd`; this does not
mean the package builder exists. Both installation paths are designed to
share the same template. The installer unit in `/usr/local/lib` overrides
the package unit in `/usr/lib` (`/lib`); installing a package does not
silently switch an existing installer service to the other binary.

The template passes `--pid-file /run/rs-l2tpd/rs-l2tpd.pid` so its
dedicated runtime directory is the only writable PID location under
`ProtectSystem=strict`. To restart that service in place, use
`rs-l2tpd --restart --pid-file /run/rs-l2tpd/rs-l2tpd.pid` or send
`SIGUSR2` to its main process. Starts without the unit keep the built-in
PID-file default.

## `musl-deb`: a minimal Debian package

Planned for [Phase 7](plan.md#phase-7--release), not implemented in the
current tree. The layout, commands and CI checks below describe that design.

A directory `musl-deb/` will build `.deb` files from the
static musl binaries, for `amd64` and `arm64`, with **our own code
only**: no `debhelper`, no `dpkg-deb`, no `debian/` directory, no Debian
tool at all, so that the packages can be built on any host that builds
the daemon. The binary is static, so the package declares no
`Depends:`, only `Recommends: systemd`, and no distribution version. It
is for Debian-family hosts where the project has no distribution
package yet; it does not follow Debian policy beyond what `dpkg` needs
to install it, and it is not meant for a distribution's archive.

`musl-deb/` is a small Rust crate of its own (not a member of the
daemon's workspace, so that the daemon's lock file stays its own), with
no dependencies: a `.deb` is an `ar` archive holding `debian-binary`,
`control.tar` and `data.tar`, and `dpkg` accepts both tars uncompressed
(`control.tar` since dpkg 1.17.6, `data.tar` since 1.10.24), so the tool
writes the `ar` and `ustar` formats itself from `std` and compresses
nothing. The maintainer scripts are POSIX `sh`.

```
musl-deb/
  Cargo.toml        package musl-deb, no dependencies, edition 2024
  src/main.rs       reads the version from ../Cargo.toml, runs ../build-release.sh unless --no-build,
                    stages the tree below with root ownership and the right modes, writes
                    control.tar and data.tar (ustar) and the ar archive; --list prints a package's contents
  control.in        Package, Version, Architecture, Section net, Priority optional, Recommends systemd, Description
  conffiles         /etc/rs-l2tpd.toml
  postinst          sh: systemctl daemon-reload; on first install `systemctl enable --now`; on upgrade nothing else
  prerm             sh: on remove `systemctl disable --now`; on upgrade nothing
  postrm            sh: on purge, remove /etc/rs-l2tpd.toml.d; daemon-reload
```

Contents of a package:

| Path | From |
|---|---|
| `/usr/sbin/rs-l2tpd` | the musl binary for the architecture (`--features bin`, without `setup-systemd`, since the package is the installer) |
| `/lib/systemd/system/rs-l2tpd.service` | `contrib/rs-l2tpd.service.in` rendered with `ExecStart=/usr/sbin/rs-l2tpd` |
| `/etc/rs-l2tpd.toml` | the commented example, a conffile: `dpkg` keeps the operator's version on upgrade |
| `/etc/rs-l2tpd.toml.d/` | empty directory |
| `/usr/share/doc/rs-l2tpd/` | `README.md`, `LICENSE-APACHE`, `LICENSE-MPL`, this page |

Rules the maintainer scripts keep:

- **Atomic replacement.** `dpkg` unpacks a new file beside the old one
  and `rename`s it into place, so `/usr/sbin/rs-l2tpd` always holds a
  complete binary and a running daemon keeps its old inode. The scripts
  add nothing to that.
- **No restart on upgrade.** `postinst` never restarts the service; the
  tunnels and interfaces of the running daemon stay up. The operator
  chooses `rs-l2tpd --restart --pid-file /run/rs-l2tpd/rs-l2tpd.pid`
  (same process, tunnels kept, P26) or `systemctl restart rs-l2tpd`. The
  scripts print one line saying so.
- **Enabled and started once.** On a first installation `postinst` runs
  `systemctl enable --now rs-l2tpd`; on a host without systemd it prints
  that the process contract (P22) applies and does nothing.
- **Removal is clean.** `prerm` on `remove` stops and disables the unit;
  `postrm` on `purge` removes the drop-in directory; the conffile is
  `dpkg`'s to remove.
- **Version from one place.** The tool reads the version from the
  daemon's `Cargo.toml`, so the package version is the crate version,
  with a `-1` Debian revision.
- **Owner and modes are written, not inherited.** Every entry of
  `data.tar` is `root:root` (uid and gid 0 in the header), directories
  `0755`, the binary `0755`, the unit and the example `0644`, the
  maintainer scripts `0755`, whatever the building user is.

Planned commands, available after the tool is implemented:

```sh
cargo run --manifest-path musl-deb/Cargo.toml --                        # both architectures
cargo run --manifest-path musl-deb/Cargo.toml -- --target x86_64-unknown-linux-musl
cargo run --manifest-path musl-deb/Cargo.toml -- --list rs-l2tpd_0.2.0-1_amd64.deb
```

The host needs `cross`, as `build-release.sh` does, and nothing else.
The result is `rs-l2tpd_<version>-1_<arch>.deb` in the repository root,
next to the tarballs. Phase 7 will add CI to build the `amd64` package and
check, with the tool's own `--list` and its unit tests of the two writers
(a fixed tree
produces a byte-identical archive), that the control file, the
conffile, the three maintainer scripts and the five installed paths are
present. Installing the result with `dpkg -i` inside a
`debian:stable-slim` container is a scenario of the test suite, a check
of the output against the consumer, not a step of the build.
