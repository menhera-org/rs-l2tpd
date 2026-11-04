# Installation

Version 0.2.0 has not been published. Build artifacts from this checkout
until a release is available. See [kernel support](kernel-support.md)
before deploying to a host or system container.

## Debian packages

The `musl-deb/` builder produces stripped static packages for `amd64` and `arm64`.
Packages contain the daemon, a systemd unit, a commented configuration
example and the license texts. They have no shared-library dependency and
recommend systemd. The packaged daemon excludes `setup-systemd`.

Run installation commands as root on the target host:

```sh
dpkg -i ./rs-l2tpd_0.2.0-1_amd64.deb
rs-l2tpd --check
systemctl status rs-l2tpd.service --no-pager
```

Choose the `arm64` file on an aarch64 host. Debian 13 is the Debian kernel
target; Debian 12 remains outside support. These packages are project
artifacts, not packages accepted into a distribution archive.

| Installed path | Purpose |
|---|---|
| `/usr/sbin/rs-l2tpd` | Static daemon, mode 0755 |
| `/lib/systemd/system/rs-l2tpd.service` | Supplied service unit |
| `/etc/rs-l2tpd.toml` | Main configuration, managed as a dpkg conffile |
| `/etc/rs-l2tpd.toml.d/` | Configuration fragments |
| `/usr/share/doc/rs-l2tpd/` | README, installation guide and both licenses |

On the first installation, the package reloads systemd and enables/starts
the service if systemd is running. Without systemd it leaves service
management to the operator; use the [process interface](operation.md#command-line).

## Upgrading

An upgrade installs the new binary and reloads systemd's unit definitions.
It does not restart or reload the daemon. The running process retains its
old executable inode until the operator chooses a restart.

To switch to the new binary while keeping the tunnels and interface indexes:

```sh
rs-l2tpd --restart --pid-file /run/rs-l2tpd/rs-l2tpd.pid
```

A regular `systemctl restart rs-l2tpd` tears down and re-creates owned objects.
Dpkg preserves edited configuration through its conffile handling.
Keep service customizations in `/etc/systemd/system/rs-l2tpd.service.d/`
or an administrator-owned unit.

## Removing a package

```sh
dpkg --remove rs-l2tpd
dpkg --purge rs-l2tpd
```

Removal stops and disables the service and leaves its conffile.
Purge lets dpkg remove the main conffile and removes the fragment directory
only if it is empty. Operator-created fragments are preserved.

## Standalone binary and systemd installer

`build-release.sh` builds x86_64 and aarch64 musl tarballs with the optional
`setup-systemd` feature enabled. Extract the matching tarball and run its
binary as root:

```sh
./rs-l2tpd --setup-systemd
```

The installer atomically writes `/usr/local/sbin/rs-l2tpd` and
`/usr/local/lib/systemd/system/rs-l2tpd.service`, creates the configuration
directory, and installs the commented main file only if it is absent.
An open old binary remains intact during replacement.

The installer preserves edited or unknown units and existing configuration.
It enables/starts a newly installed service; a re-run leaves the running
daemon in place and prints the restart command. A service still running
0.1.5 needs a regular systemd restart for its first upgrade.

The installer unit in `/usr/local/lib` takes precedence over a package unit
in `/lib`; an administrator unit in `/etc` takes precedence over both.
Installing a package does not silently switch an existing installer service.

Remove a standalone installation by disabling/stopping its service and
removing its binary and unit. Configuration remains the operator's choice.
The installer does not create users, configure firewalls or change sysctls
as an installation step.

## Running without systemd

Use `rs-l2tpd --foreground` as the container entry point or the command
supervised by another init system. Configure the required host modules
and container capabilities first. See [operation](operation.md) for
signals, readiness, logging and host requirements.

The systemd unit uses `/run/rs-l2tpd/rs-l2tpd.pid`. Standalone daemonized
starts default to `/run/rs-l2tpd.pid`. Match the PID-file argument when
issuing an in-place restart.

Build and package commands, including reproducible release checks, are in
[the developer guide](developer.md#reproducible-releases).
