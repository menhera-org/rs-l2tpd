# Installation

Packages and tarballs for each version are on the
[releases page](https://github.com/menhera-org/rs-l2tpd/releases).
See [kernel support](kernel-support.md) before deploying to a host or
system container. The
[release readiness review](https://github.com/menhera-org/rs-l2tpd/blob/main/audit/RELEASE_READINESS.md)
records the qualification of the packaging and build inputs.

## Debian packages

The `musl-deb/` builder produces stripped static packages for `amd64` and `arm64`.
Packages contain the daemon, a systemd unit, a commented configuration
example and license notices. They depend on Debian's `init-system-helpers`
for policy-aware service management and recommend systemd; the executable
has no shared-library dependency. The packaged daemon excludes `setup-systemd`.

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
| `/usr/share/doc/rs-l2tpd/` | README with published guide links, project licenses and third-party/runtime notices |

On first installation, Debian's helper enables the service according to local
service policy. If systemd is running, the package reloads its unit definitions
and asks `deb-systemd-invoke` to start the service. A `policy-rc.d` denial
prevents startup. Administrator masks and enable/disable state are preserved
on reinstall and upgrade. Without systemd, manage the service through your
chosen service manager; see the [process interface](operation.md#command-line).

## RPM packages

The same builder also produces stripped static RPMs for `x86_64` and `aarch64`.
Install the matching architecture as root, for example:

```sh
dnf install ./rs-l2tpd-0.2.0-1.x86_64.rpm
rs-l2tpd --check
systemctl status rs-l2tpd.service --no-pager
```

The RPM contains the same daemon, configuration, fragments directory and
notice files as DEB. Its unit is at
`/usr/lib/systemd/system/rs-l2tpd.service`. It requires `/bin/sh`, recommends
systemd and has no shared-library dependency. The packaged daemon excludes
`setup-systemd`. These are project artifacts, not distribution archive packages.

On first install, RPM applies the local systemd preset policy, preserving
administrator masks. If systemd is running, it reloads unit definitions and
starts the service only when enabled. There is no Debian `policy-rc.d`
integration. Without systemd running, it applies presets without starting a
daemon; without `systemctl`, it prints a service-manager reminder.

An upgrade preserves enable/disable state and masks, reloads unit definitions
when systemd is running and leaves the running daemon untouched. The main
configuration uses RPM's `%config(noreplace)`: edited content stays in place;
when packaged defaults change, the new defaults are written as `.rpmnew`.
Review that file before incorporating new settings. Configuration fragments
and administrator-owned systemd overrides remain untouched.

## Upgrading

An upgrade installs the new binary and reloads systemd's unit definitions.
It does not restart or reload the daemon. The running process retains its
old executable inode until the operator chooses a restart.

To switch to the new binary while keeping the tunnels and interface indexes:

```sh
rs-l2tpd --restart --pid-file /run/rs-l2tpd/rs-l2tpd.pid
```

A regular `systemctl restart rs-l2tpd` tears down and re-creates owned objects.
Both formats preserve edited configuration: dpkg uses conffiles and RPM uses
`%config(noreplace)`.
Keep service customizations in `/etc/systemd/system/rs-l2tpd.service.d/`
or an administrator-owned unit.

## Removing a package

### Debian

```sh
dpkg --remove rs-l2tpd
dpkg --purge rs-l2tpd
```

Removal asks Debian's policy-aware helper to stop the service and leaves its
conffile. A helper-owned mask prevents activation while the unit is absent;
reinstallation removes that mask. Administrator masks remain untouched.
Purge lets dpkg remove the main conffile and removes the fragment directory
only if it is empty. Operator-created fragments are preserved.

### RPM

```sh
dnf remove rs-l2tpd
```

RPM uninstall stops the service when systemd is running and disables it.
It removes an unchanged main configuration; an edited main configuration is
saved as `/etc/rs-l2tpd.toml.rpmsave`. There is no separate RPM purge operation.
Operator-created fragments are preserved; an empty fragment directory is
removed. Administrator masks remain untouched. A later reinstall applies
local systemd presets again rather than remembering prior enablement.

Failed service commands are reported as scriptlet failures. RPM can report a
post-install or post-uninstall failure after it has already changed package
state; inspect the transaction output and service state before retrying.

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
in `/lib` or `/usr/lib`; an administrator unit in `/etc` takes precedence over both.
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
