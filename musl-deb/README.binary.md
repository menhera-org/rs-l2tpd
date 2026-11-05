# rs-l2tpd binaries

Installation and operation:
https://menhera-org.github.io/rs-l2tpd/installation.html
https://menhera-org.github.io/rs-l2tpd/operation.html

Supported kernels:
https://menhera-org.github.io/rs-l2tpd/kernel-support.html

DEB and RPM packages install /usr/sbin/rs-l2tpd, a systemd unit, example
configuration and these notices. Upgrades preserve edited configuration and
leave the running daemon in place. Restart explicitly as described in the guide.

DEB uses Debian service-policy helpers and /lib/systemd/system. RPM uses
/usr/lib/systemd/system, applies local systemd presets on first install and
starts an enabled service if systemd is running. Neither format restarts the
daemon on upgrade; administrator masks remain untouched.

DEB removal retains the main configuration; purge removes it. RPM uninstall
stops/disables the service, removes an unchanged main configuration and saves
an edited one as /etc/rs-l2tpd.toml.rpmsave. RPM upgrades keep local edits;
changed packaged defaults are supplied as .rpmnew. A later RPM reinstall
applies presets again. Both formats preserve operator configuration fragments.

A tarball contains the executable and the same license and notice files.
Place the executable on PATH and follow the installation guide.

Source: https://github.com/menhera-org/rs-l2tpd

The project is available under LICENSE-APACHE or LICENSE-MPL.
THIRD-PARTY-NOTICES.txt covers the locked Rust dependencies.
RUST-COPYRIGHT.html.gz and RUST-LICENSES.txt contain the pinned Rust toolchain's
notices, including compiler/runtime components. MUSL-COPYRIGHT covers musl.
These notices also include build-time or unused code; inclusion does not
mean every listed component is linked into this executable.
