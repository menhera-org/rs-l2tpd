# rs-l2tpd binaries

Installation and operation:
https://menhera-org.github.io/rs-l2tpd/installation.html
https://menhera-org.github.io/rs-l2tpd/operation.html

Supported kernels:
https://menhera-org.github.io/rs-l2tpd/kernel-support.html

The Debian package installs /usr/sbin/rs-l2tpd, its systemd unit and example
configuration. Package upgrades preserve configuration and leave a running
daemon in place. Follow the installation guide for an explicit restart.

A tarball contains the executable and the same license and notice files.
Place the executable on PATH and follow the installation guide.

Source: https://github.com/menhera-org/rs-l2tpd

The project is available under LICENSE-APACHE or LICENSE-MPL.
THIRD-PARTY-NOTICES.txt covers the locked Rust dependencies.
RUST-COPYRIGHT.html.gz and RUST-LICENSES.txt contain the pinned Rust toolchain's
notices, including compiler/runtime components. MUSL-COPYRIGHT covers musl.
These notices also include build-time or unused code; inclusion does not
mean every listed component is linked into this executable.
