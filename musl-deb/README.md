# musl-deb

Build static Debian packages without Debian build tools. Run from a checkout:

```sh
cargo run --locked --manifest-path musl-deb/Cargo.toml
cargo run --locked --manifest-path musl-deb/Cargo.toml -- --target x86_64-unknown-linux-musl
cargo run --locked --manifest-path musl-deb/Cargo.toml -- --list rs-l2tpd_0.2.0-1_amd64.deb
```

The default builds amd64 and arm64 through `build-release.sh` and requires
`cross` and Docker. It always builds with `--no-default-features --features bin`
in separate target directories. Cargo fetches the locked sources on the host;
Docker builds use `--network none` and Cargo's offline mode. The builder checks
the ELF architecture and rejects an interpreter or shared-library dependency.

The dependency-free tool writes uncompressed ar/ustar archives with root
ownership, fixed modes and zero timestamps. `--list` validates only this
uncompressed package format; it never extracts files or executes scripts.
See [deb(5)](https://manpages.debian.org/trixie/dpkg-dev/deb.5.en.html)
for the consumer format, [installation](../docs/installation.md) for operator
behavior, and the [developer guide](../docs/developer.md#build-debian-packages)
for verification scope.

The common gates run native/musl unit tests and ShellCheck on all maintainer
scripts. `test-package.sh` runs only in a disposable Debian container, with
`MUSL_DEB_TEST_CONTAINER=1`. The Packages workflow supplies the networkless
container, verifies real dpkg install/upgrade/remove/purge behavior and records
systemctl actions with a stub. The real Debian helpers test startup/stop policy
denial and preserve administrator-disabled/masked units. It does not test
Debian's actual service manager.

Release inputs are pinned in `release-config.sh`. Binaries stay stripped;
locked sources are vendored and archive metadata is normalized. The [reproducibility check](../docs/developer.md#reproducible-releases)
compares clean builds in different paths, with different mtimes and umasks,
for both architectures and both installer feature variants.
