# musl-deb

Build static DEB and RPM packages without distribution build tools:

```sh
cargo run --locked --manifest-path musl-deb/Cargo.toml
cargo run --locked --manifest-path musl-deb/Cargo.toml -- --target x86_64-unknown-linux-musl
cargo run --locked --manifest-path musl-deb/Cargo.toml -- --list rs-l2tpd_0.2.0-1_amd64.deb
cargo run --locked --manifest-path musl-deb/Cargo.toml -- --list rs-l2tpd-0.2.0-1.x86_64.rpm
```

The default builds both formats for x86_64 (DEB amd64) and aarch64 (DEB arm64)
through `build-release.sh`, using pinned `cross` and Docker. `--target` selects
one architecture for both formats. Each binary is built with
`--no-default-features --features bin` in a separate target directory. Cargo
fetches locked sources on the host; Docker builds use `--network none` and
Cargo's offline mode. ELF validation rejects the wrong architecture,
an interpreter or a shared-library dependency.

The DEB writer uses uncompressed ar/ustar. RPM v4 uses the pinned pure-Rust
`rpm` crate with an uncompressed cpio payload; signing and compression
backends are disabled. Both formats use root ownership, fixed modes and zero
timestamps. `--list` validates DEB structure or RPM digests and lists paths;
it never extracts files or executes scripts.

See [installation](../docs/installation.md) for service/configuration behavior
and the [developer guide](../docs/developer.md#build-deb-and-rpm-packages)
for verification scope. RPM uses `/usr/lib/systemd/system`, systemd presets,
`%config(noreplace)` and stop/disable on erase. DEB keeps its Debian helper
policy and remove/purge distinction. Neither restarts the daemon on upgrade.

The common gates run native/musl unit tests and POSIX ShellCheck on all
maintainer scripts. `test-package.sh` uses real Debian 13 dpkg and service
helpers. `test-rpm.sh` uses real RPM install/upgrade/erase transactions on
Rocky Linux 9 and 10, including changed defaults, masks, presets, fragments,
notice installation with `--excludedocs`, and command failures. Both
consumers use a systemctl stub and require a disposable networkless container
with `MUSL_DEB_TEST_CONTAINER=1`. They do not qualify real distribution service
managers or SELinux policy.

Generate the test-only RPM upgrade, then run the consumer:

```sh
cargo run --locked --manifest-path musl-deb/Cargo.toml --example rpm-upgrade -- \
  rs-l2tpd-0.2.0-1.x86_64.rpm target/rpm-upgrade.rpm
docker run --rm --network none \
  --mount "type=bind,source=$PWD,target=/repo,readonly" \
  --env MUSL_DEB_TEST_CONTAINER=1 --entrypoint sh rockylinux/rockylinux:9 \
  /repo/musl-deb/test-rpm.sh /repo/rs-l2tpd-0.2.0-1.x86_64.rpm /repo/target/rpm-upgrade.rpm
```

The fixture changes the release field and packaged defaults while retaining
the real executable and lifecycle scripts. It is never a release artifact.

Release inputs are pinned in `release-config.sh`. Binaries stay stripped;
locked sources are vendored and archive metadata is normalized. The
[reproducibility check](../docs/developer.md#reproducible-releases) compares
independent clean builds under different paths, mtimes and umasks for both
architectures, both installer feature variants, tarballs, DEBs and RPMs.
