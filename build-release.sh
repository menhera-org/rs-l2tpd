#!/bin/sh
# Build stripped musl binaries and reproducible release tarballs.
set -eu
cd "$(dirname "$0")"
# shellcheck source=release-config.sh
. ./release-config.sh

BIN=rs-l2tpd
FEATURES=${FEATURES:-setup-systemd}
TARGETS=${TARGETS:-"x86_64-unknown-linux-musl aarch64-unknown-linux-musl"}
ver=$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -n1)
test -n "$ver"
test "$(cross --version | awk '{print $2}')" = "$RELEASE_CROSS" || {
    echo "release builds require cross $RELEASE_CROSS" >&2
    exit 1
}
if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
    echo 'release builds accept RUSTFLAGS, not CARGO_ENCODED_RUSTFLAGS' >&2
    exit 1
fi

# Cross mounts these paths consistently, so Cargo's flag hashes also stay fixed.
release_rustflags="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=/project=/usr/src/rs-l2tpd --remap-path-prefix=/cargo=/usr/src/cargo --remap-path-prefix=/rust=/usr/src/rust -C link-arg=-Wl,--build-id=none"
SOURCE_DATE_EPOCH=0
CARGO_INCREMENTAL=0
CARGO_PROFILE_RELEASE_STRIP=symbols
CROSS_CONTAINER_ENGINE=docker
CROSS_CONTAINER_OPTS='--network none --platform linux/amd64'
CROSS_TARGET_X86_64_UNKNOWN_LINUX_MUSL_IMAGE=$RELEASE_X86_IMAGE
CROSS_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_IMAGE=$RELEASE_ARM_IMAGE
CROSS_BUILD_ENV_PASSTHROUGH="${CROSS_BUILD_ENV_PASSTHROUGH:+$CROSS_BUILD_ENV_PASSTHROUGH }SOURCE_DATE_EPOCH TZ LC_ALL CONFIG_FILE_PATH CONFIG_DIR_PATH PID_FILE_PATH"
TZ=UTC
LC_ALL=C
export SOURCE_DATE_EPOCH CARGO_INCREMENTAL CARGO_PROFILE_RELEASE_STRIP
export CROSS_CONTAINER_ENGINE CROSS_CONTAINER_OPTS
export CROSS_TARGET_X86_64_UNKNOWN_LINUX_MUSL_IMAGE CROSS_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_IMAGE
export CROSS_BUILD_ENV_PASSTHROUGH TZ LC_ALL

dir=$(pwd -P)
cross_target_dir=${CROSS_TARGET_DIR:-"$dir/target/cross"}
temporary=$(mktemp -d "${TMPDIR:-/tmp}/rs-l2tpd-release.XXXXXXXX")
trap 'rm -rf "$temporary"' 0
trap 'exit 1' HUP INT TERM
umask 022
cargo "+$RELEASE_TOOLCHAIN" fetch --locked

for target in $TARGETS; do
    case $target in
        x86_64-unknown-linux-musl) image=$RELEASE_X86_IMAGE ;;
        aarch64-unknown-linux-musl) image=$RELEASE_ARM_IMAGE ;;
        *) echo "unsupported release target: $target" >&2; exit 2 ;;
    esac
    # Keep host build scripts separate for the two cross-image environments.
    CARGO_TARGET_DIR="$cross_target_dir/$target"
    export CARGO_TARGET_DIR
    RUSTFLAGS="$release_rustflags" cross "+$RELEASE_TOOLCHAIN" build --release --locked --offline \
        --target="$target" --bin "$BIN" --features "$FEATURES" "$@"

    out="$dir/$BIN-$ver-$target.tar.gz"
    cargo "+$RELEASE_TOOLCHAIN" run --locked --manifest-path musl-deb/Cargo.toml \
        -- --tar "$CARGO_TARGET_DIR/$target/release/$BIN" "$temporary/binary.tar"
    # Compression uses the pinned image as well as a timestamp-free gzip header.
    docker run --rm --network none --platform linux/amd64 -i --entrypoint gzip "$image" -n -9 -c \
        < "$temporary/binary.tar" > "$temporary/binary.tar.gz"
    cp "$temporary/binary.tar.gz" "$out"
    echo "built $out"
done
