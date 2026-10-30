#!/bin/sh
# Builds the rs-l2tpd daemon for release and packs one tarball per target.
#
# The package is a library plus the `rs-l2tpd` binary target, which needs
# the `bin` feature; `setup-systemd` (the --setup-systemd installer) implies it. Pass extra
# cargo features in FEATURES, the targets to build in TARGETS, and any
# further cargo arguments on the command line.

set -eu

cd "$(dirname "$0")"

BIN=rs-l2tpd
FEATURES=${FEATURES:-setup-systemd}
TARGETS=${TARGETS:-"x86_64-unknown-linux-musl aarch64-unknown-linux-musl"}

# The first `version =` line is the [package] version (rust-version does
# not match because of the anchored key).
ver=$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -n1)
if [ -z "$ver" ]; then
    echo "could not read the package version from Cargo.toml" >&2
    exit 1
fi

dir=$(pwd)

# Every target gets a target directory of its own. The build scripts and
# proc macros in `<target dir>/release/build` are host binaries that cargo
# reuses across targets; each cross image has a different glibc (and this
# machine a newer one still), so a build script compiled for one of them
# fails to load in another.
cross_target_dir=${CROSS_TARGET_DIR:-"$dir/target/cross"}

for target in $TARGETS; do
    CARGO_TARGET_DIR="$cross_target_dir/$target"
    export CARGO_TARGET_DIR

    cross build --release --locked \
        --target="$target" \
        --bin "$BIN" \
        --features "$FEATURES" "$@"

    out="$dir/$BIN-$ver-$target.tar.gz"
    (
        cd "$CARGO_TARGET_DIR/$target/release"
        tar caf "$out" "$BIN"
    )
    echo "built $out"
done
