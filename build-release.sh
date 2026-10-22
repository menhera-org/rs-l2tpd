#!/bin/sh
# Builds the rs-l2tpd daemon for release and packs one tarball per target.
#
# The package is a library plus the `rs-l2tpd` binary target, which needs
# the `bin` feature; `setup` (the --setup installer) implies it. Pass extra
# cargo features in FEATURES, and the targets to build in TARGETS.

set -eu

cd "$(dirname "$0")"

BIN=rs-l2tpd
FEATURES=${FEATURES:-setup}
TARGETS=${TARGETS:-"x86_64-unknown-linux-musl aarch64-unknown-linux-musl"}

# The first `version =` line is the [package] version (rust-version does
# not match because of the anchored key).
ver=$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -n1)
if [ -z "$ver" ]; then
    echo "could not read the package version from Cargo.toml" >&2
    exit 1
fi

dir=$(pwd)

for target in $TARGETS; do
    cross build --release --locked \
        --target="$target" \
        --bin "$BIN" \
        --features "$FEATURES"

    out="$dir/$BIN-$ver-$target.tar.gz"
    (
        cd "target/$target/release"
        tar caf "$out" "$BIN"
    )
    echo "built $out"
done
