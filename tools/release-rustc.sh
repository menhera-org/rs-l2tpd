#!/bin/sh
# Cross preserves host mount paths. Keep path mappings out of Cargo's flag hash.
set -eu
: "${RELEASE_SOURCE_ROOT:?release source root is required}"
sysroot=${CROSS_RUST_SYSROOT:-}
if [ -z "$sysroot" ]; then sysroot=$("$1" --print sysroot); fi
exec "$@" \
    "--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/usr/src/cargo" \
    "--remap-path-prefix=$sysroot=/usr/src/rust" \
    "--remap-path-prefix=$RELEASE_SOURCE_ROOT=/usr/src/rs-l2tpd"
