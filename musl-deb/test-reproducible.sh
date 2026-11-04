#!/bin/sh
# Compare independent clean builds, including stripped binaries and archive bytes.
set -eu
repo=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
cd "$repo"
[ "$#" = 1 ] || { echo 'usage: test-reproducible.sh RECORD' >&2; exit 2; }
record=$1
case $record in /*) ;; *) record=$repo/$record ;; esac
test ! -e "$record/result.log"
git --no-pager diff --quiet HEAD
mkdir -p "$record"
git --no-pager rev-parse HEAD > "$record/revision"
work=$(mktemp -d "${TMPDIR:-/tmp}/rs-l2tpd-repro.XXXXXXXX")
trap 'rm -rf "$work"' 0
trap 'exit 1' HUP INT TERM
git --no-pager archive HEAD > "$work/source.tar"
ver=$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -n1)
test -n "$ver"

prepare() {
    destination=$1
    timestamp=$2
    mkdir -p "$destination"
    tar -xf "$work/source.tar" -C "$destination"
    # Honor checkout-specific registry configuration without recording it.
    if [ -f .cargo/config.toml ]; then
        mkdir -p "$destination/.cargo"
        cp .cargo/config.toml "$destination/.cargo/config.toml"
    fi
    TZ=UTC find "$destination" -type f -exec touch -t "$timestamp" {} +
}
first=$work/source-a
second=$work/different-path-length/source-b
prepare "$first" 200101010000
prepare "$second" 202511010000

build() {
    destination=$1
    mask=$2
    (
        cd "$destination"
        umask "$mask"
        unset CARGO_TARGET_DIR RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
        FEATURES=setup-systemd TARGETS='x86_64-unknown-linux-musl aarch64-unknown-linux-musl' \
            CROSS_TARGET_DIR="$destination/target/musl-deb-build" ./build-release.sh
        mkdir -p target/repro-standalone
        for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
            cp "target/musl-deb-build/$target/$target/release/rs-l2tpd" "target/repro-standalone/$target"
            cp "rs-l2tpd-$ver-$target.tar.gz" "target/repro-standalone/$target.tar.gz"
        done
        cargo run --locked --manifest-path musl-deb/Cargo.toml
    )
}
build "$first" 077 > "$record/build-a.log" 2>&1 || { tail -n 30 "$record/build-a.log"; exit 1; }
build "$second" 022 > "$record/build-b.log" 2>&1 || { tail -n 30 "$record/build-b.log"; exit 1; }
: > "$record/comparisons.log"
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    for mode in standalone package; do
        case $mode in
            standalone) binary=target/repro-standalone/$target; archive=target/repro-standalone/$target.tar.gz ;;
            package) binary=target/musl-deb-build/$target/$target/release/rs-l2tpd; archive=rs-l2tpd-$ver-$target.tar.gz ;;
        esac
        cmp "$first/$binary" "$second/$binary"
        gzip -dc "$first/$archive" > "$work/extract.tar"
        mkdir -p "$work/extract-$mode-$target"
        tar -xf "$work/extract.tar" -C "$work/extract-$mode-$target"
        cmp "$first/$binary" "$work/extract-$mode-$target/rs-l2tpd"
        readelf --wide --sections "$first/$binary" > "$record/$mode-$target-sections.log"
        if grep -E '\.(debug|zdebug|symtab)([._[:space:]]|$)' "$record/$mode-$target-sections.log"; then
            echo "binary is not stripped: $mode $target" >&2
            exit 1
        fi
        if strings "$first/$binary" | grep -E '/(cargo|usr/src/cargo)/registry/src/'; then
            echo "binary embeds a registry-cache path: $mode $target" >&2
            exit 1
        fi
        printf 'mode=%s target=%s binary=identical stripped=yes registry_paths=absent\n' "$mode" "$target" >> "$record/comparisons.log"
    done
    cmp "$first/target/repro-standalone/$target.tar.gz" "$second/target/repro-standalone/$target.tar.gz"
    cmp "$first/rs-l2tpd-$ver-$target.tar.gz" "$second/rs-l2tpd-$ver-$target.tar.gz"
    printf 'target=%s standalone_tarball=identical package_tarball=identical\n' "$target" >> "$record/comparisons.log"
done
for arch in amd64 arm64; do
    cmp "$first/rs-l2tpd_$ver-1_$arch.deb" "$second/rs-l2tpd_$ver-1_$arch.deb"
    printf 'architecture=%s deb=identical\n' "$arch" >> "$record/comparisons.log"
done
git --no-pager diff --quiet HEAD
printf '%s\n' 'REPRODUCIBLE_RESULT=0' > "$record/result.log"
cat "$record/comparisons.log" "$record/result.log"
