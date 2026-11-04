#!/bin/sh
# Use Cargo's verified vendor sources and the pinned compiler's shipped notices.
set -eu
repo=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
cd "$repo"
# shellcheck source=release-config.sh
. ./release-config.sh
directory=target/release-notices
mkdir -p "$directory"
# Package IDs feed a parser even when CI forces colored Cargo output.
cargo "+$RELEASE_TOOLCHAIN" tree --color never --locked --offline --all-features --edges normal,build \
    --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl \
    --prefix none --format '{p}' > "$directory/tree"
awk 'NF >= 2 && $1 != "rs-l2tpd" {sub(/^v/, "", $2); print $1, $2}' "$directory/tree" \
    | LC_ALL=C sort -u > "$directory/crates"
test -s "$directory/crates"
(
    printf '%s\n\n' 'Notices for locked musl release dependencies (including build dependencies).'
    while read -r name version; do
        crate=$name-$version
        source=target/release-vendor/$crate
        test -d "$source"
        printf '\n===== %s =====\n' "$crate"
        printf 'Source: https://crates.io/crates/%s/%s\n' "$name" "$version"
        found=false
        for file in "$source"/LICENSE* "$source"/COPYING* "$source"/COPYRIGHT* \
            "$source"/NOTICE* "$source"/UNLICENSE "$source"/license-*; do
            [ -s "$file" ] || continue
            printf '\n--- %s ---\n' "${file##*/}"
            cat "$file"
            printf '\n'
            found=true
        done
        if [ "$found" = false ]; then
            # fqdn declares MIT but its published crate omits the license text.
            case $crate in
                fqdn-0.5.2) cat musl-deb/licenses/fqdn-0.5.2.txt ;;
                *) echo "missing license text: $crate" >&2; exit 1 ;;
            esac
        fi
    done < "$directory/crates"
) > "$directory/THIRD-PARTY-NOTICES.txt.part"
mv "$directory/THIRD-PARTY-NOTICES.txt.part" "$directory/THIRD-PARTY-NOTICES.txt"
sysroot=$(rustc "+$RELEASE_TOOLCHAIN" --print sysroot)
docker run --rm --network none --platform linux/amd64 -i --entrypoint gzip \
    "$RELEASE_X86_IMAGE" -n -9 -c < "$sysroot/share/doc/rust/COPYRIGHT.html" \
    > "$directory/RUST-COPYRIGHT.html.gz"
(
    for file in "$sysroot"/share/doc/rust/licenses/*.txt; do
        test -s "$file"
        printf '\n===== %s =====\n' "${file##*/}"
        cat "$file"
        printf '\n'
    done
) > "$directory/RUST-LICENSES.txt"
cp musl-deb/licenses/MUSL-COPYRIGHT "$directory/MUSL-COPYRIGHT"
