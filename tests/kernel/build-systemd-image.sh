#!/bin/sh
# Fetch on the caller; authenticate and install in networkless containers.
set -eu
repo=$(CDPATH='' cd -P "$(dirname "$0")/../.." && pwd)
case $#:${1:-} in
    0:|1:--offline) ;;
    *) echo 'usage: build-systemd-image.sh [--offline]' >&2; exit 2 ;;
esac
if [ "${1:-}" = --offline ]; then
    docker image inspect ubuntu:24.04 >/dev/null
fi
cache=$repo/target/systemd-image
mkdir -p "$cache"
for suite in noble noble-updates noble-security; do
    directory=$cache/dists/$suite/main/binary-amd64
    mkdir -p "$directory"
    case $suite in noble-security) origin=https://security.ubuntu.com/ubuntu ;; *) origin=https://archive.ubuntu.com/ubuntu ;; esac
    if [ "${1:-}" != --offline ]; then
        for file in InRelease main/binary-amd64/Packages.xz; do
            curl --fail --location --retry 3 --max-time 180 \
                --output "$cache/dists/$suite/$file.part" "$origin/dists/$suite/$file"
            mv "$cache/dists/$suite/$file.part" "$cache/dists/$suite/$file"
        done
    fi
    test -s "$cache/dists/$suite/InRelease"
    test -s "$directory/Packages.xz"
done
docker build --platform linux/amd64 --network none --progress=plain --target resolver \
    -t rs-l2tpd-systemd-resolver:ubuntu24.04 -f "$repo/tests/kernel/Dockerfile.systemd" "$cache"
docker run --rm --platform linux/amd64 --network none rs-l2tpd-systemd-resolver:ubuntu24.04 \
    > "$cache/resolution.log"
# apt resolves dependencies against the base image and signed, local indexes.
sed -n "s/^'file:\/packages\/\([^']*\)'.*/\1/p" "$cache/resolution.log" > "$cache/packages"
test -s "$cache/packages"
while IFS= read -r path; do
    path=$(printf '%s' "$path" | sed 's/%2[bB]/+/g; s/%7[eE]/~/g')
    case $path in pool/main/*.deb) ;; *) echo "unexpected package path: $path" >&2; exit 1 ;; esac
    case $path in *..*|*[!a-zA-Z0-9_./+~-]*) exit 1 ;; esac
    mkdir -p "$cache/${path%/*}"
    if [ "${1:-}" != --offline ]; then
        curl --fail --location --retry 3 --max-time 180 \
            --output "$cache/$path.part" "https://archive.ubuntu.com/ubuntu/$path"
        mv "$cache/$path.part" "$cache/$path"
    fi
    test -s "$cache/$path"
done < "$cache/packages"
# apt verifies each package against the authenticated index before installation.
docker build --platform linux/amd64 --network none --progress=plain --target runtime \
    -t rs-l2tpd-systemd:ubuntu24.04 -f "$repo/tests/kernel/Dockerfile.systemd" "$cache"
docker image inspect --format '{{.Id}}' rs-l2tpd-systemd:ubuntu24.04
