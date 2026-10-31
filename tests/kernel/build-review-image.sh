#!/bin/sh
# Fetch on the caller; resolve and install packages in networkless containers.
set -eu
repo=$(CDPATH='' cd -P "$(dirname "$0")/../.." && pwd)
cache=$repo/target/phase6-image
origin=https://dl-cdn.alpinelinux.org/alpine/v3.22
for repository in main community; do
    mkdir -p "$cache/$repository/x86_64"
    curl --fail --location --max-time 90 --output "$cache/$repository/x86_64/APKINDEX.tar.gz.part" \
        "$origin/$repository/x86_64/APKINDEX.tar.gz"
    mv "$cache/$repository/x86_64/APKINDEX.tar.gz.part" "$cache/$repository/x86_64/APKINDEX.tar.gz"
done
docker run --rm --platform linux/amd64 --network none \
    --mount "type=bind,source=$cache,target=/packages,readonly" alpine:3.22 \
    apk --no-network --repositories-file /dev/null \
    --repository /packages/main --repository /packages/community \
    fetch --recursive --url --simulate linux-virt iproute2 util-linux kmod > "$cache/packages"
[ -s "$cache/packages" ]
while IFS= read -r package; do
    case $package in
        /packages/main/x86_64/*.apk|/packages/community/x86_64/*.apk) ;;
        *) echo "unexpected package path: $package" >&2; exit 1 ;;
    esac
    case $package in *..*) exit 1 ;; esac
    path=${package#/packages/}
    curl --fail --location --max-time 180 --output "$cache/$path.part" "$origin/$path"
    mv "$cache/$path.part" "$cache/$path"
done < "$cache/packages"
docker build --platform linux/amd64 --network none --progress=plain -t rs-l2tpd-audit-vm:local \
    -f "$repo/tests/kernel/Dockerfile.review" "$cache"
