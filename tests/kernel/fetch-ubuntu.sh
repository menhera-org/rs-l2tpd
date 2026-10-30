#!/bin/sh
# Fetch official published packages; unpack in a networkless Ubuntu container.
set -eu
repo=$(CDPATH= cd -P "$(dirname "$0")/../.." && pwd)
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { echo "usage: $0 noble|resolute [resolve]" >&2; exit 2; }
suite=$1
case $suite in noble) release=24.04 ;; resolute) release=26.04 ;; *) exit 2 ;; esac
case ${2-} in ''|resolve) ;; *) exit 2 ;; esac
cache=$repo/target/phase6-kernels
mkdir -p "$cache/downloads"
metadata=$cache/downloads/$suite-Packages
: > "$metadata"
for pocket in updates security; do
    case $pocket in updates) host=archive.ubuntu.com ;; security) host=security.ubuntu.com ;; esac
    url=https://$host/ubuntu/dists/$suite-$pocket/main/binary-amd64/Packages.xz
    index=$cache/downloads/$suite-$pocket-Packages.xz
    curl --fail --location --max-time 90 --header 'Cache-Control: no-cache' \
        --output "$index.part" "$url"
    xz -dc "$index.part" >> "$metadata"
    mv "$index.part" "$index"
done
candidate() {
    awk -v package="$1" 'BEGIN { RS=""; FS="\n" }
        $1 == "Package: " package {
            for(i=1;i<=NF;i++) if($i ~ /^Version: /) print substr($i,10)
        }' "$metadata" | docker run --rm -i --network none \
        --entrypoint sh "ubuntu:$release" -ec '
        best=
        while IFS= read -r version; do
            if [ -z "$best" ] || dpkg --compare-versions "$version" gt "$best"; then best=$version; fi
        done
        printf "%s\n" "$best"
    '
}
version=$(candidate linux-image-generic)
[ -n "$version" ] || { echo "no generic candidate for $suite" >&2; exit 1; }
stanza() {
    awk -v package="$1" -v version="$2" 'BEGIN{RS=""; FS="\n"}
        $1 == "Package: " package {
            found=0
            for(i=1;i<=NF;i++) if($i == "Version: " version) found=1
            if(found) { print; exit }
        }' "$metadata"
}
generic=$(stanza linux-image-generic "$version")
kernel=$(printf '%s\n' "$generic" | sed -n 's/^Depends: linux-image-\([^, ]*\).*/\1/p')
case $kernel in *-generic) ;; *) echo "unrecognized generic dependency: $generic" >&2; exit 1 ;; esac
printf 'UBUNTU_SUITE=%s\nUBUNTU_META_VERSION=%s\nKERNEL_RELEASE=%s\n' "$suite" "$version" "$kernel"
printf '%s\n' "$generic"
[ "${2-}" != resolve ] || exit 0
unpack=$cache/ubuntu-$suite-$version
mkdir -p "$unpack/root"
kmod_version=$(candidate kmod)
for package in "linux-image-$kernel" "linux-modules-$kernel" "linux-modules-extra-$kernel" kmod libkmod2; do
    package_version=$version
    case $package in kmod|libkmod2) package_version=$kmod_version ;; esac
    row=$(stanza "$package" "$package_version")
    if [ -z "$row" ]; then
        case $package in linux-modules-extra-*) continue ;; esac
        echo "missing package $package $version" >&2
        exit 1
    fi
    filename=$(printf '%s\n' "$row" | sed -n 's/^Filename: //p')
    digest=$(printf '%s\n' "$row" | sed -n 's/^SHA256: //p')
    case $filename in pool/main/l/*.deb|pool/main/k/*.deb) ;; *) echo "unexpected filename: $filename" >&2; exit 1 ;; esac
    case $filename in *..*) exit 1 ;; esac
    [ "$(printf '%s' "$digest" | wc -c | tr -d ' ')" = 64 ] || exit 1
    case $digest in *[!0-9a-f]*) exit 1 ;; esac
    archive=$cache/downloads/${filename##*/}
    if [ ! -s "$archive" ]; then
        curl --fail --location --max-time 180 --output "$archive.part" \
            "https://archive.ubuntu.com/ubuntu/$filename"
        mv "$archive.part" "$archive"
    fi
    printf '%s\n' "$row"
    printf '%s  /package.deb\n' "$digest" | docker run --rm -i --network none \
        --mount "type=bind,source=$archive,target=/package.deb,readonly" \
        --entrypoint sha256sum "ubuntu:$release" -c -
    if [ ! -f "$unpack/$package.complete" ] || [ "$(cat "$unpack/$package.complete")" != "$digest" ]; then
        docker run --rm --network none --user "$(id -u):$(id -g)" \
            --mount "type=bind,source=$archive,target=/package.deb,readonly" \
            --mount "type=bind,source=$unpack/root,target=/extract" \
            --entrypoint dpkg-deb "ubuntu:$release" -x /package.deb /extract
        printf '%s\n' "$digest" > "$unpack/$package.complete"
    fi
done
[ -s "$unpack/root/boot/vmlinuz-$kernel" ] || exit 1
modules=$unpack/root/lib/modules/$kernel
[ -d "$modules" ] || modules=$unpack/root/usr/lib/modules/$kernel
[ -d "$modules" ] || exit 1
printf 'KERNEL_IMAGE=%s\nKERNEL_ROOT=%s\nKERNEL_MODULES=%s\n' "$unpack/root/boot/vmlinuz-$kernel" "$unpack/root" "$modules"
