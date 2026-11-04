#!/bin/sh
# Fetch the selected distro packages; extract without installing on the host.
set -eu
[ "$#" -eq 2 ] || { echo 'usage: fetch-optional.sh debian13|rocky9|rocky10 RECORD' >&2; exit 2; }
kind=$1
record=$2
case $kind in debian13|rocky9|rocky10) ;; *) exit 2 ;; esac
repo=$(pwd -P)
case $record in /*) ;; *) record=$repo/$record ;; esac
cache=$repo/target/optional-kernels/$kind
mkdir -p "$record" "$cache/root"
modules=$cache/root/lib/modules
check_digest() {
    [ "${#1}" -eq 64 ]
    case $1 in *[!0-9a-f]*) return 1 ;; esac
}
case $kind in
debian13)
    base=https://security.debian.org/debian-security
    curl --fail --location --max-time 180 --output "$cache/Packages.xz" \
        "$base/dists/trixie-security/main/binary-amd64/Packages.xz"
    xz -dc "$cache/Packages.xz" > "$cache/Packages"
    package=linux-image-6.12.115+deb13.1-amd64
    awk -v package="$package" 'BEGIN {RS=""; FS="\n"}
        $1 == "Package: " package {print; found++}
        END {if(found != 1) exit 1}' "$cache/Packages" > "$record/package.txt"
    grep -qx 'Version: 6.12.115-2' "$record/package.txt"
    file=$(sed -n 's/^Filename: //p' "$record/package.txt")
    digest=$(sed -n 's/^SHA256: //p' "$record/package.txt")
    check_digest "$digest"
    case $file in pool/updates/main/l/*.deb) ;; *) exit 1 ;; esac
    case $file in *..*) exit 1 ;; esac
    archive=$cache/${file##*/}
    curl --fail --location --max-time 300 --output "$archive" "$base/$file"
    printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
    docker image inspect --format '{{.Id}}' debian:trixie-slim > "$record/extractor-image.log"
    docker run --rm --network none --user "$(id -u):$(id -g)" \
        --mount "type=bind,source=$archive,target=/package.deb,readonly" \
        --mount "type=bind,source=$cache/root,target=/extract" \
        --entrypoint dpkg-deb debian:trixie-slim -x /package.deb /extract
    release=6.12.115+deb13.1-amd64
    modules=$cache/root/usr/lib/modules
    ;;
rocky9|rocky10)
    case $kind in
        rocky9) major=9; version=5.14.0-687.61.1.el9_8 ;;
        rocky10) major=10; version=6.12.0-211.72.1.el10_2 ;;
    esac
    base=https://dl.rockylinux.org/pub/rocky/$major/BaseOS/x86_64/os
    curl --fail --location --max-time 180 --output "$record/repomd.xml" "$base/repodata/repomd.xml"
    awk '/<data type="primary">/ {inside=1}
        inside {print}
        /<\/data>/ && inside {inside=0; found++}
        END {if(found != 1) exit 1}' "$record/repomd.xml" > "$record/primary-location.txt"
    primary=$(sed -n 's/.*<location href="\([^"]*\)".*/\1/p' "$record/primary-location.txt")
    digest=$(sed -n 's/.*<checksum type="sha256">\([^<]*\)<\/checksum>.*/\1/p' "$record/primary-location.txt")
    check_digest "$digest"
    case $primary in repodata/*-primary.xml.gz) ;; *) exit 1 ;; esac
    case $primary in *..*) exit 1 ;; esac
    curl --fail --location --max-time 180 --output "$cache/primary.xml.gz" "$base/$primary"
    printf '%s  %s\n' "$digest" "$cache/primary.xml.gz" | sha256sum -c -
    gzip -dc "$cache/primary.xml.gz" > "$cache/primary.xml"
    docker image inspect --format '{{.Id}}' rockylinux:9 > "$record/extractor-image.log"
    for package in kernel-core kernel-modules-core kernel-modules kernel-modules-extra; do
        filename=$package-$version.x86_64.rpm
        file=Packages/k/$filename
        awk -v file="$file" '/<package / {block=""; inside=1}
            inside {block=block $0 "\n"}
            /<\/package>/ && inside {
                if(index(block, "<location href=\"" file "\"")) {printf "%s", block; found++}
                inside=0
            }
            END {if(found != 1) exit 1}' "$cache/primary.xml" > "$record/$package.xml"
        digest=$(sed -n 's/.*<checksum type="sha256" pkgid="YES">\([^<]*\)<\/checksum>.*/\1/p' "$record/$package.xml")
        check_digest "$digest"
        archive=$cache/$filename
        curl --fail --location --max-time 300 --output "$archive" "$base/$file"
        printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
        docker run --rm --network none \
            --mount "type=bind,source=$archive,target=/package.rpm,readonly" \
            --entrypoint rpm2cpio rockylinux:9 /package.rpm > "$cache/payload.cpio"
        (cd "$cache/root" && cpio -idmu < "$cache/payload.cpio")
        rm "$cache/payload.cpio"
    done
    release=$version.x86_64
    mkdir -p "$cache/root/boot"
    cp "$cache/root/lib/modules/$release/vmlinuz" "$cache/root/boot/vmlinuz-$release"
    cp "$cache/root/lib/modules/$release/config" "$cache/root/boot/config-$release"
    ;;
*) exit 2 ;;
esac
test -s "$cache/root/boot/vmlinuz-$release"
test -s "$cache/root/boot/config-$release"
test -d "$modules/$release"
printf 'KERNEL_RELEASE=%s\nKERNEL_ROOT=%s\nKERNEL_IMAGE=%s\nKERNEL_MODULES=%s\nKERNEL_CONFIG=%s\n' \
    "$release" "$cache/root" "$cache/root/boot/vmlinuz-$release" \
    "$modules/$release" "$cache/root/boot/config-$release"
