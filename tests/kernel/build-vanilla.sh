#!/bin/sh
# Build tools run only in a disposable networkless container.
set -eu
repo=$(CDPATH= cd -P "$(dirname "$0")/../.." && pwd)
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { echo "usage: $0 VERSION [no-ipv6]" >&2; exit 2; }
version=$1
case $version in ''|*[!0-9.]*|.*|*.|*..*) echo "invalid release: $version" >&2; exit 2 ;; esac
mode=${2-ipv6}
case $mode in ipv6|no-ipv6) ;; *) echo "invalid mode: $mode" >&2; exit 2 ;; esac
cache=$repo/target/phase6-kernels
archive=$cache/downloads/linux-$version.tar.xz
major=${version%%.*}
mkdir -p "$cache/downloads"
if [ ! -s "$archive" ]; then
    curl --fail --location --max-time 180 --output "$archive.part" \
        "https://cdn.kernel.org/pub/linux/kernel/v$major.x/linux-$version.tar.xz"
    mv "$archive.part" "$archive"
fi
recipe=$(git --no-pager hash-object "$repo/tests/kernel/build-vanilla.sh")
build=$cache/linux-$version-$mode
mkdir -p "$build"
cidfile=$build/container.id
cleanup() {
    if [ -s "$cidfile" ]; then docker rm -f "$(cat "$cidfile")" >/dev/null 2>&1 || :; fi
    rm -f "$cidfile"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15
if [ ! -f "$build/complete" ] || [ "$(cat "$build/complete")" != "$recipe" ]; then
    rm -f "$build/complete" "$cidfile"
    docker run --rm --cidfile "$cidfile" --network none --user "$(id -u):$(id -g)" \
        --mount "type=bind,source=$archive,target=/source.tar.xz,readonly" \
        --mount "type=bind,source=$build,target=/build" \
        --workdir /build --entrypoint sh rs-l2tpd-kernel-builder:phase23 -ec '
            if [ ! -f Makefile ]; then tar -xf /source.tar.xz --strip-components=1; fi
            export KBUILD_BUILD_USER=phase6 KBUILD_BUILD_HOST=builder KBUILD_BUILD_VERSION=1
            export KBUILD_BUILD_TIMESTAMP='"'"'Thu Jan 1 00:00:00 UTC 1970'"'"'
            make x86_64_defconfig
            scripts/config --enable NET_NS --enable USER_NS \
                --enable IPV6 --enable IPV6_MULTIPLE_TABLES \
                --enable NET_L3_MASTER_DEV --enable NET_VRF \
                --enable L2TP --enable L2TP_V3 --enable L2TP_IP --enable L2TP_ETH \
                --enable DUMMY --enable VETH --enable NLMON \
                --enable BRIDGE --enable VLAN_8021Q \
                --enable SECCOMP --enable SECCOMP_FILTER \
                --disable DEBUG_INFO --disable DEBUG_INFO_BTF \
                --set-str SYSTEM_TRUSTED_KEYS "" --set-str SYSTEM_REVOCATION_KEYS ""
            if [ "$1" = no-ipv6 ]; then scripts/config --disable IPV6; fi
            make olddefconfig
            make -j4 bzImage
        ' build "$mode"
    printf '%s\n' "$recipe" > "$build/complete"
fi
printf 'source: linux-%s.tar.xz; git-blob: ' "$version"
git --no-pager hash-object "$archive"
printf 'config git-blob: '
git --no-pager hash-object "$build/.config"
printf 'image git-blob: '
git --no-pager hash-object "$build/arch/x86/boot/bzImage"
printf 'KERNEL_IMAGE=%s\nKERNEL_CONFIG=%s\n' "$build/arch/x86/boot/bzImage" "$build/.config"
