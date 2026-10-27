#!/bin/sh
# Test-container helper: preserve read-only kernel attributes while allowing
# networkd's /sys-root availability check to enable real udev metadata.
set -eu
[ -e /.dockerenv ] || { echo 'this helper requires a disposable Docker container' >&2; exit 1; }
mkdir -p /run/read-only-sys
mount --rbind /sys /run/read-only-sys
mount -t tmpfs -o mode=755 tmpfs /sys
for entry in /run/read-only-sys/*; do
    name=${entry##*/}
    if [ -L "$entry" ]; then
        ln -s "$(readlink "$entry")" "/sys/$name"
    elif [ -d "$entry" ]; then
        mkdir "/sys/$name"
        mount --rbind "$entry" "/sys/$name"
        mount -o remount,bind,ro "/sys/$name"
    fi
done
