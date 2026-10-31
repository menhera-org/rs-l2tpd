#!/bin/sh
# Required stock/vanilla/mainline kernels, or a requested vanilla range.
set -eu
repo=$(CDPATH='' cd -P "$(dirname "$0")/../.." && pwd)
cd "$repo"
latest_series() {
    awk -v series="$1" '
        /href="linux-.*\.tar\.xz"/ {
            version=$0
            sub(/^.*href="linux-/,"",version); sub(/\.tar\.xz".*$/,"",version)
            if(version !~ /^[0-9]+\.[0-9]+(\.[0-9]+)?$/) next
            split(version,a,"."); key=a[1] "." a[2]
            if(key == series && (!found || a[3]+0 > patch)) {
                found=1; patch=a[3]+0; result=version
            }
        }
        END { if(!found) exit 1; print result }
    ' "$2"
}
# shortcut: final mainline releases and v6/v7 indexes; extend when the required set moves beyond them.
mainline() {
    # Fail closed if the publication format changes; never select a stable
    # entry accidentally when the mainline entry is absent or malformed.
    awk '
        /^[[:space:]]*"moniker":[[:space:]]*"mainline",[[:space:]]*$/ {
            if(getline <= 0) exit 1
            if($0 !~ /^[[:space:]]*"version":[[:space:]]*"[0-9]+\.[0-9]+(\.[0-9]+)?",[[:space:]]*$/) exit 1
            version=$0; sub(/^[^:]*:[[:space:]]*"/,"",version); sub(/",.*$/,"",version)
            print version; found=1; exit
        }
        END { if(!found) exit 1 }
    ' "$1"
}
field() { sed -n "s/^$1=//p" "$2"; }
[ "$#" = 1 ] || { echo "usage: $0 required|v6.8..v7.3|self-test" >&2; exit 2; }
selection=$1
if [ "$selection" = self-test ]; then
    fixture=$(mktemp -d /tmp/rs-l2tpd-matrix-parse.XXXXXX)
    trap 'rm -rf "$fixture"' 0
    printf '%s\n' '<a href="linux-6.8.9.tar.xz">' '<a href="linux-6.8.12.tar.xz">' \
        '<a href="linux-7.0.14.tar.xz">' '<a href="linux-6.8.99.tar.gz">' > "$fixture/index"
    [ "$(latest_series 6.8 "$fixture/index")" = 6.8.12 ]
    if latest_series 6.9 "$fixture/index" >/dev/null; then exit 1; fi
    printf '%s\n' ' "moniker": "mainline",' ' "version": "7.3",' \
        ' "moniker": "stable",' ' "version": "7.4",' > "$fixture/releases"
    [ "$(mainline "$fixture/releases")" = 7.3 ]
    printf '%s\n' ' "moniker": "stable",' ' "version": "7.4",' > "$fixture/releases"
    if mainline "$fixture/releases" >/dev/null; then exit 1; fi
    printf '%s\n' ' "moniker": "mainline",' ' "source": "not a version",' > "$fixture/releases"
    if mainline "$fixture/releases" >/dev/null; then exit 1; fi
    echo 'matrix publication parser: passed'
    exit 0
fi
if [ "$selection" != required ] && ! printf '%s\n' "$selection" | grep -Eq '^v[0-9]+\.[0-9]+\.\.v[0-9]+\.[0-9]+$'; then
    echo "invalid selection" >&2
    exit 2
fi
record=$repo/audit/phase6/matrix-$(date -u +%Y%m%dT%H%M%SZ)-$$
mkdir -p "$record"
git --no-pager rev-parse HEAD > "$record/revision"
git --no-pager diff HEAD -- src tests Cargo.toml Cargo.lock > "$record/source.patch"
printf 'selection: %s\ncommand: tests/docker/run.sh matrix %s\n' "$selection" "$selection" > "$record/command.log"
resolve() {
    destination=$1
    mkdir -p "$destination"
    for major in 6 7; do
        curl --fail --location --max-time 90 --header 'Cache-Control: no-cache' \
            --output "$destination/v$major.html" "https://cdn.kernel.org/pub/linux/kernel/v$major.x/"
    done
    curl --fail --location --max-time 90 --header 'Cache-Control: no-cache' \
        --output "$destination/releases.json" https://www.kernel.org/releases.json
    mainline "$destination/releases.json" > "$destination/mainline"
    if [ "$selection" = required ]; then
        for suite in noble resolute; do
            tests/kernel/fetch-ubuntu.sh "$suite" resolve > "$destination/$suite.log"
            field UBUNTU_META_VERSION "$destination/$suite.log" >> "$destination/versions"
            release=$(field KERNEL_RELEASE "$destination/$suite.log")
            series=$(printf '%s\n' "$release" | awk -F. '{print $1 "." $2}')
            major=${series%%.*}
            latest_series "$series" "$destination/v$major.html" >> "$destination/versions"
        done
    fi
    cat "$destination/mainline" >> "$destination/versions"
}
resolve "$record/initial"
result=0
run_vanilla() {
    version=$1
    tests/kernel/build-vanilla.sh "$version" > "$record/build-$version.log" 2>&1 || return 1
    image=$(field KERNEL_IMAGE "$record/build-$version.log")
    config=$(field KERNEL_CONFIG "$record/build-$version.log")
    expected=$(printf '%s\n' "$version" | awk -F. '{if(NF==2)print $0 ".0";else print}')
    tests/kernel/run-guest.sh "$image" - "$config" normal "$record/vanilla-$version" || return 1
    grep -qx "GUEST_KERNEL_RELEASE=$expected" "$record/vanilla-$version/run.log" || return 1
    tests/kernel/run-guest.sh "$image" - "$config" clock "$record/vanilla-$version-clock" || return 1
    grep -qx "GUEST_KERNEL_RELEASE=$expected" "$record/vanilla-$version-clock/run.log"
}
if [ "$selection" = required ]; then
    for suite in noble resolute; do
        tests/kernel/fetch-ubuntu.sh "$suite" > "$record/$suite-packages.log" 2>&1 || { result=1; continue; }
        root=$(field KERNEL_ROOT "$record/$suite-packages.log")
        image=$(field KERNEL_IMAGE "$record/$suite-packages.log")
        modules=$(field KERNEL_MODULES "$record/$suite-packages.log")
        release=$(field KERNEL_RELEASE "$record/$suite-packages.log")
        initial=$(field UBUNTU_META_VERSION "$record/initial/$suite.log")
        current=$(field UBUNTU_META_VERSION "$record/$suite-packages.log")
        if [ "$initial" != "$current" ]; then echo "target changed during fetch: $suite" >&2; result=1; continue; fi
        config=-
        if [ -f "$root/boot/config-$release" ]; then config=$root/boot/config-$release; fi
        if tests/kernel/run-guest.sh "$image" "$modules" "$config" normal "$record/$suite"; then
            grep -qx "GUEST_KERNEL_RELEASE=$release" "$record/$suite/run.log" || result=1
        else result=1; fi
        if tests/kernel/run-guest.sh "$image" "$modules" "$config" clock "$record/$suite-clock"; then
            grep -qx "GUEST_KERNEL_RELEASE=$release" "$record/$suite-clock/run.log" || result=1
        else result=1; fi
        series=$(printf '%s\n' "$release" | awk -F. '{print $1 "." $2}')
        major=${series%%.*}
        version=$(latest_series "$series" "$record/initial/v$major.html")
        run_vanilla "$version" || result=1
    done
    version=$(cat "$record/initial/mainline")
    run_vanilla "$version" || result=1
    image=$(field KERNEL_IMAGE "$record/build-$version.log")
    config=$(field KERNEL_CONFIG "$record/build-$version.log")
    tests/kernel/run-guest.sh "$image" - "$config" ipv6-disable "$record/ipv6-disable" || result=1
    if tests/kernel/build-vanilla.sh "$version" no-ipv6 > "$record/build-$version-no-ipv6.log" 2>&1; then
        image=$(field KERNEL_IMAGE "$record/build-$version-no-ipv6.log")
        config=$(field KERNEL_CONFIG "$record/build-$version-no-ipv6.log")
        tests/kernel/run-guest.sh "$image" - "$config" no-ipv6 "$record/no-ipv6" || result=1
    else result=1; fi
else
    from=${selection%%..*}; from=${from#v}
    to=${selection#*..}; to=${to#v}
    case $from:$to in *[!0-9.:]*) echo "invalid range" >&2; exit 2 ;; esac
    awk -v from="$from" -v to="$to" '
        BEGIN {split(from,a,"."); low=a[1]*1000+a[2]; split(to,a,"."); high=a[1]*1000+a[2]; if(low>high)exit 1}
        /href="linux-.*\.tar\.xz"/ {
            version=$0; sub(/^.*href="linux-/,"",version); sub(/\.tar\.xz".*$/,"",version)
            if(version !~ /^[0-9]+\.[0-9]+(\.[0-9]+)?$/) next
            split(version,a,"."); n=a[1]*1000+a[2]; key=a[1] "." a[2]
            if(n>=low && n<=high && (!(key in best)||a[3]+0>patch[key])) {
                best[key]=version; patch[key]=a[3]+0
            }
        }
        END {for(key in best)print best[key]}
    ' "$record/initial/v6.html" "$record/initial/v7.html" | sort -t. -k1,1n -k2,2n > "$record/range"
    [ -s "$record/range" ] || { echo "empty range" >&2; exit 1; }
    while IFS= read -r version; do run_vanilla "$version" || result=1; done < "$record/range"
fi
if [ "$selection" = required ]; then
    packages=$record/resolute-packages.log
    image=$(field KERNEL_IMAGE "$packages")
    modules=$(field KERNEL_MODULES "$packages")
    root=$(field KERNEL_ROOT "$packages")
    release=$(field KERNEL_RELEASE "$packages")
    if tests/kernel/run-guest.sh "$image" "$modules" "$root/boot/config-$release" no-ethernet "$record/no-ethernet"; then
        grep -qx "GUEST_KERNEL_RELEASE=$release" "$record/no-ethernet/run.log" || result=1
    else result=1; fi
fi
resolve "$record/final"
if ! cmp -s "$record/initial/versions" "$record/final/versions"; then
    echo 'published targets changed; refresh documentation and rerun before claiming a pass' >&2
    result=1
fi
git --no-pager diff HEAD -- src tests Cargo.toml Cargo.lock > "$record/final-source.patch"
if ! cmp -s "$record/source.patch" "$record/final-source.patch"; then
    echo 'test sources changed during the matrix; rerun a consistent source state' >&2
    result=1
fi
printf 'MATRIX_RESULT=%s\n' "$result" > "$record/result.log"
printf 'MATRIX_RESULT=%s\nrecord: %s\n' "$result" "$record"
exit "$result"
