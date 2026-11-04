#!/bin/sh
# Use the unchanged guest suites with the three requested stock kernels.
set -eu
[ "$#" -eq 1 ] || { echo 'usage: run-optional.sh RECORD' >&2; exit 2; }
record=$1
case $record in /*) ;; *) record=$(pwd -P)/$record ;; esac
test ! -e "$record/profiles.log"
git --no-pager rev-parse HEAD > "$record/revision"
git --no-pager diff HEAD -- src tests Cargo.toml Cargo.lock > "$record/initial-source.patch"
test ! -s "$record/initial-source.patch"
field() { sed -n "s/^$1=//p" "$2"; }
result=0
for kind in debian13 rocky9 rocky10; do
    metadata=$record/$kind-packages/kernel.env
    release=$(field KERNEL_RELEASE "$metadata")
    image=$(field KERNEL_IMAGE "$metadata")
    modules=$(field KERNEL_MODULES "$metadata")
    config=$(field KERNEL_CONFIG "$metadata")
    test -n "$release" && test -f "$image" && test -d "$modules" && test -f "$config"
    for mode in normal clock; do
        status=0
        tests/kernel/run-guest.sh "$image" "$modules" "$config" "$mode" "$record/$kind-$mode" \
            > "$record/$kind-$mode-driver.log" 2>&1 || status=$?
        if [ "$status" -eq 0 ]; then
            grep -qx "GUEST_KERNEL_RELEASE=$release" "$record/$kind-$mode/run.log" || status=1
        fi
        printf 'kernel=%s release=%s mode=%s exit=%s\n' "$kind" "$release" "$mode" "$status" \
            >> "$record/profiles.log"
        if [ "$status" -ne 0 ]; then result=1; fi
    done
done
git --no-pager diff "$(cat "$record/revision")" -- src tests Cargo.toml Cargo.lock > "$record/final-source.patch"
cmp "$record/initial-source.patch" "$record/final-source.patch" || result=1
printf 'OPTIONAL_MATRIX_RESULT=%s\n' "$result" > "$record/result.log"
cat "$record/profiles.log" "$record/result.log"
exit "$result"
