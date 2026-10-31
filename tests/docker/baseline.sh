#!/bin/sh
# Share the archived interoperability peer between container and guest runners.
set -eu
[ "$#" = 1 ] || { echo "usage: $0 RECORD" >&2; exit 2; }
repo=$(CDPATH='' cd -P "$(dirname "$0")/../.." && pwd)
cd "$repo"
record=$1
mkdir -p "$record"
revision=$(git --no-pager rev-parse 'v0.1.5^{commit}')
baseline_dir=$repo/target/phase6-baseline/$revision
baseline=$baseline_dir/target/x86_64-unknown-linux-musl/release/rs-l2tpd
set +e
(
    set -e
    printf 'baseline commit: %s\n' "$revision"
    printf '%s\n' 'target: x86_64-unknown-linux-musl; features: v0.1.5 defaults; own Cargo.lock'
    if [ ! -x "$baseline" ]; then
        mkdir -p "$baseline_dir/source"
        git --no-pager archive --format=tar --output="$baseline_dir/source.tar" "$revision"
        tar -xf "$baseline_dir/source.tar" -C "$baseline_dir/source"
        printf '%s\n' 'command: cargo build --locked --release --target x86_64-unknown-linux-musl (archived baseline)'
        CARGO_TARGET_DIR="$baseline_dir/target" \
            CONFIG_FILE_PATH=/etc/rs-l2tpd.toml CONFIG_DIR_PATH=/etc/rs-l2tpd.toml.d \
            cargo build --locked --release --target x86_64-unknown-linux-musl \
            --manifest-path "$baseline_dir/source/Cargo.toml" || exit "$?"
    fi
    printf 'baseline binary git-blob: '
    git --no-pager hash-object "$baseline"
    "$baseline" --version
) > "$record/baseline.raw" 2>&1
result=$?
set -e
sed 's/\(Finished .*\) in .*/\1/' "$record/baseline.raw" > "$record/baseline.log"
rm "$record/baseline.raw"
[ "$result" = 0 ] || { cat "$record/baseline.log" >&2; exit "$result"; }
printf '%s\n' "$baseline"
