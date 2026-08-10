#!/bin/sh

set -eu

cd "$(dirname "$0")"

ver=$(grep '^\s*version\s*=\s*".*"' Cargo.toml | head -n1 | sed 's/^\s*version\s*=\s*"\(.*\)".*/\1/')

cross build --release --target=x86_64-unknown-linux-musl --features=setup
cross build --release --target=aarch64-unknown-linux-musl --features=setup

dir=$(pwd)

cd target/x86_64-unknown-linux-musl/release

tar caf "$dir/rs-l2tpd-$ver-x86_64-unknown-linux-musl.tar.gz" rs-l2tpd
cd "$dir"

cd target/aarch64-unknown-linux-musl/release

tar caf "$dir/rs-l2tpd-$ver-aarch64-unknown-linux-musl.tar.gz" rs-l2tpd
cd "$dir"
