#!/bin/sh
# The mandatory checks shared by CI and local pre-commit verification.
set -eu

cd "$(CDPATH='' cd -P "$(dirname "$0")" && pwd)"
files=$(mktemp "${TMPDIR:-/tmp}/rs-l2tpd-ci.XXXXXXXX")
trap 'rm -f "$files"' 0
trap 'exit 1' HUP INT TERM

git --no-pager ls-files -z --cached --others --exclude-standard '*.sh' > "$files"
xargs -0 shellcheck --shell=sh < "$files"
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --locked --lib --no-default-features
cargo build --locked --lib --no-default-features --features serde
cargo build --locked
cargo test --locked --all-features
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd --test process

RULEMAP_STRICT=1 SRCLINK_STRICT=1 \
    cargo test --locked --all-features --test rulemap --test srclink -- --nocapture
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
