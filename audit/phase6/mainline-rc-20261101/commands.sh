set -eu
record=$PWD/audit/phase6/mainline-rc-20261101
probe=$(mktemp -d /tmp/phase6-rc-helpers.XXXXXXXX)
trap 'rm -rf "$probe"' 0
sed -n '/^valid_release()/,/^}/p; /^source_url()/,/^}/p' tests/kernel/build-vanilla.sh > "$probe/functions.sh"
# shellcheck disable=SC1091 # Functions are extracted from the checked builder.
. "$probe/functions.sh"
for version in 6.8.12 7.3 7.3.1 7.4-rc1 7.4-rc12; do
 valid_release "$version"
 printf 'VALID_RELEASE=%s\n' "$version"
done
for version in 7.4-rc0 7.4-rc 7.4.1-rc1 7.4-rc1-extra ../7.4 7..4 7.4/other; do
 if valid_release "$version"; then exit 1; fi
 printf 'INVALID_RELEASE_REJECTED=%s\n' "$version"
done
test "$(source_url 6.8.12)" = https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.12.tar.xz
test "$(source_url 7.3)" = https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.3.tar.xz
test "$(source_url 7.4-rc1)" = "$(jq -r '.releases[]|select(.moniker=="mainline")|.source' audit/phase6/pause-20261101/publication/releases.json)"
printf 'SOURCE_URLS_MATCH_STABLE_AND_PUBLISHED_RC=0\n'

set -eu
record=$PWD/audit/phase6/mainline-rc-20261101
url=$(jq -r '.releases[]|select(.moniker=="mainline")|.source' audit/phase6/pause-20261101/publication-current/releases.json)
archive=$PWD/target/phase6-kernels/downloads/linux-7.4-rc1.tar.gz
printf 'source URL: %s\n' "$url"
if test ! -s "$archive"; then
 /usr/bin/curl --fail --location --max-time 180 --output "$archive.part" "$url"
 magic=$(od -An -tx1 -N2 "$archive.part" | tr -d ' \n')
 test "$magic" = 1f8b
 mv "$archive.part" "$archive"
fi
docker run --rm --network none --mount "type=bind,source=$archive,target=/source.tar,readonly" --entrypoint tar rs-l2tpd-kernel-builder:phase23 -xOf /source.tar linux-7.4-rc1/Makefile > "$record/Makefile"
grep -q '^VERSION = 7$' "$record/Makefile"
grep -q '^PATCHLEVEL = 4$' "$record/Makefile"
grep -q '^EXTRAVERSION = -rc1$' "$record/Makefile"
printf 'source git-blob: '
git --no-pager hash-object "$archive"
printf 'RC_ARCHIVE_AND_VERSION_VERIFIED=0\n'
