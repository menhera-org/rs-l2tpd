#!/bin/sh
# Consumer checks run only inside a disposable, networkless Debian container.
set -eu
[ "${MUSL_DEB_TEST_CONTAINER:-}" = 1 ] && [ "$(id -u)" = 0 ] || {
    echo 'run in a disposable Debian container with MUSL_DEB_TEST_CONTAINER=1' >&2
    exit 2
}
[ "$#" = 1 ] || exit 2
package=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' 0
export MUSL_DEB_CALLS="$work/calls"
export DPKG_MAINTSCRIPT_PACKAGE=rs-l2tpd
: > "$MUSL_DEB_CALLS"
mkdir -p /run/systemd/system /usr/local/bin
cat > /usr/local/bin/systemctl <<'SH'
#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
    case $1 in --system|--quiet|--) shift ;; *) break ;; esac
done
action=$1
shift
case $action in
is-enabled)
    if [ "$(readlink /etc/systemd/system/rs-l2tpd.service || :)" = /dev/null ]; then
        echo masked
        exit 1
    fi
    if [ -L /etc/systemd/system/network-online.target.requires/rs-l2tpd.service ]; then
        echo enabled
    else
        echo disabled
        exit 1
    fi
    ;;
is-active) exit 3 ;;
*)
    printf '%s\n' "$action${*:+ $*}" >> "$MUSL_DEB_CALLS"
    [ "${MUSL_DEB_FAIL:-}" != "$action" ]
    ;;
esac
SH
chmod 755 /usr/local/bin/systemctl
policy() {
    cat > /usr/sbin/policy-rc.d <<SH
#!/bin/sh
exit $1
SH
    chmod 755 /usr/sbin/policy-rc.d
}
no_start() {
    if grep -q '^start ' "$MUSL_DEB_CALLS"; then exit 1; fi
}
dpkg-deb --info "$package"
dpkg-deb --contents "$package"
dpkg-deb --control "$package" "$work/control"
grep -qx 'Architecture: amd64' "$work/control/control"
grep -qx 'Depends: init-system-helpers (>= 1.54)' "$work/control/control"
grep -qx '/etc/rs-l2tpd.toml' "$work/control/conffiles"

# The real Debian helpers must honor policy denial on first installation.
policy 101
dpkg -i "$package"
no_start
test -L /etc/systemd/system/network-online.target.requires/rs-l2tpd.service
test -x /usr/sbin/rs-l2tpd
test -f /lib/systemd/system/rs-l2tpd.service
test -d /etc/rs-l2tpd.toml.d
grep -q '^ExecStart=/usr/sbin/rs-l2tpd ' /lib/systemd/system/rs-l2tpd.service
test -n "$(find /usr/sbin/rs-l2tpd -user root -group root -perm 0755)"
/usr/sbin/rs-l2tpd --version
/usr/sbin/rs-l2tpd --check
status=0
/usr/sbin/rs-l2tpd --setup-systemd > "$work/usage" 2>&1 || status=$?
test "$status" = 2
if grep -q '| --setup-systemd' "$work/usage"; then exit 1; fi

# Check the files administrators actually receive, including each local link.
docs=/usr/share/doc/rs-l2tpd
for file in README.md LICENSE-APACHE LICENSE-MPL THIRD-PARTY-NOTICES.txt \
    RUST-COPYRIGHT.html.gz RUST-LICENSES.txt MUSL-COPYRIGHT; do
    test -s "$docs/$file"
done
grep -q '===== tokio-' "$docs/THIRD-PARTY-NOTICES.txt"
grep -q 'Tokio Contributors' "$docs/THIRD-PARTY-NOTICES.txt"
grep -q 'Permission is hereby granted' "$docs/THIRD-PARTY-NOTICES.txt"
for file in LICENSE-APACHE LICENSE-MPL THIRD-PARTY-NOTICES.txt \
    RUST-COPYRIGHT.html.gz RUST-LICENSES.txt MUSL-COPYRIGHT; do
    grep -q "$file" "$docs/README.md"
done
if grep -Eq '\]\([^h#][^)]*\)|docs/|installation\.md' "$docs/README.md"; then exit 1; fi

# An allowed first start uses the helper; disabling or masking stays respected.
policy 0
: > "$MUSL_DEB_CALLS"
sh "$work/control/postinst" configure
grep -qx 'start rs-l2tpd.service' "$MUSL_DEB_CALLS"
rm /etc/systemd/system/network-online.target.requires/rs-l2tpd.service
: > "$MUSL_DEB_CALLS"
sh "$work/control/postinst" configure
no_start
test ! -L /etc/systemd/system/network-online.target.requires/rs-l2tpd.service
ln -s /dev/null /etc/systemd/system/rs-l2tpd.service
sh "$work/control/postinst" configure
test "$(readlink /etc/systemd/system/rs-l2tpd.service)" = /dev/null
no_start

printf '%s\n' '# operator configuration' >> /etc/rs-l2tpd.toml
cp /etc/rs-l2tpd.toml "$work/operator.toml"
printf '%s\n' '# operator fragment' > /etc/rs-l2tpd.toml.d/operator.toml
: > "$MUSL_DEB_CALLS"
dpkg -i "$package"
cmp "$work/operator.toml" /etc/rs-l2tpd.toml
test ! -L /etc/systemd/system/network-online.target.requires/rs-l2tpd.service
test "$(readlink /etc/systemd/system/rs-l2tpd.service)" = /dev/null
no_start

: > "$MUSL_DEB_CALLS"
sh "$work/control/prerm" upgrade 0.2.0-1
sh "$work/control/postrm" upgrade 0.2.0-1
test ! -s "$MUSL_DEB_CALLS"
if MUSL_DEB_FAIL=daemon-reload sh "$work/control/postinst" configure 0.2.0-1; then exit 1; fi

# Stops also honor policy. Removing and purging preserve administrator files.
policy 101
: > "$MUSL_DEB_CALLS"
sh "$work/control/prerm" remove
test ! -s "$MUSL_DEB_CALLS"
policy 0
dpkg --remove rs-l2tpd
grep -qx 'stop rs-l2tpd.service' "$MUSL_DEB_CALLS"
test -f /etc/rs-l2tpd.toml
dpkg --purge rs-l2tpd
test ! -e /etc/rs-l2tpd.toml
test -f /etc/rs-l2tpd.toml.d/operator.toml
test "$(readlink /etc/systemd/system/rs-l2tpd.service)" = /dev/null
rm /etc/rs-l2tpd.toml.d/operator.toml

# A repeated purge removes an empty directory and works without systemd.
rmdir /run/systemd/system
sh "$work/control/postrm" purge
test ! -e /etc/rs-l2tpd.toml.d
: > "$MUSL_DEB_CALLS"
dpkg -i "$package"
test ! -s "$MUSL_DEB_CALLS"
dpkg --purge rs-l2tpd

# A helper-owned removal mask is undone on reinstall and removed on purge.
rm /etc/systemd/system/rs-l2tpd.service
deb-systemd-helper purge rs-l2tpd.service
mkdir -p /run/systemd/system
policy 101
dpkg -i "$package"
test -L /etc/systemd/system/network-online.target.requires/rs-l2tpd.service
dpkg --remove rs-l2tpd
test "$(readlink /etc/systemd/system/rs-l2tpd.service)" = /dev/null
dpkg -i "$package"
test ! -L /etc/systemd/system/rs-l2tpd.service
test -L /etc/systemd/system/network-online.target.requires/rs-l2tpd.service
dpkg --purge rs-l2tpd
test ! -L /etc/systemd/system/rs-l2tpd.service
test ! -L /etc/systemd/system/network-online.target.requires/rs-l2tpd.service
printf '%s\n' 'PACKAGE_CONSUMER_RESULT=0'
