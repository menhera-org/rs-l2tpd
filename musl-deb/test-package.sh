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
: > "$MUSL_DEB_CALLS"
mkdir -p /run/systemd/system /usr/local/bin
cat > /usr/local/bin/systemctl <<'SH'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$MUSL_DEB_CALLS"
[ "${MUSL_DEB_FAIL:-}" != "$1" ]
SH
chmod 755 /usr/local/bin/systemctl

dpkg-deb --info "$package"
dpkg-deb --contents "$package"
dpkg-deb --control "$package" "$work/control"
grep -qx 'Architecture: amd64' "$work/control/control"
if grep -q '^Depends:' "$work/control/control"; then exit 1; fi
grep -qx '/etc/rs-l2tpd.toml' "$work/control/conffiles"

dpkg -i "$package"
test "$(cat "$MUSL_DEB_CALLS")" = "$(printf 'daemon-reload\nenable --now rs-l2tpd.service')"
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

printf '%s\n' '# operator configuration' >> /etc/rs-l2tpd.toml
cp /etc/rs-l2tpd.toml "$work/operator.toml"
printf '%s\n' '# operator fragment' > /etc/rs-l2tpd.toml.d/operator.toml
: > "$MUSL_DEB_CALLS"
dpkg -i "$package"
cmp "$work/operator.toml" /etc/rs-l2tpd.toml
test "$(cat "$MUSL_DEB_CALLS")" = daemon-reload

: > "$MUSL_DEB_CALLS"
sh "$work/control/prerm" upgrade 0.2.0-1
sh "$work/control/postrm" upgrade 0.2.0-1
test ! -s "$MUSL_DEB_CALLS"
if MUSL_DEB_FAIL=daemon-reload sh "$work/control/postinst" configure 0.2.0-1; then exit 1; fi
test "$(cat "$MUSL_DEB_CALLS")" = daemon-reload

: > "$MUSL_DEB_CALLS"
dpkg --remove rs-l2tpd
test "$(cat "$MUSL_DEB_CALLS")" = "$(printf 'disable --now rs-l2tpd.service\ndaemon-reload')"
test -f /etc/rs-l2tpd.toml
dpkg --purge rs-l2tpd
test ! -e /etc/rs-l2tpd.toml
test -f /etc/rs-l2tpd.toml.d/operator.toml
rm /etc/rs-l2tpd.toml.d/operator.toml

# A repeated purge removes an empty directory and works without systemd.
rmdir /run/systemd/system
sh "$work/control/postrm" purge
test ! -e /etc/rs-l2tpd.toml.d
: > "$MUSL_DEB_CALLS"
sh "$work/control/postinst" configure
test ! -s "$MUSL_DEB_CALLS"
printf '%s\n' 'PACKAGE_CONSUMER_RESULT=0'
