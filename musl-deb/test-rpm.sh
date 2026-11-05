#!/bin/sh
# Real RPM transactions; run only inside a disposable, networkless container.
set -eu
[ "${MUSL_DEB_TEST_CONTAINER:-}" = 1 ] && [ "$(id -u)" -eq 0 ] || {
    echo 'run only in a disposable container with MUSL_DEB_TEST_CONTAINER=1' >&2
    exit 2
}
[ "$#" -eq 2 ] || { echo 'usage: test-rpm.sh PACKAGE UPGRADE_FIXTURE' >&2; exit 2; }
same() {
    test "$(sha256sum < "$1")" = "$(sha256sum < "$2")"
}
package=$1
upgrade=$2
repo=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /tmp/rpm-test /usr/local/bin /run/systemd/system
export RPM_TEST=/tmp/rpm-test
cat > /usr/bin/systemctl <<'STUB'
#!/bin/sh
set -eu
while :; do
    case ${1:-} in --system|--quiet|--) shift ;; *) break ;; esac
done
command=$1
shift
printf '%s %s\n' "$command" "$*" >> "$RPM_TEST/actions"
if [ -f "$RPM_TEST/fail" ] && [ "$(cat "$RPM_TEST/fail")" = "$command" ]; then exit 1; fi
unit=/etc/systemd/system/rs-l2tpd.service
enabled=/etc/systemd/system/network-online.target.requires/rs-l2tpd.service
case $command in
    is-enabled)
        if [ -L "$unit" ] && [ "$(readlink "$unit")" = /dev/null ]; then
            echo masked
            exit 1
        fi
        if [ -L "$enabled" ]; then echo enabled; else echo disabled; exit 1; fi
        ;;
    preset)
        if [ "$(cat "$RPM_TEST/preset")" = enable ]; then
            mkdir -p "$(dirname "$enabled")"
            ln -sf /usr/lib/systemd/system/rs-l2tpd.service "$enabled"
        else
            rm -f "$enabled"
        fi
        ;;
    disable) rm -f "$enabled" ;;
    daemon-reload|start|stop) ;;
    *) echo "unexpected systemctl command: $command" >&2; exit 1 ;;
esac
STUB
chmod 755 /usr/bin/systemctl
enabled=/etc/systemd/system/network-online.target.requires/rs-l2tpd.service
mask=/etc/systemd/system/rs-l2tpd.service
printf 'enable\n' > "$RPM_TEST/preset"
: > "$RPM_TEST/actions"
rpm -K "$package"
test "$(rpm -qp --queryformat '%{NAME} %{ARCH}' "$package")" = 'rs-l2tpd x86_64'
test "$(rpm -qp --queryformat '%{RELEASE}' "$upgrade")" = "$(rpm -qp --queryformat '%{RELEASE}' "$package").test"
rpm -qp --configfiles "$package" | grep -qx /etc/rs-l2tpd.toml
rpm -qp --requires "$package" > "$RPM_TEST/requires"
grep -qx /bin/sh "$RPM_TEST/requires"
if grep -E 'libc\.so|ld-linux' "$RPM_TEST/requires"; then exit 1; fi
rpm -i --excludedocs "$package"
grep -qx 'start rs-l2tpd.service' "$RPM_TEST/actions"
test -L "$enabled"
/usr/sbin/rs-l2tpd --check
if /usr/sbin/rs-l2tpd --setup-systemd > "$RPM_TEST/installer.log" 2>&1; then exit 1; fi
test "$(stat -c '%a %u %g' /usr/sbin/rs-l2tpd)" = '755 0 0'
test "$(stat -c '%a %u %g' /usr/lib/systemd/system/rs-l2tpd.service)" = '644 0 0'
test "$(stat -c '%a %u %g' /etc/rs-l2tpd.toml)" = '644 0 0'
test "$(stat -c '%a %u %g' /etc/rs-l2tpd.toml.d)" = '755 0 0'
for document in README.md LICENSE-APACHE LICENSE-MPL THIRD-PARTY-NOTICES.txt \
    RUST-COPYRIGHT.html.gz RUST-LICENSES.txt MUSL-COPYRIGHT; do
    test -s "/usr/share/doc/rs-l2tpd/$document"
    test "$(stat -c '%a %u %g' "/usr/share/doc/rs-l2tpd/$document")" = '644 0 0'
done
grep -q 'Tokio Contributors' /usr/share/doc/rs-l2tpd/THIRD-PARTY-NOTICES.txt
gzip -t /usr/share/doc/rs-l2tpd/RUST-COPYRIGHT.html.gz
grep -q 'installation.html' /usr/share/doc/rs-l2tpd/README.md
grep -q 'rpmsave' /usr/share/doc/rs-l2tpd/README.md
grep -q 'ExecStart=/usr/sbin/rs-l2tpd ' /usr/lib/systemd/system/rs-l2tpd.service
rpm -V rs-l2tpd
printf 'daemon-reload \n' > "$RPM_TEST/reload-only"
: > "$RPM_TEST/actions"
rpm -U --replacepkgs "$package"
same "$RPM_TEST/actions" "$RPM_TEST/reload-only"
test -L "$enabled"
# The actual upgrade must preserve disabled state, local edits and fragments.
rm "$enabled"
printf '\n# operator main configuration\n' >> /etc/rs-l2tpd.toml
cp /etc/rs-l2tpd.toml "$RPM_TEST/edited"
printf '# operator fragment\n' > /etc/rs-l2tpd.toml.d/operator.toml
: > "$RPM_TEST/actions"
rpm -U "$upgrade"
printf 'daemon-reload \n' > "$RPM_TEST/reload-only"
same "$RPM_TEST/actions" "$RPM_TEST/reload-only"
test ! -L "$enabled"
same /etc/rs-l2tpd.toml "$RPM_TEST/edited"
grep -q 'changed defaults' /etc/rs-l2tpd.toml.rpmnew
test -s /etc/rs-l2tpd.toml.d/operator.toml
# A refused stop must be visible and leave the package installed.
printf 'stop\n' > "$RPM_TEST/fail"
if rpm -e rs-l2tpd > "$RPM_TEST/refused-erase.log" 2>&1; then exit 1; fi
rpm -q rs-l2tpd
test -x /usr/sbin/rs-l2tpd
rm "$RPM_TEST/fail"
: > "$RPM_TEST/actions"
rpm -e rs-l2tpd
printf 'stop rs-l2tpd.service\ndisable rs-l2tpd.service\ndaemon-reload \n' > "$RPM_TEST/erase-actions"
same "$RPM_TEST/actions" "$RPM_TEST/erase-actions"
test ! -e /etc/rs-l2tpd.toml
same /etc/rs-l2tpd.toml.rpmsave "$RPM_TEST/edited"
test -s /etc/rs-l2tpd.toml.d/operator.toml
# Reinstall reapplies presets; an unchanged main configuration is removed on erase.
: > "$RPM_TEST/actions"
rpm -i "$package"
grep -qx 'preset rs-l2tpd.service' "$RPM_TEST/actions"
grep -qx 'start rs-l2tpd.service' "$RPM_TEST/actions"
rpm -e rs-l2tpd
test ! -e /etc/rs-l2tpd.toml
same /etc/rs-l2tpd.toml.rpmsave "$RPM_TEST/edited"
test -s /etc/rs-l2tpd.toml.d/operator.toml
# Administrator masks survive first install, upgrade and removal.
mkdir -p "$(dirname "$mask")"
ln -s /dev/null "$mask"
: > "$RPM_TEST/actions"
rpm -i "$package"
test "$(readlink "$mask")" = /dev/null
if grep -E '^(preset|start) ' "$RPM_TEST/actions"; then exit 1; fi
: > "$RPM_TEST/actions"
rpm -U "$upgrade"
same "$RPM_TEST/actions" "$RPM_TEST/reload-only"
test "$(readlink "$mask")" = /dev/null
rpm -e rs-l2tpd
test "$(readlink "$mask")" = /dev/null
rm "$mask" /etc/rs-l2tpd.toml.d/operator.toml
rmdir /etc/rs-l2tpd.toml.d
# A disabled preset must not start the daemon, and an empty config directory goes away.
printf 'disable\n' > "$RPM_TEST/preset"
: > "$RPM_TEST/actions"
rpm -i "$package"
test ! -L "$enabled"
if grep -q '^start ' "$RPM_TEST/actions"; then exit 1; fi
# Scriptlet errors propagate even where RPM reports them after installing files.
printf 'daemon-reload\n' > "$RPM_TEST/fail"
if sh "$repo/musl-deb/rpm-postinst" 2 > "$RPM_TEST/refused-reload.log" 2>&1; then exit 1; fi
rpm -U --replacepkgs "$package" > "$RPM_TEST/refused-post.log" 2>&1 || :
grep -q 'scriptlet failed' "$RPM_TEST/refused-post.log"
rpm -q rs-l2tpd
rm "$RPM_TEST/fail"
rpm -e rs-l2tpd
test ! -d /etc/rs-l2tpd.toml.d
# Image/chroot installs apply presets without requiring a running systemd.
rmdir /run/systemd/system
: > "$RPM_TEST/actions"
rpm -i "$package"
if grep -E '^(start|stop|daemon-reload) ' "$RPM_TEST/actions"; then exit 1; fi
rpm -e rs-l2tpd
# No service manager is a supported install/removal path.
mv /usr/bin/systemctl "$RPM_TEST/systemctl"
if command -v systemctl >/dev/null 2>&1; then
    mv "$(command -v systemctl)" "$RPM_TEST/native-systemctl"
fi
: > "$RPM_TEST/actions"
rpm -i "$package"
test ! -s "$RPM_TEST/actions"
rpm -e rs-l2tpd
test ! -e /etc/rs-l2tpd.toml
test ! -d /etc/rs-l2tpd.toml.d
printf 'RPM_CONSUMER_RESULT=0\n'
