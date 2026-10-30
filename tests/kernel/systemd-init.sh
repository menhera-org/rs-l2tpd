#!/bin/sh
# PID 1 bootstrap only in the root systemd QEMU fixture.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
set -eu
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /dev/pts /run
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /run
mount -t cgroup2 cgroup2 /sys/fs/cgroup
chmod 1777 /tmp
uname -a
printf 'GUEST_KERNEL_RELEASE=%s\n' "$(uname -r)"
depmod -a
# Leave netlink and Ethernet unloaded: the test proves kernel autoload,
# then temporarily refuses it to withhold the unit's readiness.
modprobe l2tp_ip
modprobe l2tp_ip6
printf '%s\n' phase6 > /etc/hostname
printf '%s\n' 11111111111111111111111111111111 > /etc/machine-id
printf '%s\n' 'nameserver 127.0.0.1' > /etc/resolv.conf
mkdir -p /etc/systemd/system/multi-user.target.wants /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/phase6.conf <<'JOURNAL'
[Journal]
Storage=volatile
ForwardToConsole=yes
MaxLevelConsole=debug
JOURNAL
cat > /etc/systemd/system/phase6-probe.service <<'UNIT'
[Unit]
Description=Phase 6 root systemd assertions
After=basic.target systemd-networkd.service systemd-udevd.service
Wants=systemd-networkd.service systemd-udevd.service
OnSuccess=phase6-finish.service
OnFailure=phase6-finish.service
[Service]
Type=simple
Environment=RS_L2TPD_ROOT_SYSTEMD=1
ExecStart=/phase6-probe
StandardOutput=journal+console
StandardError=journal+console
UNIT
cat > /etc/systemd/system/phase6-finish.service <<'UNIT'
[Unit]
Description=Record the Phase 6 result and power off the disposable guest
After=phase6-probe.service
[Service]
Type=oneshot
ExecStart=/phase6-finish
StandardOutput=journal+console
StandardError=journal+console
UNIT
cat > /phase6-probe <<'PROBE'
#!/bin/sh
result=0
/systemd-scenarios --ignored --exact supplied_unit_enforces_mounts_capabilities_ordering_store_and_cleanup --nocapture > /run/phase6-result.log 2>&1 || result=$?
cat /run/phase6-result.log
grep -q 'test result: ok. 1 passed;' /run/phase6-result.log || result=1
exit "$result"
PROBE
chmod 755 /phase6-probe
cat > /phase6-finish <<'FINISH'
#!/bin/sh
journalctl --no-pager -n 1000 -u rs-l2tpd.service -u phase6-probe.service
result=$(systemctl --no-pager show phase6-probe.service --value -p ExecMainStatus)
printf '\nROOT_SYSTEMD_RESULT=%s\n' "$result" > /dev/console
systemctl --no-pager poweroff --force
FINISH
chmod 755 /phase6-finish
ln -sf ../phase6-probe.service /etc/systemd/system/multi-user.target.wants/phase6-probe.service
ln -sf /lib/systemd/system/multi-user.target /etc/systemd/system/default.target
exec /lib/systemd/systemd --system --log-target=console
