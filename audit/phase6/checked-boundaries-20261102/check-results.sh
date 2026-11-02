set -eu
record=$PWD/audit/phase6/checked-boundaries-20261102
for label in noble resolute vanilla-6.8.12 vanilla-7.0.14 vanilla-7.4-rc1 noble-clock resolute-clock vanilla-6.8.12-clock vanilla-7.0.14-clock vanilla-7.4-rc1-clock ipv6-disable no-ipv6 no-ethernet; do
 [ "$(cat "$record/kernels/$label.exit")" = 0 ]
 grep -q '^MATRIX_GUEST_RESULT=0' "$record/kernels/$label/run.log"
 grep -q '^CONFORMANCE_RESULT=0' "$record/kernels/$label/run.log"
 grep -q '^SCENARIO_RESULT=0' "$record/kernels/$label/run.log"
 printf '%s: PASS\n' "$label"
done
grep -q '^ROOT_SYSTEMD_RESULT=0' "$record/root-systemd/run.log"
cmp "$record/publication/versions" audit/phase6/matrix-20261102T011736Z-3377142/initial/versions
printf 'CHECKED_THIRTEEN_KERNEL_PROFILES_AND_ROOT_SYSTEMD_RESULT=0\n'
