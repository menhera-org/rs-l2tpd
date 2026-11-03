#!/bin/sh
# Counts refer to one fixed binary and 500 delivered events per case.
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 RECORD PREFIX" >&2; exit 2; }
record=$1; prefix=$2
value() {
 number=$(sed -n 's/^SOURCE_WORK_REGION_EXECUTIONS=//p' "$1/work.log")
 case $number in ''|*[!0-9]*) echo 'invalid work total' >&2; exit 1 ;; esac
 [ "$number" -gt 0 ]
 printf '%s\n' "$number"
}
for kind in calibration unrelated unchanged rename; do
 baseline=$(value "$record/$prefix-$kind-1")
 for count in 100 300; do
  observed=$(value "$record/$prefix-$kind-$count")
  if [ "$kind" = calibration ]; then expected=$((baseline * count)); else expected=$baseline; fi
  if [ "$observed" -ne "$expected" ]; then
   echo "work curve differs: kind=$kind bindings=$count observed=$observed expected=$expected" >&2
   exit 1
  fi
 done
done
printf 'SOURCE_WORK_CALIBRATION_AND_CONSTANT_DISPATCH_CURVES_RESULT=0\n'
