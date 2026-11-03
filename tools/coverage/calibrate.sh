#!/bin/sh
# Compile the oracle with the same branch instrumentation as the report.
set -eu
repo=$(CDPATH='' cd -P "$(dirname "$0")/../.." && pwd)
cd "$repo"
[ "$#" -eq 1 ] || { echo "usage: $0 RECORD" >&2; exit 2; }
mkdir -p "$1"
record=$(CDPATH='' cd -P "$1" && pwd)
scratch=$(mktemp -d /tmp/rs-l2tpd-coverage-calibration.XXXXXXXX)
trap 'rm -rf "$scratch"' 0
trap 'exit 1' HUP INT TERM
mkdir "$scratch/src"
cp tools/coverage/fixtures/conditions.rs "$scratch/src/conditions.rs"
checker=$repo/tools/coverage/target/debug/phase6-coverage
cargo build --locked --manifest-path tools/coverage/Cargo.toml
toolchain=nightly-2026-10-28
sysroot=$(rustc "+$toolchain" --print sysroot)
host=$(rustc "+$toolchain" -vV | sed -n 's/^host: //p')
llvm=$sysroot/lib/rustlib/$host/bin
rustc "+$toolchain" --edition=2024 -D warnings -C instrument-coverage -Z coverage-options=branch "$scratch/src/conditions.rs" -o "$scratch/fixture"
# Capture the first compiled mapping; later profiles must preserve it.

for mode in complementary both missing-arm missing-repeated; do
 LLVM_PROFILE_FILE="$scratch/$mode.profraw" "$scratch/fixture" "$mode"
 "$llvm/llvm-profdata" merge -sparse "$scratch/$mode.profraw" -o "$scratch/$mode.profdata"
 "$llvm/llvm-cov" export "$scratch/fixture" --instr-profile "$scratch/$mode.profdata" > "$record/$mode.json"
 "$llvm/llvm-cov" report "$scratch/fixture" --instr-profile "$scratch/$mode.profdata" --show-functions "$scratch/src/conditions.rs" > "$record/$mode-raw.log"
 "$llvm/llvm-cov" show "$scratch/fixture" --instr-profile "$scratch/$mode.profdata" --show-branches=count --show-instantiations > "$record/$mode-source.log"
 if [ "$mode" = complementary ]; then
  "$checker" snapshot "$scratch" "$scratch/sources.json" "$record/$mode.json"
  cp "$scratch/sources.json" "$record/sources.json"

 fi
 status=0
 "$checker" check "$scratch" "$scratch/sources.json" "$record/$mode.json" > "$record/$mode-merged.log" 2>&1 || status=$?

 case $mode in
  complementary|both)
   test "$status" -eq 0
   grep -qx 'MERGED_SOURCE_GATE=PASS' "$record/$mode-merged.log"
   ;;
  missing-arm|missing-repeated)
   test "$status" -eq 1
   grep -qx 'MERGED_SOURCE_GATE=FAIL' "$record/$mode-merged.log"
   ;;
 esac
done
# The unmerged generic copies each miss one source arm.
awk '/6choose/ {found++; if($7 != "80.00%" || $10 != "50.00%") exit 1}
 END {if(found != 2) exit 1}' "$record/complementary-raw.log"
awk '/6choose/ {found++; if($7 != "100.00%" || $10 != "100.00%") exit 1}
 END {if(found != 2) exit 1}' "$record/both-raw.log"
# Repeated match guards must keep their two independent conditions.
test "$(grep -c 'missing condition' "$record/missing-repeated-merged.log")" -eq 2
grep -q 'occurrence 0' "$record/missing-repeated-merged.log"
grep -q 'occurrence 1' "$record/missing-repeated-merged.log"
printf 'changed\n' >> "$scratch/src/conditions.rs"
status=0
"$checker" check "$scratch" "$scratch/sources.json" "$record/both.json" > "$record/changed-source.log" 2>&1 || status=$?
test "$status" -eq 2
grep -q 'source inventory or mappings changed' "$record/changed-source.log"

printf 'LLVM_COMPLEMENTARY_COPIES_REPEATED_CONDITIONS_MISSING_ARMS_AND_SOURCE_CHANGE_CALIBRATION_RESULT=0\n'
