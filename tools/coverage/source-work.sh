#!/bin/sh
# Measure 500 dispatches before/after initialization with one fixed binary.
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 RECORD" >&2; exit 2; }
repo=$(CDPATH='' cd -P "$(dirname "$0")/../.." && pwd)
cd "$repo"
mkdir -p "$1"
record=$(CDPATH='' cd -P "$1" && pwd)
# Refuse reuse: a stale profile must not count toward a new qualification.
[ ! -e "$record/build.log" ] || { echo 'record already contains a build' >&2; exit 2; }
toolchain=nightly-2026-10-28
export CARGO_LLVM_COV_TARGET_DIR="$repo/target/source-work"
cargo build --locked --manifest-path tools/coverage/Cargo.toml --bin phase6-source-work > "$record/checker-build.log" 2>&1
cargo "+$toolchain" llvm-cov --locked --all-features --target x86_64-unknown-linux-gnu --no-report --test source-work -- --list > "$record/build.log" 2>&1
executable=$(awk -v root="$repo/" -v label='Running tests/source_work.rs (' '
 {at=index($0,label); if(at) {line=substr($0,at+length(label));sub(/[)]$/, "",line);print root line}}
' "$record/build.log")
[ -f "$executable" ] && [ -x "$executable" ] || { cat "$record/build.log"; echo 'missing work fixture executable' >&2; exit 1; }
sysroot=$(rustc "+$toolchain" --print sysroot)
host=$(rustc "+$toolchain" -vV | sed -n 's/^host: //p')
llvm=$sysroot/lib/rustlib/$host/bin
sha256sum "$executable" tests/source_work.rs tools/coverage/src/work.rs "$0" > "$record/source-and-binary.sha256"
checker=$repo/tools/coverage/target/debug/phase6-source-work
for repeat in 1 2 3 4 5 6 7 8 9 10; do
 for kind in calibration unrelated unchanged rename member address unrelated-address deletion; do
  baseline=0
  for count in 1 100 300; do
   output=$record/$repeat-$kind-$count
   mkdir "$output"
   PHASE6_WORK_BINDINGS=$count PHASE6_WORK_KIND=$kind PHASE6_WORK_RECORD=$output LLVM_PROFILE_FILE="$output/exit-%p-%m.profraw" "$executable" --ignored --exact measured_dispatch_work --nocapture > "$output/test.log" 2>&1
   grep -q 'test result: ok. 1 passed; 0 failed' "$output/test.log"
   for stage in before after; do
    "$llvm/llvm-profdata" merge -sparse "$output/$stage.profraw" -o "$output/$stage.profdata"
    "$llvm/llvm-cov" export "$executable" --instr-profile "$output/$stage.profdata" --compilation-dir "$repo" > "$output/$stage.json"
   done
   "$checker" "$repo" "$output/before.json" "$output/after.json" > "$output/work.log"
   observed=$(sed -n 's/^SOURCE_WORK_REGION_EXECUTIONS=//p' "$output/work.log")
   case $observed in ''|*[!0-9]*) echo 'invalid work total' >&2; exit 1 ;; esac
   [ "$observed" -gt 0 ]
   if [ "$count" -eq 1 ]; then baseline=$observed; fi
   if [ "$kind" = calibration ]; then expected=$((baseline * count)); else expected=$baseline; fi
   if [ "$observed" -ne "$expected" ]; then
    echo "work curve differs: repeat=$repeat kind=$kind bindings=$count observed=$observed expected=$expected" >&2
    exit 1
   fi
   printf 'repeat=%s kind=%s bindings=%s region_executions=%s\n' "$repeat" "$kind" "$count" "$observed"
   # The exports retain all counters; remove redundant runtime buffers.
   xz "$output/before.json" "$output/after.json"
   rm "$output/before.profraw" "$output/after.profraw" "$output/before.profdata" "$output/after.profdata" "$output"/exit-*.profraw
  done
 done
done
sha256sum -c "$record/source-and-binary.sha256" > "$record/final-identity.log"
printf 'TEN_SOURCE_WORK_CURVE_REPETITIONS_RESULT=0\n'
