set -eu
record=$PWD/audit/phase6/current-head-qualification-20261101
mkdir "$record"
git --no-pager rev-parse HEAD > "$record/revision"
git --no-pager diff HEAD -- src tests Cargo.toml Cargo.lock build.rs > "$record/source.patch"
cp audit/phase6/lifetime-completion-20261101/native.log "$record/native.log"
uname -r > "$record/kernel"
PHASE6_COVERAGE_RECORD=$record sh audit/phase6/process-errors-20261031/run-live.sh > "$record/gnu-live.log" 2>&1
PHASE6_COVERAGE_RECORD=$record sh audit/phase6/coverage-simplify-20261031/run-incus-normal.sh > "$record/gnu-incus.log" 2>&1
for repeat in 1 2 3; do
 tests/docker/run.sh scenarios > "$record/musl-scenarios-$repeat.log" 2>&1
 tests/docker/run.sh incus > "$record/musl-incus-$repeat.log" 2>&1
done
git --no-pager diff HEAD -- src tests Cargo.toml Cargo.lock build.rs > "$record/final-source.patch"
cmp "$record/source.patch" "$record/final-source.patch"
test ! -s "$record/source.patch"
printf 'CURRENT_HEAD_HOST_QUALIFICATION_RESULT=0\n'
