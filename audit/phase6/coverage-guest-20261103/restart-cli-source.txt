#!/bin/sh
# Successful CLI restart of a real daemon in a disposable test namespace.
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 BINARY" >&2; exit 2; }
[ "${RS_L2TPD_SCENARIO_CONTAINER-}" = 1 ] || { echo 'requires an isolated test container or guest' >&2; exit 2; }
binary=$1
case $binary in /*) ;; *) binary=$PWD/$binary ;; esac
test -f "$binary" && test -x "$binary"
scratch=$(mktemp -d /tmp/rs-l2tpd-cli-restart.XXXXXXXX)
child=
cleanup() {
 status=$?
 trap - 0
 if [ -n "$child" ]; then
  kill -TERM "$child" 2>/dev/null || :
  wait "$child" || :
 fi
 cat "$scratch/daemon.log" 2>/dev/null || :
 rm -rf "$scratch"
 exit "$status"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
printf '[host]\nfix_bindv6only=false\n' > "$scratch/config.toml"
"$binary" --foreground --config "$scratch/config.toml" --config-dir "$scratch/absent" > "$scratch/daemon.log" 2>&1 &
child=$!
# The shell is the init system and owns this PID file (P22/P27).
printf '%s\n' "$child" > "$scratch/pid"
chmod 600 "$scratch/pid"
# The child expands its own log argument after timeout starts it.
# shellcheck disable=SC2016
timeout 10 sh -c '
 until grep -q "ready pid=" "$1"; do sleep 1; done

' sh "$scratch/daemon.log"
"$binary" --restart --pid-file "$scratch/pid"
# The child expands its own log argument after timeout starts it.
# shellcheck disable=SC2016
timeout 10 sh -c '
 until grep -q "re-exec resumed" "$1"; do sleep 1; done

' sh "$scratch/daemon.log"
kill -TERM "$child"
status=0
wait "$child" || status=$?
child=
test "$status" -eq 0
grep -q 'shutdown complete' "$scratch/daemon.log"
if grep -q 'LLVM Profile Error' "$scratch/daemon.log"; then exit 1; fi
printf 'REAL_DAEMON_CLI_RESTART_AND_SHUTDOWN_RESULT=0\n'
