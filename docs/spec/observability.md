# Observability

[Specification index](README.md)

## Logging

O1. The library logs through the `log` facade; the binary writes to
standard error at information level, or debug level with `--verbose`.

O2. Levels: a configuration entry left out is an error; a tolerated
mistake, a condition the daemon is working around (a pending peer, an
unmanageable device, a left-out entry, a lost subscription, a repair
failure) is a warning; a change applied, an obstacle overcome, readiness,
a reload completed and a shutdown step is information; everything that
happens every second is debug.

O3. A lasting condition is reported once when it begins and once when it
ends, never on every retry. In particular the one-second retries of
pending peers, incomplete reconciles, failed reconnects, left-out entries
and route repairs are silent after their first report.

O4. Every message about an entry names it by its identifiers
(`tunnel_id=`, `session_id=`) and, where it comes from the configuration,
by its configuration name and the field at fault.

O5. Cookies are never logged, at any level, in any error message; a
cookie's `Debug` form gives its length only. Hardware addresses, peers and
names are logged.

O6. Messages from the kernel are passed through with their errno names, so
that `ENETUNREACH`, `EEXIST` and the like can be searched for.

## Exit codes

O7. The parent process exits 0 when the daemon is ready and 1 when it
failed before readiness or was asked to shut down before readiness. The
daemon exits 0 after a complete shutdown and non-zero when a shutdown step
failed or the reload callback failed. `--check` exits 0 with no problem
and 1 with any.

## Check mode

O8. `--check` prints the configuration that would be applied, rendered as
TOML with the same keys the files use, tolerated mistakes already
corrected (the discard address as peer, no hardware address), left-out
entries absent; and reports every problem on standard error in the same
words the daemon would log at start-up. It makes no kernel request.

## State visible on the host

O9. The daemon's objects are recognisable on the host: tunnels by their
identifiers in `ip l2tp show tunnel`, with the current peer (a discard
address while there is none); sessions by their identifiers and, in the
kernel's record, the creation-time interface name; null devices by their
`rsl2tpnull` names and their routes by their prefixes. The PID file holds
the daemon's PID followed by a newline.
