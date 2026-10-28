# Observability

[Specification index](README.md)

## Logging

O1. The library logs through the `log` facade; the binary writes to
standard error at information level, or debug level with `--verbose`,
one line per message in the form `LEVEL target: message`, the target
being the module, with no timestamp (the journal and every supervisor
add one). No environment variable changes the level; `--verbose` is the
only knob.

O2. Severity is fixed by context and condition:

| Context | Condition | Level |
|---|---|---|
| Start-up | an entry left out for a hard mistake | error |
| Start-up, reload | a tolerated mistake; an unknown key | warning |
| Start-up | a required capability the process does not hold ([R49](requirements.md#the-host)), once per capability, naming it and what degrades | warning |
| Reload | an entry with a hard mistake keeping its values; a new entry left out | warning |
| Reload | the whole reload refused | error |
| Any | a condition the daemon is working around: a disconnected tunnel with a pending peer, an absent bind device, an unmanageable device, a left-out entry, a lost subscription, a deferred change, a skipped change, a resolver that does not answer, a host tunable set back | warning |
| Any | a host defect ([M13](model.md#failure-classes)) | error, once |
| Any | a defect of the daemon ([M13](model.md#failure-classes)) | error |
| Any | a change applied, an obstacle overcome, readiness, a reload completed, a shutdown step | information |
| Any | everything that happens every second, and a changed errno within an episode | debug |

O3. A lasting condition is reported once when it begins and once when it
ends, never on every retry. An episode is keyed by the entry and the
condition; a reload that changes the entry's relevant values starts a new
episode, a retry does not. In particular the one-second retries of
pending peers, incomplete reconciles, failed reconnects and left-out
entries are silent after their first report. One exception: a deferred
hardware-address change ([S12](sessions.md#hardware-addresses)) is
reported at every reconcile that carries it, so that an operator who
reloads sees why the address did not apply.

O4. Every message about an entry names it by its identifiers
(`tunnel_id=`, `session_id=`) and by its configuration name; where it
comes from the configuration, also by the field at fault. When the
identifier is what is missing or invalid, the configuration name and the
field stand alone.

O5. Cookies are never logged, at any level, in any error message, in any
diagnostic; a cookie's `Debug` form gives its length only. The one place
a cookie value appears is the standard output of `--check`
([O8](#check-mode)), which renders the operator's own input. Hardware
addresses, peers and names are logged.

O6. Messages from the kernel are passed through with their errno names, so
that `ENETUNREACH`, `EEXIST` and the like can be searched for.

## Exit codes

O7. The parent process exits 0 when the daemon is ready and 1 when it
failed before readiness or was asked to shut down before readiness. The
daemon exits 0 after a complete shutdown, 1 when a shutdown step failed
and 2 when the reload callback panicked. A reload callback that returned an
error, and every other recovered condition, leaves the exit code of a
later clean shutdown at 0. `--check` exits 0 with no problem and 1 with
any, unknown keys included.

## Check mode

O8. `--check` prints the configuration that would be applied, rendered as
TOML with the same keys the files use, tolerated mistakes already
corrected (no peer for an unusable endpoint, no hardware address for an
unusable one), left-out entries absent, in a fixed order so that the
output can be compared: the tables `host`, `resolvers`, `tunnels`,
`sessions`; entries in ascending byte order of their names; keys in the
order of the tables of [C7](configuration.md#tunnel-entries),
[C8](configuration.md#session-entries), [C16](configuration.md#resolver-entries)
and [C17](configuration.md#host-settings); defaults the files did not
write are not printed; and reports every problem on
standard error in the same words the daemon would log at start-up. It
makes no kernel request and writes no tunable. Thus it reports static
configuration problems only; device kind, availability, MAC and VRF
membership conditions are evaluated and reported at runtime (C16, T27).

## State visible on the host

O9. The daemon's objects are recognisable on the host: tunnels by their
identifiers in `ip l2tp show tunnel`, with the peer and source while
connected and, while disconnected, the previous peer or none and an empty
source ([K25](kernel.md#facts)); sessions by their identifiers and, in the
kernel's record, the creation-time interface name; staged sessions by
their `rsl2tp-t` names and renames in progress by `rsl2tp-r` names.
Whether a tunnel is connected is reported by the daemon's own log, not
derivable from the kernel's record alone. The PID file holds the daemon's
PID followed by a newline. No other object of the daemon's exists on the
host.
