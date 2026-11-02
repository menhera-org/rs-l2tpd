# Competing state and input boundaries

This batch extends signed `2eaa987`. Production function bodies remain
unchanged. The collector covers **8,597/8,687 lines (98.96%)** and
**1,783/1,852 branch outcomes (96.27%)**: eight more lines and eighteen
outcomes than the preceding report. **90 lines and 69 outcomes remain
uncovered.** There are no production exclusions, profile mismatches or
saturated regions.

All 4,331 previous function mappings remain unchanged. A non-map input
adds one UnknownKeys deserializer instantiation, bringing the count to
4,332. The line/branch denominators remain unchanged. The edited production
prefixes compare byte-for-byte with `revision`. Earlier production
implementations are not merged.

The new model cases cover competing session names when removal fails,
an already satisfied competing name, replacement of a zone's interface
index without changing its peer, and timer-driven verification after a
tunnel lookup fails. The name test retains a queued rename failure to
detect an extra attempt; the timer test requires its queued lookup failure
to be consumed. Other cases cover an unwanted record's update guard,
a late tunable acknowledgement during shutdown and a closed service queue.

Private configuration fixtures check refusal of an invalid retained resolver,
a diagnostic whose session entry is absent and rejection of a non-map
deserializer. The fake-kernel fixture checks a replaced link's ownership
and a tunnel without a known socket. These private-state fixtures establish
model bookkeeping and defensive conversion behavior.

The binary fixtures cover SIGHUP and SIGUSR2 while the service queue is
full, a regular file at an installation directory, additional malformed
re-exec announcements and a PID file growing after its metadata check.
The growth fixture stops its own disposable worker before reading, then
supplies a 33-byte number naming an owned child. It checks the exact refusal
and that the child receives only the fixture's cleanup signal.

The root process fixture checks that failure to read the source binary
prevents enablement while later installation stages still run. It also
checks refusal of a PID file owned by another uid. The report-count fixture
checks one IPv6-unavailable warning across two tunnels and repeated retries.

Final common gates, Rust 1.89 and three additional musl architecture compile
checks pass. Ten final instrumented repetitions cover the selected ordinary
model, daemon and process suites; three final musl repetitions cover the
same selected suites. An earlier qualification preceded a stronger timer
assertion and retains its own logs/source snapshot.

Three stable GNU and three stable musl container repetitions each pass the
75 ordinary daemon cases, three selected filesystem cases and all 34 process
cases. Three further GNU instrumented container repetitions pass that scope
and export independent profile filenames. Existing ignored profiles retain
their earlier recorded scope.

All five focused guest profiles pass: Ubuntu 6.8.0-147.147 and 7.0.0-42.42,
vanilla 6.8.12 and 7.0.14, and mainline 7.4-rc1. Each passes 75 ordinary daemon
cases, three filesystem cases, both signal task-limit variants, twelve
ordinary process cases and the expanded root installer case. The private
init addition is isolated in `guest-fixture.patch`; it extends the binary
profile with those process fixtures. `guest-source.patch` includes it,
against `guest-base-revision`; the shipping Rust/test sources otherwise
compare identically. This scope preserves the existing thirteen-profile
matrix's qualification of unchanged production bodies.

An attempted full normal rerun reused the shorter binary profile's
600-second outer wrapper. Ubuntu's final markers appeared after that
wrapper timed out; it is not a passing run. The 6.8.12 attempt was then
deliberately stopped to correct the scope. Both rejected records and their
commands remain. The focused profile retains a bounded 600-second wrapper.
An initial instrumented-container launch used a relative executable path;
the corrected launch uses absolute paths. The initial installer control
failed before its intended assertion because an unprivileged child could
not traverse the private checkout; mounting its build directory at the
embedded path fixes that fixture. These rejected attempts are not
determinism passes.

Ten restored mutations fail at their intended runtime assertions:

- Ignore a name already acquired by the first pending session.
- Stage a competing owner already at its desired name.
- Discard a reload when its queue is full.
- Accept a PID file growing beyond the post-read limit.
- Remove a link belonging to another session.
- Report IPv6 unavailability for every tunnel.
- Ignore a changed zone index.
- Skip the timer's tunnel-verification lookup.
- Treat a closed service queue as a successful convergence.
- Enable the service after binary installation failed.

The control scripts and source patches retain the exact mutations. Two
control-log matchers initially expected the wrong diagnostic; the runtime
assertions themselves detected their mutations. The corrected continuation
checks those actual diagnostics. All control sources are restored.

The fresh publication list matches the sealed matrix's required set.
Signed `2eaa987` passes both CI jobs and CodeQL; the preceding run records
are retained. This batch's own push CI is checked after publication.

Affected logs encode NUL as `<NUL>`, with checked reconstruction and raw
Git identities in `nul-encoding.log`. Cargo build durations are removed.
This package establishes no new Incus/root-unit scope. The 100% gate and
complete clause/history/resource/event-cost proof remain open.
