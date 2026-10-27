# Library

[Specification index](README.md)

The crate is a library with a thin binary on top. Everything the binary
does with the kernel, the library does; the binary adds files, logging
output, signals, daemonisation, the PID file and the installer.

## Boundaries

L1. The library reads no file, writes to no terminal, installs no signal
handler and assumes no serialisation format. Configuration types
deserialise through serde when the `serde` feature is on, from any format;
TOML, the command line and the logger implementation belong to the binary
behind the `bin` feature.

L2. Unsafe code is denied in the library. Every kernel interaction goes
through netlink and socket crates.

L3. No type of another crate appears in the public API without being
re-exported next to its use, so that no dependency of a matching version is
needed to name it. Public types keep private fields with builders and
getters; enums are non-exhaustive; adding a variant, a field or a method is
not a breaking change.

## Configuration types

L4. A `Config` is always valid: every constructor and insertion validates
([configuration](configuration.md)), so a configuration obtained in code,
by strict deserialisation or by lenient conversion satisfies the same
rules. The lenient conversions return every problem with its kind, name,
effect and error.

## The service

L5. `Service` is the daemon minus process management: created with a
configuration, it opens the kernel interfaces; `converge` applies the
configuration, retrying every second until it is applied or a shutdown is
requested, handling kernel and DNS events meanwhile and ignoring reloads;
`run` then handles events, reloads through a caller-supplied callback and
shutdown, removes everything at shutdown and returns.

L6. `Control` is a cloneable handle usable from any thread: `reload` never
waits and fails when the queue is full, `reload_wait` waits for room,
`shutdown` never fails for lack of room because it is a separate persistent
request that wins over queued reloads. `config` returns the configuration
being applied.

L7. The reload callback runs on a thread that may block; its error is
logged and the previous configuration kept; its panic ends the service with
an error after cleanup.

L8. `blocking::Service` offers the same on a runtime of its own, on its
own thread, so that a program without Tokio, or inside another Tokio
runtime, can call `converge` and `run` as ordinary blocking functions.
Dropping it stops the thread and removes everything.

## The reconciler

L9. `Runtime` is the reconciler underneath, for programs that drive the
event loop themselves: `new` opens the kernel interfaces and starts the
watchers, which send `ControlEvent`s to a channel the program reads;
`reconcile` applies a configuration and reports whether anything is still
unapplied; each `handle_*` method applies one kind of event; `shutdown`
removes everything. Dropping a `Runtime` stops its tasks and closes the
tunnel sockets, which tears the tunnels down without order; `shutdown`
first is the orderly way.

L10. The program MUST forward every event the runtime sends to the
handler of its kind, in order; it MAY drop none. Events it does not
recognise, from a newer version, are forwarded all the same through the
non-exhaustive match's wildcard arm, which does nothing.

## Errors

L11. Errors are one non-exhaustive enum: an invalid configuration with a
message, a kernel or socket error carried from the L2TP crate with its
errno, and other failures with a message. No operation panics on bad
input; every kernel refusal is an error value.
