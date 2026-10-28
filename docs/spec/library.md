# Library

[Specification index](README.md)

The crate is a library with a thin binary on top. Everything the binary
does with the kernel, the library does; the binary adds files, logging
output, signals, daemonisation, the PID file, the host tunable write and
the descriptor hand-over.

## Boundaries

L1. The library owns no configuration and no process policy. It does no
standard I/O (it reads no standard input and writes no standard output
or standard error), no file I/O, reads no configuration and no
environment variable, installs no signal handler, writes no kernel
tunable, and assumes no serialisation format. Kernel interfaces are its
business: sockets, netlink, and the kernel's special filesystems where a
rule names them, which today is `/proc` through its namespace dependency
([K12](kernel.md#requirements)). The one other exception is what the libc
resolver reads for the system resolver ([V3](resolvers.md#model)), which
is the libc's doing, not the library's. It is acceptable because even
the most constrained hosts the daemon targets let the libc read it (a
statically linked musl binary reads `/etc/resolv.conf` even in an
Android app's context), and because the configured resolvers
([resolvers](resolvers.md)) are the alternative wherever the system
resolver is unwanted or unusable.
Configuration types deserialise through serde when the `serde` feature is
on, from any format; TOML, the command line and the logger implementation
belong to the binary behind the `bin` feature.

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
effect and error ([C15](configuration.md#library-conversions)).

## The service

L5. `Service` is the daemon minus process management: created with a
configuration and an optional list of adopted descriptors (each an
`OwnedFd` with the tunnel identifier the program read from
`LISTEN_FDNAMES`, [P14](process.md#restart)), it opens the kernel
interfaces and returns an error at once when it cannot, leaving the
retry of [P5](process.md#start-up) to the caller, and verifies each
adopted descriptor as P14 says; `converge` applies the configuration, retrying every second until
every eligible entry exists or a shutdown is requested, handling kernel
and resolver events meanwhile and ignoring reloads, and returns with the
list of entries left out for conflicts; `run` then handles events,
reloads through a caller-supplied callback and shutdown, removes
everything at shutdown and returns. Calling `run` without `converge`
first converges first.

L6. `Control` is a cloneable handle usable from any thread: `reload` never
waits and fails when the queue is full, `reload_wait` waits for room,
`shutdown` never fails for lack of room because it is a separate persistent
request that wins over queued reloads. `restart` requests the restart of
[P26](process.md#restart): the service finishes the operation in
progress, stops its timers and calls the program's restart callback with
the tunnel descriptors to hand over; the program execs, and if the
callback returns (the exec failed) the service resumes. Requests accepted
through the handle are processed in order of acceptance, one at a time.
`config` returns the accepted configuration.

L7. The reload callback runs on a thread that may block; its error is
logged and the previous configuration kept; its panic ends the service with
an error after cleanup; a shutdown does not wait for a blocked callback
([P13](process.md#signals-and-requests)).

L8. `blocking::Service` offers the same on a runtime of its own, on its
own thread, so that a program without Tokio, or inside another Tokio
runtime, can call `converge` and `run` as ordinary blocking functions.
Dropping it, before or after `run`, performs the shutdown of
[P16](process.md#shutdown) and removes everything.

## The reconciler

L9. `Runtime` is the reconciler underneath, for programs that drive the
event loop themselves: `new` opens the kernel interfaces (failing at once
when it cannot) and starts the watchers, which send `ControlEvent`s to a
channel the program reads; `reconcile` applies a configuration and reports
whether anything is still unapplied; `handle_event` applies one event of
any kind; `shutdown` removes everything. Dropping a `Runtime` stops its
tasks and closes the tunnel sockets, which tears the tunnels down without
order; `shutdown` first is the orderly way.

L10. The program MUST hand every event the runtime sends to
`handle_event`, in order, and MAY drop none. `handle_event` dispatches
every variant, including variants added in a newer version, so that a
program compiled against an older version forwards them unchanged; the
per-kind `handle_*` methods exist for programs that want to observe or
filter one kind and are not required.

L12. The runtime never writes a kernel tunable. When
[P25](process.md#host-tunables) calls for a write, the runtime sends an
event naming the tunable and the value; the program (the binary, in the
daemon) performs the write and reports the outcome through the control
handle; until it does, or when it reports failure, the runtime proceeds
as with the option off ([T26](tunnels.md#hosts-with-bindv6only)).

L13. The runtime never speaks to a descriptor store. It sends
`StoreSocket { tunnel_id, fd }` when a tunnel exists and
`ForgetSocket { tunnel_id }` before it closes a tunnel's socket; the
program (the binary, in the daemon) performs the store operation of
[P14](process.md#restart) where a store exists and reports the outcome
through the control handle. The close of a socket waits for the answer
to its `ForgetSocket`, bounded by the two seconds of
[T8](tunnels.md#creation-and-identifiers); without a store the program
answers at once.

## Errors

L11. Errors are one non-exhaustive enum: an invalid configuration with a
message, a kernel or socket error carried from the L2TP crate with its
errno, and other failures with a message. No operation panics on bad
input; every kernel refusal is an error value.
