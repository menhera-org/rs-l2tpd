# Process

[Specification index](README.md)

## Start-up

P1. The daemon is started before the network is ready and MUST work in
that condition: no DNS, no default route, no route to any peer, no address
on any interface, bind devices not created yet, no IPv6, a VRF whose
default route is unreachable. None of these delays the creation of the
tunnels and session interfaces ([degradation ladder](model.md#the-degradation-ladder)):
a tunnel that cannot reach its peer is created disconnected
([T16](tunnels.md#peers-that-cannot-be-reached)).

P2. Start-up order: change directory to `/`, initialise logging, parse the
command line, load the configuration leniently
([C10](configuration.md#start-up)), report every problem, then daemonise
and apply. A configuration problem never prevents start-up; an empty
configuration is valid and makes the daemon ready at once.

P3. `--check` loads the configuration the same way, prints the
configuration that would be applied, reports every problem, exits 1 if
there was any and 0 otherwise, and touches nothing else: no socket, no
device, no tunable, no PID file ([O8](observability.md#check-mode)).

P4. The daemon double-forks. The grandchild applies the configuration; the
original parent waits and exits 0 when the grandchild reports readiness,
or 1 when it reports failure or dies. The intermediate child exits at once.
The grandchild uses a restrictive umask and creates only its PID file and
the directories of that file.

P5. The kernel interfaces (netlink, L2TP generic netlink) are opened before
the configuration is applied, and the host tunable of [P25](#host-tunables)
is checked then. Failing to open them is a host defect
([M13](model.md#failure-classes)): reported, readiness withheld, retried.

## Readiness

P6. Readiness means that every entry eligible for it
([terms](model.md#terms)) exists in the kernel: every tunnel of the
accepted configuration, connected or not, and every session, under its
configured name or still under its temporary name, with or without a
deferred hardware-address change. Readiness is reported exactly once, by
the parent exiting 0 and the PID file appearing; with the supplied unit
this releases `network-online.target`. It is never revoked: later
degradation is reported, not signalled.

P7. Readiness MUST NOT wait for: a host name to resolve, a route to a
literal or resolved peer, a source address, an absent bind device, IPv6,
a deferred hardware-address change, a session's publication under its
configured name, a session interface another manager already configured,
or an entry whose identifiers are held elsewhere once the bounded retries
are spent.

P8. Readiness MAY wait for: the bounded conflict retries (at most ten
seconds per entry, run concurrently with the rest), and a kernel that
cannot create the objects at all.

P9. Until readiness, failed creations are retried every second. Kernel and
resolver events are handled meanwhile, so a device appearing or a name
resolving during a slow start is not lost. Reload requests before
readiness are ignored; the files are read again at the next reload after
readiness.

## PID file

P10. The PID file is published only after readiness, as a fresh inode owned
by the daemon user, replacing any previous file atomically. Its directories
MUST be owned by root or the daemon user; the daemon MUST NOT change their
permissions and only warns when other users could replace the file. In a
directory it cannot write to, a pre-created file is updated in place only
if the daemon user owns it, it has one link and no group or other write
permission, and it is still the inspected inode when opened. Symbolic links
in the file's place are refused; trusted directory symlinks are followed.
The daemon remembers the inode it published.

P11. At shutdown the PID file is removed only if the pathname still
denotes the inode the daemon published; a file another instance or
process put there is left alone, with a warning. A stale file from a
crash is replaced at the next start. Publication happens before the
parent is told to exit; if publication fails the daemon reports it, keeps
running, and the parent still exits 0, because readiness is a fact about
the kernel, not about the file.

## Signals and requests

P12. `SIGHUP` requests a reload, `SIGTERM` and `SIGINT` a shutdown,
`SIGUSR2` a restart ([P26](#restart)). A signal is a request to reload
the latest files, to shut down or to restart, not a counted event: several `SIGHUP`s before the daemon acts cause one reload
of the files as they are then. A reload request the signal thread has
observed MUST NOT be lost: the thread waits for queue capacity, and a
shutdown request bypasses that wait through the persistent flag
([A6](architecture.md#concurrency)). A shutdown request takes precedence
over queued reloads; a second shutdown request during shutdown changes
nothing. Reloads are serialised: one at a time, in order of acceptance.
Requests through the control handle are counted and ordered as
[L6](library.md#the-service) says.

P13. A reload reads the files again, converts them against the accepted
configuration ([C12](configuration.md#reload)), replaces the accepted
configuration if the result is acceptable, and reconciles. A reload whose
reconcile is incomplete is retried every second until complete; a new
reload replaces it. The reload callback runs on a thread that may block;
a shutdown during a blocked callback proceeds without waiting for it, and
its result, if it ever returns, is discarded. A reload callback that
returns an error keeps the previous configuration and is logged; one that
panics ends the daemon with an error, after the kernel objects were
removed.

## Restart

P14. Stopping the daemon removes everything it owns ([P16](#shutdown)). A
restart therefore re-creates every interface and with them their
addresses, routes and children. Where the init system offers a
descriptor store (systemd's `FDSTORE`), the daemon SHOULD, on a restart
or upgrade, hand its tunnel sockets to the store on exit and adopt them
again at the next start, so that the tunnels, the sessions and their
interfaces survive; this is the one exception to [G9](promises.md#unconditional-promises)
and the adoption the one exception to [G2](promises.md#unconditional-promises).
The hand-over is used only when the init system announces the store to
the process; it needs no configuration key, no systemd on hosts without
it, and no file. The daemon speaks the protocol itself, through the
`NOTIFY_SOCKET`, `LISTEN_FDS`, `LISTEN_PID` and `LISTEN_FDNAMES`
environment variables and a datagram carrying `FDSTORE=1` with the
descriptors, and MUST NOT link against libsystemd or any D-Bus library:
the same binary runs on a host without systemd, where the hand-over is
simply absent. An adopted socket is verified to carry the tunnel of the
same identifiers before it is used; one that does not is closed. An
explicit stop MUST still remove everything, and the store MUST be told to
forget the sockets then (`FDSTOREREMOVE=1`).

P26. On every host, with or without a descriptor store, the daemon
provides a **restart** operation of its own, so that a new binary on disk
replaces the running one without re-creating the tunnels: on a restart
request (`SIGUSR2`, or the control handle; the binary MAY offer a
command-line form that signals the PID of the PID file), the daemon
executes the binary again in the same process, with its tunnel sockets
inherited as descriptors 3 and up and announced to the new program through
the same `LISTEN_FDS`, `LISTEN_PID` and `LISTEN_FDNAMES` protocol as
[P14](#restart), which is the indirection between the two programs. Rules:

- The program executed is the one at the path the daemon was started
  with, or the path given on the command line, never `/proc/self/exe`,
  which names the old inode once the file on disk was replaced.
- Close-on-exec ([T6](tunnels.md#creation-and-identifiers)) is cleared
  only on the descriptors being handed over and only for this exec; every
  other descriptor (netlink, resolvers, the readiness pipe) closes with
  the exec and is opened anew.
- The process, its PID and the PID file stay the same, so every init
  system keeps supervising the same process ([P22](#the-process-contract)).
- The new instance reads the configuration files afresh, verifies every
  adopted socket as in [P14](#restart), closes those it cannot verify,
  and reconciles; a tunnel of the accepted configuration that was not
  handed over is created as at start-up. Readiness is not signalled
  again: there is no parent to tell.
- If the exec fails, the old instance continues unchanged, restores
  close-on-exec, and reports the failure; if the new program dies before
  adopting, the kernel closes the sockets and removes the tunnels, and
  the init system restarts the daemon as after any crash.
- A restart request before readiness, or during a shutdown, is ignored
  with a report.

Where a descriptor store exists, the restart operation and the store are
independent: the operation works the same, and the store additionally
keeps the sockets across an unplanned exit.

P15. After a restart the daemon MUST reach the applied state at least as
fast as after a first start, and the configuration MUST NOT need to
change for the restart to succeed.

## Shutdown

P16. Shutdown, in order: stop every timer; apply the empty configuration
under the ordering rules of [M6](model.md#reconciliation), which deletes
every owned session the daemon can prove it owns and then every tunnel by
closing its socket (or handing it over, [P14](#restart)); remove the PID
file ([P11](#pid-file)); exit. A session the daemon cannot prove it owns
is left alone ([S22](sessions.md#identity-loss)), and a tunnel is never
deleted by its identifier, so a foreign tunnel that reused the identifier
survives. Dependent children of an owned session, in any namespace, are
removed by the kernel with their parent, and so is any session another
process attached to an owned tunnel ([K17](kernel.md#facts)); that is the
operator's concern to arrange around, not the daemon's to prevent.

P17. Shutdown waits for each tunnel deletion to leave the kernel, up to
two seconds each ([K17](kernel.md#facts)), so that a restart can reuse the
identifiers at once. Shutdown exits non-zero if a cleanup step failed,
after logging it, and still performs every later step.

## Crashes

P18. Tunnels are owned by sockets so that a crash leaves no kernel tunnel
or session behind: the kernel removes them when the process dies. Nothing
else survives a crash; nothing has to be cleaned up at the next start.

P19. The daemon MUST NOT panic on any input from the configuration, the
kernel, a resolver or another process. Unexpected kernel replies are
errors to retry or report, never reasons to abort.

## Concurrent instances

P20. Running two instances with overlapping identifiers is not supported.
The second instance meets refusals from the kernel and handles them as
conflicts ([T25](tunnels.md#identifier-conflicts)); neither instance
deletes the other's objects. Instances that are meant to coexist MUST use
distinct PID file paths.

## The supplied systemd unit

P21. When the supplied unit is used, it MUST order the service
`Before=network-online.target` and install it
`RequiredBy=network-online.target`, use `Type=forking` with the PID file,
`TimeoutStartSec=infinity`, and restart on failure, with `NotifyAccess=all`
and a `FileDescriptorStoreMax=` large enough for the tunnels so that the
hand-over of [P14](#restart) works. It MUST NOT depend on, or be ordered
after, `network-online.target` or any wait-online service.
It MUST confine the service to netlink and IP sockets plus the socket
families the host's resolver needs, a read-only system except the PID
file, no new privileges and no access to home directories or logs, and
MUST allow writing `net.ipv6.bindv6only` for [P25](#host-tunables),
without restricting the capabilities the kernel needs to autoload the
L2TP modules. It MUST grant every required capability explicitly
([R49](requirements.md#the-host)): `CAP_NET_ADMIN`, `CAP_NET_RAW` and
`CAP_NET_BIND_SERVICE`. An operator who removes one gets the start-up
report of R49 and the fallbacks, which are not guaranteed to work in every
case. Using the unit is optional; the process contract below is
what the daemon promises every init system.

## The process contract

P22. The daemon's interface to its init system is: it double-forks and
its parent exits 0 at readiness ([P4](#start-up), [P6](#readiness)); it
publishes a PID file at the configured path ([P10](#pid-file)); it takes
`SIGHUP`, `SIGTERM`, `SIGINT` and `SIGUSR2` ([P12](#signals-and-requests),
[P26](#restart)); it logs
to standard error ([O1](observability.md#logging)); and it reads its
configuration from the paths of [C1](configuration.md#files): the
defaults it was built with, or the main file and drop-in directory given
on its command line, which `--check` ([P3](#start-up)) accepts the same way.
This is sufficient for OpenRC, busybox init, sysvinit, runit, s6 or a
container entry point, with no other file or service.

P23. The daemon MUST NOT depend on `/run/systemd`, the journal, D-Bus,
`sysctl.d`, `tmpfiles.d`, the XDG or freedesktop.org layout, or the
installer, and MUST NOT link against libsystemd or any D-Bus library; the
descriptor hand-over of [P14](#restart) is used only when the init system
offers it, with the protocol implemented in the daemon. Of the filesystem it needs its
own files, `/proc` ([K12](kernel.md#requirements)) and nothing else; it
MUST NOT read `/sys`.

P24. The daemon builds and runs against glibc and against musl. The system
resolver is the libc's ([V3](resolvers.md#model)); no rule depends on which
libc it is.

## Host tunables

P25. The `host.fix_bindv6only` setting ([C17](configuration.md#host-settings)),
on by default, authorises the daemon to keep `net.ipv6.bindv6only` at 0
in its own network namespace for its lifetime. With it on: at start-up
and whenever a freshly created `AF_INET6` socket reports `IPV6_V6ONLY=1`
([K23](kernel.md#facts), [T26](tunnels.md#hosts-with-bindv6only)), the
service asks the binary (or the embedding program) to write 0, the binary
does so, the change is logged at warning level with the previous value,
and the socket is created again. A write that fails is a host defect for
the tunnels concerned: reported once, and those tunnels get `AF_INET`
sockets as with the option off. With it off, the daemon never writes the
tunable and [T26](tunnels.md#hosts-with-bindv6only) applies. This is the
only kernel setting the daemon ever changes ([G10](promises.md#unconditional-promises));
the reason it is on by default is that a value of 1 silently disables
every IPv4 peer on an `AF_INET6` socket, and the Linux default is 0.
