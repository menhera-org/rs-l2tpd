# Process

[Specification index](README.md)

## Start-up

P1. The daemon is started before the network is ready and MUST work in
that condition: no DNS, no default route, no route to any peer, no address
on any interface, bind devices not created yet, no IPv6, a VRF whose
default route is unreachable. None of these delays the creation of the
tunnels and session interfaces ([degradation ladder](model.md#the-degradation-ladder)).

P2. Start-up order: change directory to `/`, initialise logging, parse the
command line, load the configuration leniently
([C10](configuration.md#start-up)), report every problem, then daemonise
and apply. A configuration problem never prevents start-up; an empty
configuration is valid and makes the daemon ready at once.

P3. `--check` loads the configuration the same way, prints the
configuration that would be applied, reports every problem, exits 1 if
there was any and 0 otherwise, and touches nothing else: no socket, no
device, no route, no PID file ([O8](observability.md#check-mode)).

P4. The daemon double-forks. The grandchild applies the configuration; the
original parent waits and exits 0 when the grandchild reports readiness,
or 1 when it reports failure or dies. The intermediate child exits at once.
The grandchild uses a restrictive umask and creates only its PID file and
the directories of that file.

P5. The kernel interfaces (netlink, L2TP generic netlink) are opened before
the configuration is applied. Failing to open them is a host defect
([M13](model.md#failure-classes)): reported, readiness withheld, retried.

## Readiness

P6. Readiness means that every tunnel and every session of the applied
configuration exists in the kernel, including tunnels connected to a
discard address and sessions whose hardware-address change is deferred.
Readiness is reported exactly once, by the parent exiting 0 and the PID
file appearing; with the supplied unit this releases `network-online.target`.

P7. Readiness MUST NOT wait for: a host name to resolve, a route to a
literal or resolved peer, an absent bind device, an IPv6 source address, a
deferred hardware-address change, a session interface another manager
already configured, or an entry whose identifiers are held elsewhere once
the bounded retries are spent.

P8. Readiness MAY wait for: the discard-route grace period on a host that
routes no discard address (at most ten seconds per family), the bounded
conflict retries (at most ten seconds per entry, run concurrently with the
rest), and a kernel that cannot create the objects at all.

P9. Until readiness, failed creations are retried every second. Kernel and
DNS events are handled meanwhile, so a device appearing or a name resolving
during a slow start is not lost. Reload requests before readiness are
ignored; the files are read again at the next reload after readiness.

## PID file

P10. The PID file is published only after readiness, as a fresh inode owned
by the daemon user, replacing any previous file atomically. Its directories
MUST be owned by root or the daemon user; the daemon MUST NOT change their
permissions and only warns when other users could replace the file. In a
directory it cannot write to, a pre-created file is updated in place only
if the daemon user owns it, it has one link and no group or other write
permission, and it is still the inspected inode when opened. Symbolic links
in the file's place are refused; trusted directory symlinks are followed.

P11. The PID file is removed at shutdown. A stale file from a crash is
replaced at the next start.

## Signals and requests

P12. `SIGHUP` requests a reload, `SIGTERM` and `SIGINT` a shutdown. A
reload request MUST NOT be lost: the signal handler waits for queue
capacity. A shutdown request MUST NOT be lost either and takes precedence
over queued reloads; a second shutdown request during shutdown changes
nothing. Reloads are serialised: one at a time, in order.

P13. A reload reads the files again, converts them against the applied
configuration ([C12](configuration.md#reload)), replaces the applied
configuration if the result is acceptable, and reconciles. A reload whose
reconcile is incomplete is retried every second until complete; a new
reload replaces it. A reload callback that panics ends the daemon with an
error, after the kernel objects were removed.

## Restart

P14. Stopping the daemon removes everything it owns
([P16](#shutdown)). A restart therefore re-creates every interface and
with them their addresses, routes and children. Because this changes
interface identities for no reason of the kernel's, a restart or an
upgrade SHOULD keep the session interfaces where the platform allows it,
for example by handing the tunnel sockets to the init system's descriptor
store and adopting them again; this is a [known gap](README.md#known-gaps).
Whatever the mechanism, an explicit stop MUST still remove everything.

P15. After a restart the daemon MUST reach the applied state at least as
fast as after a first start, and the configuration MUST NOT need to
change for the restart to succeed.

## Shutdown

P16. Shutdown, in order: stop every timer; apply the empty configuration,
which deletes every owned session the daemon can prove it owns and then
every tunnel by closing its socket; remove the discard routes and null
devices the daemon still owns; remove the PID file; exit. A session the
daemon cannot prove it owns is left alone ([S22](sessions.md#identity-loss)),
and a tunnel is never deleted by its identifier, so a foreign tunnel that
reused the identifier survives. Dependent children of an owned session,
in any namespace, are removed by the kernel with their parent; that is the
operator's concern to arrange around, not the daemon's to prevent.

P17. Shutdown waits for each tunnel deletion to leave the kernel, up to
two seconds each, so that a restart can reuse the identifiers at once.
Shutdown exits non-zero if a cleanup step failed, after logging it, and
still performs every later step.

## Crashes

P18. Tunnels are owned by sockets so that a crash leaves no kernel tunnel
or session behind: the kernel removes them when the process dies. Null
devices and discard routes are the only objects that can survive a crash;
at the next start they are foreign ([M9](model.md#ownership)): never
adopted, never removed, reported, and a new null device is created under
the next free name if one is needed.

P19. The daemon MUST NOT panic on any input from the configuration, the
kernel, DNS or another process. Unexpected kernel replies are errors to
retry or report, never reasons to abort.

## Concurrent instances

P20. Running two instances with overlapping identifiers is not supported.
The second instance meets refusals from the kernel and handles them as
conflicts ([T25](tunnels.md#identifier-conflicts)); neither instance
deletes the other's objects.

## The supplied systemd unit

P21. The unit MUST order the service `Before=network-online.target` and
install it `RequiredBy=network-online.target`, use `Type=forking` with the
PID file, `TimeoutStartSec=infinity`, and restart on failure. It MUST NOT
depend on, or be ordered after, `network-online.target` or any wait-online
service. It MUST confine the service to netlink and IP sockets, a
read-only system except the PID file, no new privileges and no access to
home directories, kernel tunables or logs, without restricting the
capabilities the kernel needs to autoload the L2TP modules and resolve
names on the daemon's behalf.
