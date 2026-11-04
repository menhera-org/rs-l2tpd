# Architecture

[Documentation index](README.md)

The implementation follows the layers of the
[architecture specification](spec/architecture.md). The library owns
configuration and reconciliation; the binary supplies process integration.
All reconciler operations on the host pass through `kernel::Kernel`.

## Module map

| Module | Responsibility |
|---|---|
| `config::{partial,text,serde}` | Merge partial input, report problems, validate typed configuration; optional serialization |
| `kernel` | Synchronous host boundary, subscriptions, registration proofs and typed observations |
| `kernel::fake` | In-memory namespace, virtual clock, seeded names and controlled failures, behind tests or `fake-kernel` |
| `kernel::linux::{socket,l2tp,rtnl,request}` | Tunnel sockets and bounded netlink requests |
| `kernel::linux::{monitor,lifetime,bpf}` | Filtered notifications, ordered registration proofs and persistent loss detection |
| `reconciler::{records,tunnels,sessions,ladder}` | Accepted configuration, object identities, ordered mutations and degraded states |
| `reconciler::{events,timers,deadlines}` | Dependency indexes, selective inventories, event handling and bounded retries |
| `reconciler::{resolvers,workers}` | Released `iphost` adapters, answer retention and bounded lookup admission |
| `reconciler::{store,report}` | Descriptor-store handshakes and condition episodes |
| `runtime` | Program-driven reconciliation, bounded event admission and host requests |
| `service`, `blocking` | Tokio-facing and blocking services over a dedicated reconciliation thread |
| `bin/rs-l2tpd` | Options, files, logging, daemonization, PID-file authority, signals, store transport, re-exec and optional installation |

## The kernel boundary

`Kernel` is synchronous and object-safe. It exposes sockets, tunnel/session
operations, selected link/address inventories, subscriptions and registration
proofs. Kernel errors retain their errno. Both netlink transports impose a
five-second total request deadline, including family resolution, multipart
responses and acknowledgements. Unrelated traffic cannot renew that deadline.

A timed-out mutation has an unknown outcome. The reconciler retains its
ownership and reservations, reopens the failed transport and verifies local
state before retrying. Tunnel deletion waits use timers rather than nested
blocking waits. The raw adapter reuses the packet codecs already supplied
by the dependencies; it does not delegate requests to an unbounded queue.

Lifetime proofs identify a registration incarnation, rather than a reusable
link index. Capture is armed and ordered before session creation. Lookups
drain preceding notifications before deciding `Proved`, `Removed` or `Lost`.
Lost notifications cannot turn an index/name match into an ownership proof.
Session dumps stream into bounded checks and reservations. Incomplete dumps
cannot establish uniqueness or absence.

Selected inventories request links under one master or addresses on one
interface; selector zero requests the whole namespace. The Linux adapter
applies selectors in the kernel. Addresses become authoritative only after
every selected family dump completes. VRF membership retains enough previous
state to reconnect dependencies affected by both the old and new domain.
See [K7](spec/kernel.md#dependency-inventories-k7) for handler fallback limits.

The fake implements the same boundary with explicit event delivery, virtual
time, seeded random names and injected errors. Shared conformance cases run
against both backends; source-only and delegated facts keep their distinct
[evidence classifications](kernel-evidence.md).

## Records and reconciliation

`Reconciler` holds accepted configuration, identity-indexed tunnel/session
records, device dependencies, resolver state, pending handshakes and deadlines.
Configuration names can change without replacing kernel identities (C14/M17).
Applied state advances only after confirmation; uncertain mutations remain
pending verification. Session identity records distinguish proved, staged,
removed, lost and adopted objects.

Reconciliation performs deletions before name release and cycle staging,
then creations and final in-place changes (M6). Children are removed before
parents. Name and identifier reservations survive asynchronous deletion.
Session rename chains release acyclic dependencies before staging cycles.
Unrelated entries continue after a failure. There is no separate `plan.rs`;
the ordered passes live in `reconciler` and its operation modules.

The degradation ladder determines the best state currently possible.
Promotion reuses the same objects when their identities permit it. Event
indexes select affected dependencies, and deadline indexes select due work;
unrelated events do not scan all configured entries or query the kernel.

## Tasks and channels

The service owns a dedicated reconciliation thread. Its small current-thread
Tokio runtime waits for events; synchronous kernel operations run outside
that wait. Subscriptions continue reading on the service runtime. The input
channel has capacity 1,024. Monitor and L2TP subscriptions use nonblocking
admission with persistent loss flags outside the queue, so overflow cannot
lose the resync request.

Shutdown has a persistent atomic flag and wakeup, independent of queue
capacity. The worker checks it before taking more operator work. Deferred
reload/restart requests retain their bounded admission slots and interleave
with background events. Reload callbacks run off-thread; generations reject
obsolete completions. Callback panic is retained through cleanup, including
when its completion cannot be dequeued before shutdown finishes.

Resolver jobs retain process-wide permits until the underlying call returns.
Separate system/configured budgets prevent blocked libc lookups from consuming
configured-DNS capacity. Pending work and results coalesce by current key.
Dropping interest does not cancel libc; shutdown does not join those calls.
Dispatch preserves each instance's network namespace.

## Runtime, services, binary

`Runtime` is the program-driven interface. Constructors synchronously open
kernel interfaces and return adopted descriptors with startup errors.
`next_event` prepares injected callbacks on the caller's thread, then returns
the waiting future. Explicit shutdown performs ordered cleanup; plain drop
closes owned sockets without claiming manager withdrawal succeeded.

`service::Service` runs reconciliation on its worker thread while exposing
async control. Its drop requests shutdown; await `run` to observe cleanup.
`blocking::Service` supplies its own runtime and waits for cleanup on drop.
Both can expose `WriteTunable`, `StoreSocket` and `ForgetSocket` requests to
the embedding program. Without integration they decline tunable writes and
use local socket ownership. See the [interface](interface.md#library).

The binary implements those host requests, signal collection, startup retry,
readiness, PID-file publication and re-exec. Descriptor retirement retains the
exact store name and serializes withdrawal before replacement storage. Re-exec
isolates descriptor remapping from live threads. The optional installer embeds
the unit template; the library performs no process or configuration-file I/O.

The [testing page](testing.md) maps these layers to deterministic policy tests,
live conformance, process checks, whole-daemon scenarios and coverage gates.
