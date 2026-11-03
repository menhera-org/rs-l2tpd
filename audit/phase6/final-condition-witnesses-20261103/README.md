# Address indexing and shutdown dispatch witnesses

This batch adds a private stale-device-index address-addition case and a
service dequeue witness that requests shutdown synchronously when a full
queue releases a blocked sender. The latter checks that shutdown releases
the admitted reload's slot and preserves the accepted configuration. Its
extension checks restart through the same mechanism.

A third witness leaves a descriptor-store request in the runtime's outgoing
queue, then requires orderly shutdown to refuse it, release its socket copy
and remove the tunnel. The tunable shutdown case remains separate.

The initial two cases pass ten repetitions per libc. The extended shutdown
batch passes **19 tests per repetition, ten times on GNU and ten on musl**.
Both the initial and extended mandatory common gates pass. These repetitions
qualify this batch; they do not establish whole-matrix determinism.

Restored fault controls remove the address-addition removed guard, the
reload shutdown guard, refusal of an unsent store request and the restart
shutdown guard. Individual logs retain each intended assertion failure.
The first two controls precede the restart/store extension. The stale index
is deliberately private test state, not a claim about reachable public cache
state.

The [first instrumented collection](../final-source-coverage-20261103/README.md)
still fails coverage. The [fresh closure collection](../closure-coverage-20261103/README.md)
passes 8,444/8,444 production lines and 1,838/1,838 condition outcomes,
checker exit 0. Production code is unchanged by these three witnesses.

