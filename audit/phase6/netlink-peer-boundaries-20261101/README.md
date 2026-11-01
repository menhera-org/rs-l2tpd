# Netlink peer, deadline and framing boundaries

Three test-only cases use the existing request adapter and real userspace
netlink sockets. Both peers bind nonzero automatic ports and connect only
to each other with NETLINK_USERSOCK. They send nothing to the kernel's
routing or L2TP handlers and change no network configuration.

The expired exchange returns ETIMEDOUT and leaves its peer's receive queue
empty. This assertion catches transmission even if the later receive loop
also times out. Malformed headers and declared lengths below NLMSG_HDRLEN
return EPROTO without panicking. The empty message sequence stays empty.

The sender test queues a malformed datagram and, separately, a valid DONE
with matching sequence and a zero PID in its header. Both actual sender
ports are nonzero. Neither reaches framing/visitor processing; the absolute
one-second deadline expires. Reading the outgoing request at the peer also
proves the exchange transmitted before that deadline. There is no asserted
upper bound on scheduler-delayed completion.

`revision` identifies signed 79aca22; `source.patch` adds the tests and
shares the existing test-message builder with its sibling test module.
No production, dependency, API or specification changes. Ten native and
instrumented seeds, three musl library runs and all common gates pass.
The ordinary library has 247 passing cases and 19 ignored; instrumentation
adds three serial-only startup cases.

Four controls fail: unchecked framing, transmission after expiry, unchecked
sender addresses, and trust in a forged zero header PID. Patches apply
after source.patch; mutations are isolated and restored. Failed controls
do not enter coverage.

All **4,304 complete coverage mappings remain identical**. The fresh
merged report reaches **8,423/8,671 lines (97.14%)** and
**1,672/1,850 branches (90.38%)**, leaving 248 lines and 178 branches.
No production exclusion, profile mismatch or saturated region is present.

The new socket cases execute on Ubuntu 6.8.0-147-generic with GNU and musl.
They are not part of the completed five-kernel matrix frozen at production
584062d. That matrix retains its recorded live transport/conformance scope.
Complete clause/history/resource proof and 100% coverage remain open.
